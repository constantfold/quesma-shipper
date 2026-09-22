package engine_test

import (
	"context"
	"maps"
	"regexp"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/QuesmaOrg/quesma-shipper/internal/engine"
)

// The suite's upload port: an in-memory store recording every group and object a run touched.

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

type fakeObject struct {
	Body     []byte
	Metadata map[string]string

	// Versions stands in for a bucket's noncurrent stack: a re-PUT must add one, not replace.
	Versions int
}

type fakePort struct {
	mu      sync.Mutex
	groups  [][]string // object keys per call, in call order
	objects map[string]*fakeObject
	puts    int      // PUTs since the last reset
	faults  []string // descriptor invariants the engine broke
	calls   int

	// verdict decides one object's fate; nil stores everything. call and idx are zero-based.
	verdict func(call, idx int, o engine.PreparedObject) error
}

func newPort() *fakePort { return &fakePort{objects: map[string]*fakeObject{}} }

// always fails every object, for conditions about the install rather than one object.
func always(err error) func(int, int, engine.PreparedObject) error {
	return func(int, int, engine.PreparedObject) error { return err }
}

func (p *fakePort) AuthorizeAndUpload(_ context.Context, batch []engine.PreparedObject) []error {
	p.mu.Lock()
	defer p.mu.Unlock()
	call := p.calls
	p.calls++
	keys := make([]string, len(batch))
	ids := map[string]bool{}
	out := make([]error, len(batch))
	for i, o := range batch {
		keys[i] = o.Key
		switch {
		case ids[o.ObjectID]:
			p.faults = append(p.faults, "duplicate object id "+o.ObjectID)
		case o.ObjectID == "":
			p.faults = append(p.faults, "empty object id for "+o.Key)
		case !hex64.MatchString(o.SourceHash):
			p.faults = append(p.faults, "source hash is not 64 lowercase hex for "+o.Key)
		case o.Metadata["source-hash"] != "":
			p.faults = append(p.faults, "source-hash left in the metadata of "+o.Key)
		case len(o.Body) == 0:
			p.faults = append(p.faults, "empty body for "+o.Key)
		}
		ids[o.ObjectID] = true
		if p.verdict != nil {
			if out[i] = p.verdict(call, i, o); out[i] != nil {
				continue
			}
		}
		p.puts++
		obj := p.objects[o.Key]
		if obj == nil {
			obj = &fakeObject{}
			p.objects[o.Key] = obj
		}
		obj.Body = slices.Clone(o.Body)
		obj.Metadata = maps.Clone(o.Metadata)
		obj.Metadata["source-hash"] = o.SourceHash
		obj.Versions++
	}
	p.groups = append(p.groups, keys)
	return out
}

func (p *fakePort) keys() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Sorted(maps.Keys(p.objects))
}

func (p *fakePort) get(key string) (*fakeObject, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	obj, ok := p.objects[key]
	return obj, ok
}

func (p *fakePort) putCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.puts
}

// sizes is how many objects each authorization group carried, in call order.
func (p *fakePort) sizes() []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := make([]int, len(p.groups))
	for i, g := range p.groups {
		n[i] = len(g)
	}
	return n
}

// storedOnce fails unless every key the port holds was stored exactly once.
func (p *fakePort) storedOnce(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, f := range p.faults {
		t.Errorf("descriptor invariant broken: %s", f)
	}
	for key, obj := range p.objects {
		assert.Equalf(t, 1, obj.Versions, "%s was stored %d times; one prepared object is one PUT", key, obj.Versions)
	}
}
