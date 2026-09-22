// The PUT itself: one request per ticket, HTTP 200 the only success. No retry loop lives here:
// a failed PUT commits nothing and the next run reauthorizes.
package upload

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Per-phase timeouts: no single Client.Timeout both allows 256 MiB on a slow link and catches a stall.
const (
	dialTimeout           = 10 * time.Second
	tlsTimeout            = 10 * time.Second
	responseHeaderTimeout = 60 * time.Second // the stall catcher, starting after the body
	idleTimeout           = 90 * time.Second
	expectContinueTimeout = 5 * time.Second
	operationOverhead     = 90 * time.Second
	minThroughput         = 64 << 10 // bytes per second
	maxOperation          = 30 * time.Minute
)

// A failure body is read this far for the diagnostic, then drained further to keep the connection reusable.
const (
	maxDiagnosticBytes = 4 << 10
	maxDrainBytes      = 64 << 10
	maxReasonRunes     = 200
)

// ErrRedirect is any 3xx: a presigned signature covers one origin and path, so none is followed.
var ErrRedirect = errors.New("upload: the object store redirected and presigned tickets are never followed")

// StatusError is a PUT that answered something other than 200; Reason is the store's sanitized text, never the URL.
type StatusError struct {
	Status int
	Reason string
}

func (e *StatusError) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("upload: object store answered HTTP %d", e.Status)
	}
	return fmt.Sprintf("upload: object store answered HTTP %d: %s", e.Status, e.Reason)
}

// Uploader's transport is not configurable: every setting is a way back to the unbounded hang it prevents.
type Uploader struct {
	client *http.Client
}

func New() *Uploader {
	return &Uploader{client: &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   dialTimeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          64,
			MaxIdleConnsPerHost:   64,
			IdleConnTimeout:       idleTimeout,
			TLSHandshakeTimeout:   tlsTimeout,
			ExpectContinueTimeout: expectContinueTimeout,
			ResponseHeaderTimeout: responseHeaderTimeout,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRedirect },
	}}
}

// Upload spends one ticket ValidateTicket accepted, re-deriving no URL and no header of its own.
func (u *Uploader) Upload(ctx context.Context, ticket Ticket, body []byte) error {
	d := operationOverhead + time.Duration(len(body)/minThroughput)*time.Second
	ctx, cancel := context.WithTimeout(ctx, min(d, maxOperation))
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, ticket.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("upload: build PUT for object %q: %w", ticket.ObjectID, sanitizeURLError(err))
	}
	// Exactly the authorized headers, in a stable order: the signature may cover any of them.
	for _, name := range slices.Sorted(maps.Keys(ticket.RequiredHeaders)) {
		req.Header.Set(name, ticket.RequiredHeaders[name])
	}
	// Explicit: with the length inside the signature, a chunked body would be refused.
	req.ContentLength = ticket.ContentLength

	resp, err := u.client.Do(req)
	if err != nil {
		return fmt.Errorf("upload: PUT object %q: %w", ticket.ObjectID, sanitizeURLError(err))
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrainBytes))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		diagnostic, readErr := io.ReadAll(io.LimitReader(resp.Body, maxDiagnosticBytes))
		if readErr != nil {
			diagnostic = nil
		}
		return &StatusError{Status: resp.StatusCode, Reason: sanitizeReason(string(diagnostic))}
	}
	return nil
}

// sanitizeURLError strips *url.Error, whose message repeats the request URL and its query.
func sanitizeURLError(err error) error {
	var wrapped *url.Error
	if errors.As(err, &wrapped) && wrapped.Err != nil {
		return wrapped.Err
	}
	return err
}

// sanitizeReason makes a store's error body safe to print: one line, printable, bounded.
func sanitizeReason(body string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(body))
	oneLine := []rune(strings.Join(strings.Fields(cleaned), " "))
	return string(oneLine[:min(len(oneLine), maxReasonRunes)])
}
