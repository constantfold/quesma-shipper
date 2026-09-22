//go:build perf

// This protocol peer exists only to issue real MinIO tickets. It deliberately models no
// control-plane product behavior: the subject of this package is the shipper binary.
package perf

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	tcminio "github.com/testcontainers/testcontainers-go/modules/minio"
)

const (
	perfOrg           = "acme"
	authorizePreamble = "trajectory-shipper-upload-authorize-v2\nPOST\n/v2/uploads/authorize\n"
	ingestUserKey     = "trajectories-ingest"
	ingestUserSecret  = "ingest-secret-for-a-throwaway-container"
	ingestPolicyName  = "trajectories-ingest-writeonly"
)

const ingestPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
	`"Action":["s3:PutObject","s3:PutObjectTagging"],"Resource":["arn:aws:s3:::*/*"]}]}`

func mintIngestUser(ctx context.Context, container *tcminio.MinioContainer) error {
	script := strings.Join([]string{
		"set -e",
		"mc alias set local http://127.0.0.1:9000 " + container.Username + " " + container.Password,
		"printf '%s' '" + ingestPolicy + "' > /tmp/ingest-policy.json",
		"mc admin policy create local " + ingestPolicyName + " /tmp/ingest-policy.json",
		"mc admin user add local " + ingestUserKey + " " + ingestUserSecret,
		"mc admin policy attach local " + ingestPolicyName + " --user " + ingestUserKey,
	}, "\n")
	code, output, err := container.Exec(ctx, []string{"sh", "-c", script})
	if err != nil {
		return err
	}
	if code != 0 {
		raw, _ := io.ReadAll(output)
		return fmt.Errorf("mc exited %d: %s", code, raw)
	}
	return nil
}

// The harness's admin client and the peer's presigner both speak to MinIO this way.
func pathStyleS3(endpoint, key, secret string) *awss3.Client {
	return awss3.NewFromConfig(aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""),
	}, func(o *awss3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})
}

type perfInstall struct {
	id, org, origin, bucket string
	key                     ed25519.PublicKey
}

type protocolPeer struct {
	server   *httptest.Server
	mu       sync.Mutex
	installs map[string]perfInstall
}

var peer *protocolPeer

func startProtocolPeer() {
	peer = &protocolPeer{installs: map[string]perfInstall{}}
	peer.server = httptest.NewServer(http.HandlerFunc(peer.serve))
}

func (c *protocolPeer) register(install perfInstall) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.installs[install.id] = install
}

type perfAuthorizeRequest struct {
	WriterID string    `json:"writer_id"`
	IssuedAt time.Time `json:"issued_at"`
	Objects  []struct {
		ObjectID   string            `json:"object_id"`
		Key        string            `json:"key"`
		Size       int64             `json:"size"`
		SourceHash string            `json:"source_hash"`
		Metadata   map[string]string `json:"metadata"`
	} `json:"objects"`
}

func (c *protocolPeer) serve(w http.ResponseWriter, r *http.Request) {
	org, installID, signature, ok := parseDeviceAuthorization(r.Header.Get("Authorization"))
	if !ok {
		http.Error(w, "invalid device authorization", http.StatusUnauthorized)
		return
	}
	c.mu.Lock()
	install, exists := c.installs[installID]
	c.mu.Unlock()
	if !exists || org != install.org {
		http.Error(w, "unknown install", http.StatusUnauthorized)
		return
	}
	if r.URL.Path == "/v1/config" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"config":     []byte("config_version: 1\nissued_at: \"2026-09-03T00:00:00Z\"\norg: " + install.org + "\n"),
			"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
		})
		return
	}
	if r.URL.Path != "/v2/uploads/authorize" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !ed25519.Verify(install.key, append([]byte(authorizePreamble), body...), signature) {
		http.Error(w, "invalid device signature", http.StatusUnauthorized)
		return
	}

	var req perfAuthorizeRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tickets, err := issueTickets(r.Context(), install, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"tickets": tickets})
}

func parseDeviceAuthorization(header string) (string, string, []byte, bool) {
	rest, ok := strings.CutPrefix(header, "Shipper-Device ")
	if !ok {
		return "", "", nil, false
	}
	values := map[string]string{}
	for field := range strings.SplitSeq(rest, ", ") {
		if name, value, ok := strings.Cut(field, "="); ok {
			values[name] = value
		}
	}
	sig, err := base64.StdEncoding.DecodeString(values["sig"])
	return values["org"], values["install"], sig,
		values["org"] != "" && values["install"] != "" && err == nil
}

func issueTickets(ctx context.Context, install perfInstall, req perfAuthorizeRequest) ([]map[string]any, error) {
	presigner := awss3.NewPresignClient(pathStyleS3(install.origin, ingestUserKey, ingestUserSecret))
	expires := time.Now().Add(5 * time.Minute).UTC()
	root := "v1/organization=" + install.org + "/install=" + install.id + "/"
	tickets := make([]map[string]any, 0, len(req.Objects))
	for _, obj := range req.Objects {
		if !strings.HasPrefix(obj.Key, root) {
			return nil, fmt.Errorf("object key %q is outside %q", obj.Key, root)
		}
		ticketID := uuid.NewString()
		metadata := map[string]string{}
		maps.Copy(metadata, obj.Metadata)
		metadata["source-hash"] = obj.SourceHash
		metadata["ticket-id"] = ticketID
		tagging := "class=context"
		if strings.Contains(obj.Key, "/mirror/") {
			tagging = "class=trajectory"
		}
		signed, err := presigner.PresignPutObject(ctx, &awss3.PutObjectInput{
			Bucket: aws.String(install.bucket), Key: aws.String(obj.Key),
			ContentLength: aws.Int64(obj.Size), Metadata: metadata, Tagging: aws.String(tagging),
		}, awss3.WithPresignExpires(5*time.Minute))
		if err != nil {
			return nil, err
		}
		headers := map[string]string{}
		lengthSigned := false
		for name, values := range signed.SignedHeader {
			switch lower := strings.ToLower(name); {
			case lower == "content-length":
				lengthSigned = true
			case lower == "host":
			case len(values) != 1:
				return nil, fmt.Errorf("signed header %s has %d values", name, len(values))
			default:
				headers[lower] = values[0]
			}
		}
		tickets = append(tickets, map[string]any{
			"ticket_id": ticketID, "object_id": obj.ObjectID, "method": signed.Method,
			"url": signed.URL, "expires_at": expires.Format(time.RFC3339Nano),
			"required_headers": headers, "content_length": obj.Size,
			"content_length_signed": lengthSigned,
		})
	}
	return tickets, nil
}
