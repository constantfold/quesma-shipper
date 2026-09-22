package controlplane

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

// EnrollmentFile is where the enrollment record lives, beside the identity unit.
const EnrollmentFile = "enrollment.json"

// enrollmentSchema versions the record. A newer schema is rejected: guessing at one another version
// wrote is how a client writes into the wrong subtree. An older one is migrated forward and persisted.
const enrollmentSchema = 2

// Enrollment is what an enrolled install remembers, persisted as one unit with the identity:
// without that identity it grants a subtree the client can no longer name.
type Enrollment struct {
	EnrollmentSchema int    `json:"enrollment_schema"`
	InstallID        string `json:"install_id"`
	Organization     string `json:"organization"`
	Endpoint         string `json:"endpoint"`

	// DeviceKey signs later requests. Private, so this file is 0600 and refused if it is looser.
	DeviceKey string `json:"device_key"`

	EnrolledAt string `json:"enrolled_at"`
}

// Save writes the record atomically at 0600.
func (e Enrollment) Save(stateDir string) error {
	e.EnrollmentSchema = enrollmentSchema
	return platform.WriteJSON(filepath.Join(stateDir, EnrollmentFile), e, 0o600)
}

// LoadEnrollment reads the record. A missing file means standalone and returns os.ErrNotExist.
func LoadEnrollment(stateDir string) (*Enrollment, error) {
	raw, err := platform.ReadPrivate(filepath.Join(stateDir, EnrollmentFile), 1<<20)
	if err != nil {
		return nil, err
	}
	var e Enrollment
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, fmt.Errorf("backend: parse enrollment: %w", err)
	}
	// Schema 1 is schema 2 plus a sink grant, which decoding already dropped. The frozen fixture checks the conversion.
	if e.EnrollmentSchema == 1 {
		// Persisted immediately so the upgrade happens once and a downgraded binary refuses the record loudly.
		if err := e.Save(stateDir); err != nil {
			return nil, fmt.Errorf("backend: persist migrated enrollment: %w", err)
		}
		e.EnrollmentSchema = enrollmentSchema
	}
	if e.EnrollmentSchema != enrollmentSchema {
		return nil, fmt.Errorf("backend: enrollment_schema %d, this client speaks %d", e.EnrollmentSchema, enrollmentSchema)
	}
	return &e, nil
}

// PrivateKey decodes the device signing key.
func (e Enrollment) PrivateKey() (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(e.DeviceKey)
	if err != nil {
		return nil, fmt.Errorf("backend: device key is not base64: %w", err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("backend: device key is %d bytes, want %d", len(b), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(b), nil
}

// Client binds requests to this enrollment's endpoint, identity and signing key.
func (e Enrollment) Client() (*Client, error) {
	key, err := e.PrivateKey()
	if err != nil {
		return nil, err
	}
	return New(Options{Endpoint: e.Endpoint, InstallID: e.InstallID, Organization: e.Organization, DeviceKey: key})
}

// NewDeviceKey generates the request-signing keypair.
func NewDeviceKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(nil)
}

// Now is the enrollment timestamp format.
func Now() string { return time.Now().UTC().Format(time.RFC3339) }

// EncodeKey renders a key as base64, the wire and on-disk form for both halves.
func EncodeKey(key []byte) string { return base64.StdEncoding.EncodeToString(key) }
