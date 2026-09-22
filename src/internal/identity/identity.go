// Package identity owns the install's identity unit and the naming rules derived from it. The
// install_id, age identity and name_key persist together as ONE file or not at all: losing one
// while keeping the others is worse than losing all three. String and Format redact the secrets.
package identity

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"uuid"

	"filippo.io/age"

	"github.com/QuesmaOrg/quesma-shipper/internal/formats"
	"github.com/QuesmaOrg/quesma-shipper/internal/platform"
)

// IdentitySchema versions the on-disk unit; an unknown value means downgrade or corruption.
const IdentitySchema = 1

const FileName = "identity.json"

type Unit struct {
	// InstallID is the machine pseudonym and the unit of erasure: one prefix sweep deletes a device.
	InstallID uuid.UUID
	// Identity is the default recipient in a standalone install; an enterprise may withhold it.
	Identity *age.X25519Identity
	// NameKey keys the mirror-name HMAC, so a listable object name is no confirmation oracle.
	NameKey   []byte
	CreatedAt time.Time
}

type unitFile struct {
	IdentitySchema int    `json:"identity_schema"`
	InstallID      string `json:"install_id"`
	AgeIdentity    string `json:"age_identity"`
	AgeRecipient   string `json:"age_recipient"`
	NameKey        string `json:"name_key"`
	CreatedAt      string `json:"created_at"`
}

func (u *Unit) Recipient() *age.X25519Recipient {
	return u.Identity.Recipient()
}

// String redacts: the likeliest way a private key escapes is an incidental log line.
func (u Unit) String() string {
	return fmt.Sprintf("identity.Unit{install_id:%s, age_recipient:%s, name_key:REDACTED, age_identity:REDACTED}",
		u.InstallID, u.Identity.Recipient())
}

// Format routes every verb through String, so %v, %s and %#v all redact.
func (u Unit) Format(f fmt.State, verb rune) {
	fmt.Fprint(f, u.String())
}

// Mint generates a new identity unit and writes it to stateDir, refusing to overwrite an existing
// one: that would orphan every object the previous unit named and every archive it could decrypt.
func Mint(stateDir string) (*Unit, error) {
	if err := platform.EnsureDir(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	path := filepath.Join(stateDir, FileName)
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("identity: %s already exists: refusing to mint over an existing unit", path)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("identity: stat %s: %w", path, err)
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("identity: generate age identity: %w", err)
	}
	nameKey := make([]byte, formats.NameKeySize)
	rand.Read(nameKey) // never fails since Go 1.24

	u := &Unit{InstallID: uuid.New(), Identity: id, NameKey: nameKey, CreatedAt: time.Now().UTC().Truncate(time.Second)}
	// Written atomically, so a crash leaves no unit or a complete one.
	if err := platform.WriteJSON(path, unitFile{
		IdentitySchema: IdentitySchema,
		InstallID:      u.InstallID.String(),
		AgeIdentity:    u.Identity.String(),
		AgeRecipient:   u.Identity.Recipient().String(),
		NameKey:        hex.EncodeToString(u.NameKey),
		CreatedAt:      u.CreatedAt.Format(time.RFC3339),
	}, 0o600); err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	return u, nil
}

func Load(stateDir string) (*Unit, error) {
	path := filepath.Join(stateDir, FileName)
	// ReadPrivate checks the mode on the file it opened, so a swapped-in symlink cannot borrow another file's mode.
	raw, err := platform.ReadPrivate(path, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	var uf unitFile
	if err := json.Unmarshal(raw, &uf); err != nil {
		return nil, fmt.Errorf("identity: parse %s: %w", path, err)
	}
	if uf.IdentitySchema != IdentitySchema {
		return nil, fmt.Errorf("identity: %s has identity_schema %d, this client speaks %d: refusing to guess",
			path, uf.IdentitySchema, IdentitySchema)
	}
	installID, err := uuid.Parse(uf.InstallID)
	if err != nil {
		return nil, fmt.Errorf("identity: install_id: %w", err)
	}
	ageID, err := age.ParseX25519Identity(uf.AgeIdentity)
	if err != nil {
		return nil, fmt.Errorf("identity: age_identity: %w", err)
	}
	nameKey, err := hex.DecodeString(uf.NameKey)
	if err != nil {
		return nil, fmt.Errorf("identity: name_key: %w", err)
	}
	if len(nameKey) != formats.NameKeySize {
		return nil, fmt.Errorf("identity: name_key is %d bytes, want %d", len(nameKey), formats.NameKeySize)
	}
	createdAt, err := time.Parse(time.RFC3339, uf.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("identity: created_at: %w", err)
	}
	// A disagreeing recipient means the file was edited and its halves may no longer belong together.
	if got := ageID.Recipient().String(); uf.AgeRecipient != "" && uf.AgeRecipient != got {
		return nil, fmt.Errorf("identity: age_recipient does not match age_identity")
	}

	return &Unit{InstallID: installID, Identity: ageID, NameKey: nameKey, CreatedAt: createdAt.UTC()}, nil
}
