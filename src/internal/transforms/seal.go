// Objects contain tar(manifest.json, payload), compressed with zstd and encrypted with age.
// The manifest comes first so a ranged GET can read it without downloading the payload.
package transforms

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"

	"filippo.io/age"
	"github.com/klauspost/compress/zstd"
)

// Fixed entry names: the payload's real name is a path, which belongs in the manifest only.
const (
	ManifestEntry = "manifest.json"
	PayloadEntry  = "payload"
)

// ZstdLevel stays at 3: changing it changes every object's bytes.
const ZstdLevel = 3

// Bounds on hostile input, which must not exhaust memory through zstd expansion.
const (
	maxManifestBytes     = 4 << 20
	maxDecompressedBytes = 8 << 30
)

// Seal builds one mirror object and returns the manifest as sealed, with ShippedHash, PayloadSize
// and (unless the caller set it) Encryption filled: object metadata comes from the returned copy.
func Seal(m Manifest, payload []byte, recipients []age.Recipient) ([]byte, Manifest, error) {
	if len(recipients) == 0 {
		return nil, Manifest{}, errors.New("seal: no age recipients: encryption is not optional")
	}
	if m.SealedAt == "" {
		return nil, Manifest{}, errors.New("seal: sealed_at must be set by the caller")
	}
	m.ShippedHash = Hash(payload)
	m.PayloadSize = int64(len(payload))
	if m.Encryption == nil {
		m.Encryption = &Encryption{Scheme: "age"}
	}
	if len(m.Encryption.RecipientKeyIDs) == 0 {
		for _, r := range recipients {
			m.Encryption.RecipientKeyIDs = append(m.Encryption.RecipientKeyIDs, recipientID(r))
		}
	}

	manifestJSON, err := m.Encode()
	if err != nil {
		return nil, Manifest{}, err
	}

	obj, err := writeContainer(manifestJSON, payload, m.PayloadMTime, recipients)
	if err != nil {
		return nil, Manifest{}, err
	}
	return obj, m, nil
}

// writeContainer streams all three layers into one pre-sized buffer, with no staging copy.
func writeContainer(manifestJSON, payload []byte, payloadMTime *time.Time, recipients []age.Recipient) ([]byte, error) {
	out := bytes.NewBuffer(make([]byte, 0, ciphertextHint(len(manifestJSON), len(payload), len(recipients))))
	ageWriter, err := age.Encrypt(out, recipients...)
	if err != nil {
		return nil, fmt.Errorf("seal: age encrypt: %w", err)
	}
	zstdWriter, err := zstd.NewWriter(ageWriter,
		zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(ZstdLevel)),
		zstd.WithEncoderConcurrency(1),
		zstd.WithZeroFrames(true),
	)
	if err != nil {
		return nil, fmt.Errorf("seal: zstd writer: %w", err)
	}
	if err := writeTar(zstdWriter, manifestJSON, payload, payloadMTime); err != nil {
		return nil, err
	}
	if err := zstdWriter.Close(); err != nil {
		return nil, fmt.Errorf("seal: zstd close: %w", err)
	}
	if err := ageWriter.Close(); err != nil {
		return nil, fmt.Errorf("seal: age close: %w", err)
	}
	return out.Bytes(), nil
}

func ciphertextHint(manifestLen, payloadLen, recipients int) int {
	const (
		tarBlock  = 512
		zstdBlock = 128 << 10
		ageChunk  = 64 << 10
	)
	round := func(n, block int) int {
		if rem := n % block; rem != 0 {
			return n + block - rem
		}
		return n
	}
	tarLen := 4*tarBlock + round(manifestLen, tarBlock) + round(payloadLen, tarBlock)
	zstdLen := tarLen + 3*(tarLen/zstdBlock+1) + 32
	return zstdLen + 256 + 256*recipients + 16*(zstdLen/ageChunk+1)
}

// writeTar writes the two entries, manifest first, with headers normalised so the tar layer adds
// no machine-specific bytes. USTAR, since PAX headers would push the manifest deeper.
func writeTar(w io.Writer, manifestJSON, payload []byte, payloadMTime *time.Time) error {
	tw := tar.NewWriter(w)

	mtime := time.Unix(0, 0).UTC()
	if payloadMTime != nil {
		mtime = payloadMTime.UTC().Truncate(time.Second)
	}

	entries := []struct {
		name  string
		body  []byte
		mtime time.Time
	}{
		{ManifestEntry, manifestJSON, time.Unix(0, 0).UTC()},
		{PayloadEntry, payload, mtime},
	}
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     e.name,
			Size:     int64(len(e.body)),
			Mode:     0o600,
			ModTime:  e.mtime,
			Format:   tar.FormatUSTAR,
		}); err != nil {
			return fmt.Errorf("seal: tar header %s: %w", e.name, err)
		}
		if _, err := tw.Write(e.body); err != nil {
			return fmt.Errorf("seal: tar write %s: %w", e.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("seal: tar close: %w", err)
	}
	return nil
}

// Open decrypts a whole object and returns its manifest and payload. A first entry other than the
// manifest means the container was not built by this code, so its layout cannot be trusted.
func Open(object []byte, identities ...age.Identity) (Manifest, []byte, error) {
	if len(identities) == 0 {
		return Manifest{}, nil, errors.New("seal: no age identity supplied")
	}
	dec, err := age.Decrypt(bytes.NewReader(object), identities...)
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("age decrypt: %w", err)
	}
	zr, err := zstd.NewReader(dec, zstd.WithDecoderMaxMemory(maxDecompressedBytes))
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("zstd reader: %w", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)

	hdr, err := tr.Next()
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("read first tar entry: %w", err)
	}
	if hdr.Name != ManifestEntry {
		return Manifest{}, nil, fmt.Errorf("first entry is %q, want %q: manifest-first is the container contract",
			hdr.Name, ManifestEntry)
	}
	if hdr.Size > maxManifestBytes {
		return Manifest{}, nil, fmt.Errorf("manifest claims %d bytes, over the %d limit", hdr.Size, maxManifestBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("read manifest entry: %w", err)
	}
	if int64(len(raw)) < hdr.Size {
		return Manifest{}, nil, fmt.Errorf("manifest entry truncated: %d of %d bytes", len(raw), hdr.Size)
	}
	m, err := DecodeManifest(raw)
	if err != nil {
		return Manifest{}, nil, err
	}

	if hdr, err = tr.Next(); err != nil {
		return Manifest{}, nil, fmt.Errorf("seal: no payload entry: %w", err)
	}
	if hdr.Name != PayloadEntry {
		return Manifest{}, nil, fmt.Errorf("seal: second entry is %q, want %q", hdr.Name, PayloadEntry)
	}
	payload, err := io.ReadAll(io.LimitReader(tr, maxDecompressedBytes))
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("seal: read payload: %w", err)
	}
	// The manifest describes bytes; verify it describes these bytes.
	if got := Hash(payload); got != m.ShippedHash {
		return Manifest{}, nil, fmt.Errorf("seal: payload hash %s does not match manifest shipped_hash %s",
			got, m.ShippedHash)
	}
	return m, payload, nil
}

func recipientID(r age.Recipient) string {
	if s, ok := r.(fmt.Stringer); ok {
		return s.String()
	}
	return fmt.Sprintf("%T", r)
}
