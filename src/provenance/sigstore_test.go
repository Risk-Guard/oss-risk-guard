package provenance

import (
	"context"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// loadFixture returns the real captured attestation bundle for
// pdfjs-dist@5.7.284 and its registry sha512 (base64, npm SRI form).
func loadFixture(t *testing.T) (bundleJSON []byte, sha512b64 string) {
	t.Helper()
	b, err := os.ReadFile("testdata/pdfjs-dist-5.7.284-attestation.json")
	require.NoError(t, err)
	integ, err := os.ReadFile("testdata/pdfjs-dist-5.7.284-integrity.txt")
	require.NoError(t, err)
	return b, strings.TrimPrefix(strings.TrimSpace(string(integ)), "sha512-")
}

// TestSigstoreVerifier_RealProvenance verifies the real pdfjs-dist attestation
// fully offline against the embedded trust root, proving the artifact was built
// from mozilla/pdf.js — the motivating false-positive case.
func TestSigstoreVerifier_RealProvenance(t *testing.T) {
	v, err := NewSigstoreVerifier()
	require.NoError(t, err)

	bundleJSON, digest := loadFixture(t)
	res, err := v.Verify(context.Background(), Request{
		Bundle:         bundleJSON,
		ArtifactSHA512: digest,
		PackageName:    "pdfjs-dist",
		Version:        "5.7.284",
	})
	require.NoError(t, err)
	require.Truef(t, res.Verified, "expected verified; FailReason=%q", res.FailReason)
	require.Equal(t, "https://github.com/mozilla/pdf.js", res.SourceRepo)
	require.Equal(t, FailNone, res.FailReason)
	require.NotEmpty(t, res.Commit)
}

// TestSigstoreVerifier_DigestMismatch confirms a validly-signed bundle whose
// subject does not match the given artifact hash is reported as a digest
// mismatch, not silently accepted.
func TestSigstoreVerifier_DigestMismatch(t *testing.T) {
	v, err := NewSigstoreVerifier()
	require.NoError(t, err)

	bundleJSON, _ := loadFixture(t)
	wrong := base64.StdEncoding.EncodeToString(make([]byte, 64)) // valid sha512 length, wrong value
	res, err := v.Verify(context.Background(), Request{
		Bundle:         bundleJSON,
		ArtifactSHA512: wrong,
		PackageName:    "pdfjs-dist",
		Version:        "5.7.284",
	})
	require.NoError(t, err)
	require.False(t, res.Verified)
	require.Equal(t, FailDigestMismatch, res.FailReason)
}

// TestSigstoreVerifier_TamperedBundle confirms a corrupted signature fails
// verification (reported as invalid-signature), not accepted.
func TestSigstoreVerifier_TamperedBundle(t *testing.T) {
	v, err := NewSigstoreVerifier()
	require.NoError(t, err)

	bundleJSON, digest := loadFixture(t)
	// Flip bytes in the middle of the signed material to break the signature.
	tampered := make([]byte, len(bundleJSON))
	copy(tampered, bundleJSON)
	for i := len(tampered) / 2; i < len(tampered)/2+200 && i < len(tampered); i++ {
		if tampered[i] >= 'a' && tampered[i] <= 'y' {
			tampered[i]++
		}
	}
	res, err := v.Verify(context.Background(), Request{
		Bundle:         tampered,
		ArtifactSHA512: digest,
		PackageName:    "pdfjs-dist",
		Version:        "5.7.284",
	})
	require.NoError(t, err)
	require.False(t, res.Verified)
}

func TestSigstoreVerifier_NoAttestation(t *testing.T) {
	v, err := NewSigstoreVerifier()
	require.NoError(t, err)
	res, err := v.Verify(context.Background(), Request{Bundle: []byte(`{"attestations":[]}`)})
	require.NoError(t, err)
	require.Equal(t, FailNoAttestation, res.FailReason)
}
