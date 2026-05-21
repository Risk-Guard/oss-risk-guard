package artifact

import (
	"crypto/sha1" //nolint:gosec // testing legacy verification
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewHasher_SHA256(t *testing.T) {
	h, err := NewHasher("sha256")
	require.NoError(t, err)
	require.NotNil(t, h)
	h.Write([]byte("test"))
	require.Len(t, h.Sum(nil), 32)
}

func TestNewHasher_SHA512(t *testing.T) {
	h, err := NewHasher("sha512")
	require.NoError(t, err)
	require.NotNil(t, h)
	h.Write([]byte("test"))
	require.Len(t, h.Sum(nil), 64)
}

func TestNewHasher_SHA1(t *testing.T) {
	h, err := NewHasher("sha1")
	require.NoError(t, err)
	require.NotNil(t, h)
	h.Write([]byte("test"))
	require.Len(t, h.Sum(nil), 20)
}

func TestNewHasher_Empty(t *testing.T) {
	_, err := NewHasher("")
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty hash algorithm")
}

func TestNewHasher_Unknown(t *testing.T) {
	_, err := NewHasher("md5")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported hash algorithm")
}

func TestVerifyHashFromDigest_HexSHA256(t *testing.T) {
	data := []byte("test content for hashing")
	hash := sha256.Sum256(data)
	expected := hex.EncodeToString(hash[:])

	err := VerifyHashFromDigest(hash[:], expected, "sha256")
	require.NoError(t, err)
}

func TestVerifyHashFromDigest_Base64SHA256(t *testing.T) {
	data := []byte("test content for base64")
	hash := sha256.Sum256(data)
	expected := base64.StdEncoding.EncodeToString(hash[:])

	err := VerifyHashFromDigest(hash[:], expected, "sha256")
	require.NoError(t, err)
}

func TestVerifyHashFromDigest_SRISHA512(t *testing.T) {
	data := []byte("test content for SRI")
	hash := sha512.Sum512(data)
	b64 := base64.StdEncoding.EncodeToString(hash[:])
	sri := "sha512-" + b64

	err := VerifyHashFromDigest(hash[:], sri, "sha512")
	require.NoError(t, err)
}

func TestVerifyHashFromDigest_SHA1(t *testing.T) {
	data := []byte("test content for sha1")
	hash := sha1.Sum(data) //nolint:gosec // testing legacy verification
	expected := hex.EncodeToString(hash[:])

	err := VerifyHashFromDigest(hash[:], expected, "sha1")
	require.NoError(t, err)
}

func TestVerifyHashFromDigest_Mismatch(t *testing.T) {
	data := []byte("actual content")
	hash := sha256.Sum256(data)

	err := VerifyHashFromDigest(hash[:], "0000000000000000000000000000000000000000000000000000000000000000", "sha256")
	require.Error(t, err)
	require.Contains(t, err.Error(), "hash mismatch")
}

func TestVerifyHashFromDigest_EmptyExpected(t *testing.T) {
	err := VerifyHashFromDigest([]byte{0}, "", "sha256")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no hash provided")
}
