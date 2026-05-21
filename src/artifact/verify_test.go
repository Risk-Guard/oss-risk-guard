package artifact

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseExpectedHash_HexFormat(t *testing.T) {
	hash := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	result, isBase64, err := parseExpectedHash(hash, "sha256")
	require.NoError(t, err)
	require.False(t, isBase64)
	require.Equal(t, hash, result)
}

func TestParseExpectedHash_Base64Format(t *testing.T) {
	rawHash := make([]byte, 32)
	for i := range rawHash {
		rawHash[i] = byte(i)
	}
	hash := base64.StdEncoding.EncodeToString(rawHash)

	result, isBase64, err := parseExpectedHash(hash, "sha256")
	require.NoError(t, err)
	require.True(t, isBase64)
	require.Equal(t, hash, result)
}

func TestParseExpectedHash_SRIFormat(t *testing.T) {
	b64Part := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	sriHash := "sha256-" + b64Part

	result, isBase64, err := parseExpectedHash(sriHash, "sha256")
	require.NoError(t, err)
	require.True(t, isBase64)
	require.Equal(t, b64Part, result)
}

func TestGetExpectedHexLength(t *testing.T) {
	require.Equal(t, 64, getExpectedHexLength("sha256"))
	require.Equal(t, 128, getExpectedHexLength("sha512"))
	require.Equal(t, 40, getExpectedHexLength("sha1"))
	require.Equal(t, 0, getExpectedHexLength("unknown"))
}

func TestGetExpectedBase64Length(t *testing.T) {
	require.Equal(t, 44, getExpectedBase64Length("sha256"))
	require.Equal(t, 88, getExpectedBase64Length("sha512"))
	require.Equal(t, 28, getExpectedBase64Length("sha1"))
	require.Equal(t, 0, getExpectedBase64Length("unknown"))
}
