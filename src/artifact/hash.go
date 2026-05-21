package artifact

import (
	"crypto/sha1" //nolint:gosec // sha1 needed for legacy artifact verification
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
)

func NewHasher(algorithm string) (hash.Hash, error) {
	switch algorithm {
	case "sha256":
		return sha256.New(), nil
	case "sha512":
		return sha512.New(), nil
	case "sha1":
		return sha1.New(), nil //nolint:gosec // sha1 needed for legacy artifact verification
	case "":
		return nil, fmt.Errorf("empty hash algorithm")
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}
}

func VerifyHashFromDigest(digest []byte, expectedHash, algorithm string) error {
	if expectedHash == "" {
		return fmt.Errorf("no hash provided for verification")
	}

	normalizedHash, isBase64, err := parseExpectedHash(expectedHash, algorithm)
	if err != nil {
		return err
	}

	var actualEncoded string
	if isBase64 {
		actualEncoded = base64.StdEncoding.EncodeToString(digest)
	} else {
		actualEncoded = hex.EncodeToString(digest)
	}

	if actualEncoded != normalizedHash {
		return fmt.Errorf("hash mismatch: expected %s, got %s", normalizedHash, actualEncoded)
	}

	return nil
}
