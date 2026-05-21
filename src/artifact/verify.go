package artifact

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

func parseExpectedHash(hashStr, algorithm string) (string, bool, error) {
	if strings.Contains(hashStr, "-") {
		parts := strings.SplitN(hashStr, "-", 2)
		if len(parts) != 2 {
			return "", false, fmt.Errorf("invalid SRI hash format: %s", hashStr)
		}
		return parts[1], true, nil
	}

	hashLen := len(hashStr)
	isBase64 := isBase64Format(hashStr, algorithm, hashLen)

	if isBase64 {
		return hashStr, true, nil
	}

	hashStr = strings.ToLower(hashStr)
	expectedHexLen := getExpectedHexLength(algorithm)
	if expectedHexLen > 0 && hashLen != expectedHexLen {
		return "", false, fmt.Errorf("invalid %s hash length: %d (expected %d)", algorithm, hashLen, expectedHexLen)
	}

	return hashStr, false, nil
}

func isBase64Format(hashStr, algorithm string, hashLen int) bool {
	expectedBase64Len := getExpectedBase64Length(algorithm)
	if expectedBase64Len > 0 && hashLen == expectedBase64Len {
		_, err := base64.StdEncoding.DecodeString(hashStr)
		return err == nil
	}

	_, err := hex.DecodeString(hashStr)
	if err != nil {
		_, b64Err := base64.StdEncoding.DecodeString(hashStr)
		return b64Err == nil
	}

	return false
}

func getExpectedHexLength(algorithm string) int {
	switch algorithm {
	case "sha256":
		return 64
	case "sha512":
		return 128
	case "sha1":
		return 40
	default:
		return 0
	}
}

func getExpectedBase64Length(algorithm string) int {
	switch algorithm {
	case "sha256":
		return 44
	case "sha512":
		return 88
	case "sha1":
		return 28
	default:
		return 0
	}
}
