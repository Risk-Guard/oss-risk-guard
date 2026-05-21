package artifact

import (
	"context"
	"fmt"
	"io"
	"risk-guard/src/archive"
	"risk-guard/src/models"
)

type ExtractionResult struct {
	Files       map[string]string
	Verified    bool
	VerifyError *string
}

func StreamExtractAndVerify(ctx context.Context, dist *models.DistributionInfo, filename, ecosystem string) (*ExtractionResult, error) {
	patterns, ok := archive.TargetPatterns[ecosystem]
	if !ok {
		return nil, fmt.Errorf("no target patterns for ecosystem: %s", ecosystem)
	}

	stream, err := StreamDownload(ctx, dist.URL)
	if err != nil {
		return nil, fmt.Errorf("downloading artifact: %w", err)
	}
	defer func() { _ = stream.Body.Close() }()

	result := &ExtractionResult{}
	hasHash := dist.Hash != "" && dist.HashAlgorithm != ""

	var hashReader io.Reader
	var hasher interface{ Sum([]byte) []byte }

	if hasHash {
		h, err := NewHasher(dist.HashAlgorithm)
		if err != nil {
			errStr := err.Error()
			result.VerifyError = &errStr
			hashReader = stream.Body
		} else {
			hasher = h
			hashReader = io.TeeReader(stream.Body, h)
		}
	} else {
		reason := "no hash provided by registry"
		result.VerifyError = &reason
		hashReader = stream.Body
	}

	result.Files, err = archive.ExtractTargetFilesFromReader(hashReader, filename, patterns)
	if err != nil {
		return nil, fmt.Errorf("extracting files: %w", err)
	}

	if hasher != nil {
		if _, drainErr := io.Copy(io.Discard, hashReader); drainErr != nil {
			errStr := fmt.Sprintf("failed to drain stream for hash verification: %s", drainErr.Error())
			result.VerifyError = &errStr
			hasher = nil
		}
	}

	if hasher != nil {
		digest := hasher.Sum(nil)
		if err := VerifyHashFromDigest(digest, dist.Hash, dist.HashAlgorithm); err != nil {
			errStr := err.Error()
			result.VerifyError = &errStr
			result.Files = nil
		} else {
			result.Verified = true
		}
	}

	return result, nil
}
