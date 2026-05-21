package storage

import (
	"context"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

type NoOpBackend struct {
	metadata *noOpMetadataBackend
	checks   *noOpChecksBackend
}

func NewNoOpBackend() *NoOpBackend {
	return &NoOpBackend{
		metadata: &noOpMetadataBackend{},
		checks:   &noOpChecksBackend{},
	}
}

func (n *NoOpBackend) Metadata() MetadataBackend {
	return n.metadata
}

func (n *NoOpBackend) Checks() ChecksBackend {
	return n.checks
}

type noOpMetadataBackend struct{}

func (n *noOpMetadataBackend) WriteAll(ctx context.Context, outputDir string, entries []executiondag.Entry, input dag_impl.Input) error {
	return nil
}

func (n *noOpMetadataBackend) Get(ctx context.Context, analysisID string, fields []string) (*MetadataResult, error) {
	return nil, nil
}

type noOpChecksBackend struct{}

func (n *noOpChecksBackend) Get(ctx context.Context, analysisID string) (*ChecksInsertParams, error) {
	return nil, nil
}

func (n *noOpChecksBackend) Exists(ctx context.Context, analysisID string) (bool, error) {
	return false, nil
}

func (n *noOpChecksBackend) Insert(ctx context.Context, params ChecksInsertParams) error {
	return nil
}

func (n *noOpChecksBackend) GetBatch(ctx context.Context, analysisIDs []string) ([]*ChecksInsertParams, error) {
	return nil, nil
}

func (n *noOpChecksBackend) Invalidate(ctx context.Context, analysisIDs []string) (int64, error) {
	return 0, nil
}

func (n *noOpChecksBackend) GetPolicy(ctx context.Context, analysisID string) (string, error) {
	return "", nil
}
