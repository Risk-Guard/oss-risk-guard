package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"

	"go.uber.org/zap"
	"sigs.k8s.io/yaml"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

type FileBackend struct {
	metadata *fileMetadataBackend
	checks   *fileChecksBackend
}

func NewFileBackend() *FileBackend {
	return &FileBackend{
		metadata: &fileMetadataBackend{},
		checks:   &fileChecksBackend{},
	}
}

func (f *FileBackend) Metadata() MetadataBackend {
	return f.metadata
}

func (f *FileBackend) Checks() ChecksBackend {
	return f.checks
}

type fileMetadataBackend struct{}

func (f *fileMetadataBackend) WriteAll(ctx context.Context, outputDir string, entries []executiondag.Entry, input dag_impl.Input) error {
	log := ctxutil.GetLogger(ctx)

	for _, entry := range entries {
		if entry.Data == nil {
			continue
		}

		path, err := buildPath(outputDir, entry, input)
		if err != nil {
			return fmt.Errorf("building path for entry %q: %w", entry.Key, err)
		}

		if err := writeEntry(path, entry); err != nil {
			return fmt.Errorf("writing entry %q: %w", entry.Key, err)
		}

		log.Debug("wrote entry", zap.String("key", entry.Key), zap.String("path", path))
	}

	return nil
}

func (f *fileMetadataBackend) Get(ctx context.Context, analysisID string, fields []string) (*MetadataResult, error) {
	return nil, nil
}

type fileChecksBackend struct{}

func (f *fileChecksBackend) Get(ctx context.Context, analysisID string) (*ChecksInsertParams, error) {
	return nil, nil
}

func (f *fileChecksBackend) Exists(ctx context.Context, analysisID string) (bool, error) {
	return false, nil
}

func (f *fileChecksBackend) Insert(ctx context.Context, params ChecksInsertParams) error {
	return nil
}

func (f *fileChecksBackend) GetBatch(ctx context.Context, analysisIDs []string) ([]*ChecksInsertParams, error) {
	return nil, nil
}

func (f *fileChecksBackend) Invalidate(ctx context.Context, analysisIDs []string) (int64, error) {
	return 0, nil
}

func (f *fileChecksBackend) GetPolicy(ctx context.Context, analysisID string) (string, error) {
	return "", nil
}

func buildPath(outputDir string, entry executiondag.Entry, input dag_impl.Input) (string, error) {
	return filepath.Join(outputDir, input.BasePath(), entry.Key+".yml"), nil
}

func writeEntry(path string, entry executiondag.Entry) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("creating directory %q: %w", dir, err)
	}

	data, err := yaml.Marshal(entry.Data)
	if err != nil {
		return fmt.Errorf("marshaling data: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing file: %w", err)
	}

	return nil
}
