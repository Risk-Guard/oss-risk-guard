package storage

import (
	"context"
	"fmt"
	"time"

	dag_impl "risk-guard/src/dag-impl"
	executiondag "risk-guard/src/execution-dag"
)

type FieldNotFoundError struct {
	Field string
}

func (e *FieldNotFoundError) Error() string {
	return fmt.Sprintf("field %q does not exist", e.Field)
}

type MetadataResult struct {
	AnalysisIdentifier string         `json:"analysis_identifier"`
	AnalyzedAt         time.Time      `json:"analyzed_at"`
	TraceID            string         `json:"trace_id,omitempty"`
	SourceURL          string         `json:"source_url,omitempty"`
	Ecosystem          string         `json:"ecosystem,omitempty"`
	PackageName        string         `json:"package_name,omitempty"`
	PackageVersion     string         `json:"package_version,omitempty"`
	Input              dag_impl.Input `json:"input"`
	Data               map[string]any `json:"data"`
}

type MetadataBackend interface {
	WriteAll(ctx context.Context, outputDir string, entries []executiondag.Entry, input dag_impl.Input) error
	Get(ctx context.Context, analysisID string, fields []string) (*MetadataResult, error)
}
