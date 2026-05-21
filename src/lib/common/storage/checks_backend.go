package storage

import (
	"context"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/overrides"
)

type CheckStatus string

const (
	StatusCompliant CheckStatus = "compliant"
	StatusViolation CheckStatus = "violation"
	StatusSkipped   CheckStatus = "skipped"
)

func (s CheckStatus) String() string {
	return string(s)
}

// Outcomes maps each check status to a description of what that result means.
type Outcomes map[CheckStatus]string

type Check struct {
	CheckCode   string         `json:"check_code"`
	CheckStatus CheckStatus    `json:"check_status"`
	Rationale   string         `json:"rationale"`
	Evidence    []string       `json:"evidence,omitempty"`
	Thresholds  map[string]any `json:"thresholds"`
}
type ChecksResult struct {
	AnalysisIdentifier string                      `json:"analysis_identifier"`
	AppliedOverrides   []overrides.AppliedOverride `json:"applied_overrides,omitempty"`
	AnalyzedAt         *time.Time                  `json:"analyzed_at"`
	Checks             []Check                     `json:"checks"`
}

type PolicyData struct {
	Policy  any    `json:"policy,omitempty"`
	RawYAML string `json:"raw_yaml,omitempty"`
	Error   string `json:"error,omitempty"`
}

type ChecksInsertParams struct {
	Checks ChecksResult
	Policy *PolicyData
}

type ChecksBackend interface {
	Get(ctx context.Context, analysisID string) (*ChecksInsertParams, error)
	Exists(ctx context.Context, analysisID string) (bool, error)
	Insert(ctx context.Context, params ChecksInsertParams) error
	GetBatch(ctx context.Context, analysisIDs []string) ([]*ChecksInsertParams, error)
	GetPolicy(ctx context.Context, analysisID string) (string, error)
}
