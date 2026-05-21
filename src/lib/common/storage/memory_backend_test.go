package storage

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestMemoryBackend_InsertGetExists(t *testing.T) {
	b := NewMemoryBackend()
	ctx := context.Background()
	now := time.Now().UTC()

	params := ChecksInsertParams{
		Checks: ChecksResult{
			AnalysisIdentifier: "package/npm/lodash",
			AnalyzedAt:         &now,
			Checks: []Check{
				{CheckCode: "VULN_UNFIXED", CheckStatus: StatusViolation, Rationale: "vuln"},
			},
		},
		Policy: &PolicyData{RawYAML: "rules: []"},
	}

	if err := b.Checks().Insert(ctx, params); err != nil {
		t.Fatalf("insert: %v", err)
	}

	got, err := b.Checks().Get(ctx, "package/npm/lodash")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("expected row, got nil")
	}
	if got.Checks.AnalysisIdentifier != "package/npm/lodash" {
		t.Errorf("AnalysisIdentifier mismatch: %q", got.Checks.AnalysisIdentifier)
	}
	if len(got.Checks.Checks) != 1 || got.Checks.Checks[0].CheckCode != "VULN_UNFIXED" {
		t.Errorf("checks mismatch: %v", got.Checks.Checks)
	}

	exists, err := b.Checks().Exists(ctx, "package/npm/lodash")
	if err != nil {
		t.Fatalf("exists: %v", err)
	}
	if !exists {
		t.Error("expected exists=true")
	}

	missing, err := b.Checks().Get(ctx, "package/npm/missing")
	if err != nil {
		t.Fatalf("get missing: %v", err)
	}
	if missing != nil {
		t.Errorf("expected nil for missing key, got %v", missing)
	}

	// Contract (matches GCSChecksBackend): GetPolicy returns the PolicyData as
	// JSON so policy.Evaluate can json.Unmarshal it into its storedPolicy struct.
	policyJSON, err := b.Checks().GetPolicy(ctx, "package/npm/lodash")
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	var decoded PolicyData
	if err := json.Unmarshal([]byte(policyJSON), &decoded); err != nil {
		t.Fatalf("GetPolicy did not return JSON-encoded PolicyData: %v (got %q)", err, policyJSON)
	}
	if decoded.RawYAML != "rules: []" {
		t.Errorf("RawYAML mismatch: got %q", decoded.RawYAML)
	}
}

func TestMemoryBackend_GetPolicyMissingReturnsEmpty(t *testing.T) {
	b := NewMemoryBackend()
	got, err := b.Checks().GetPolicy(context.Background(), "missing")
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty string for missing row, got %q", got)
	}
}

func TestMemoryBackend_GetBatchSkipsMissing(t *testing.T) {
	b := NewMemoryBackend()
	ctx := context.Background()

	for _, id := range []string{"package/npm/a", "package/npm/b"} {
		_ = b.Checks().Insert(ctx, ChecksInsertParams{
			Checks: ChecksResult{AnalysisIdentifier: id},
		})
	}

	rows, err := b.Checks().GetBatch(ctx, []string{"package/npm/a", "package/npm/missing", "package/npm/b"})
	if err != nil {
		t.Fatalf("get batch: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows (missing skipped), got %d", len(rows))
	}
}

func TestMemoryBackend_BackendInterface(t *testing.T) {
	var _ Backend = NewMemoryBackend()
}
