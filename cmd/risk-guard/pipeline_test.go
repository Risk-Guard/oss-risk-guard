package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"github.com/Risk-Guard/oss-risk-guard/src/violations"

	"go.uber.org/zap"
)

func testCtx() context.Context {
	return ctxutil.SetLogger(context.Background(), zap.NewNop())
}

func TestKeysAndLocations_PreservesOrderAndSkipsNilLocations(t *testing.T) {
	pkgJSON := "package.json"
	line := 12

	deps := []sbom.DirectDep{
		{Key: "package/npm/lodash", Location: &models.LocationInfo{File: &pkgJSON, LineNumber: &line}},
		{Key: "package/npm/date-fns?version=4.1.0", Location: nil},
		{Key: "package/pypi/requests", Location: &models.LocationInfo{File: &pkgJSON}},
	}

	keys, byKey := keysAndLocations(deps)

	wantKeys := []string{
		"package/npm/lodash",
		"package/npm/date-fns?version=4.1.0",
		"package/pypi/requests",
	}
	if len(keys) != len(wantKeys) {
		t.Fatalf("keys length: got %d want %d", len(keys), len(wantKeys))
	}
	for i, k := range wantKeys {
		if keys[i] != k {
			t.Errorf("keys[%d] = %q, want %q", i, keys[i], k)
		}
	}
	if _, present := byKey["package/npm/date-fns?version=4.1.0"]; present {
		t.Error("nil-location dep should be absent from map")
	}
	if got := byKey["package/npm/lodash"]; got == nil || got.File == nil || *got.File != "package.json" {
		t.Errorf("lodash location missing: %+v", got)
	}
}

func TestKeysAndLocations_EmptyInput(t *testing.T) {
	keys, byKey := keysAndLocations(nil)
	if len(keys) != 0 {
		t.Errorf("expected empty keys, got %v", keys)
	}
	if len(byKey) != 0 {
		t.Errorf("expected empty map, got %v", byKey)
	}
}

func TestAssembleReport_NoViolationsProducesGradedReport(t *testing.T) {
	ctx := testCtx()
	local := &violations.AnalysisViolations{AnalysisID: "source/test"}
	report, err := assembleReport(ctx, "source/test", local, nil, nil, nil)
	if err != nil {
		t.Fatalf("assembleReport: %v", err)
	}
	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 graded run, got %d", len(report.Runs))
	}
}

func TestAssembleReport_FailuresAppendErrorRuns(t *testing.T) {
	ctx := testCtx()
	report, err := assembleReport(ctx, "source/test", nil, nil, []packageError{
		{Key: "package/npm/x", Name: "x", Err: os.ErrNotExist},
	}, nil)
	if err != nil {
		t.Fatalf("assembleReport: %v", err)
	}
	if len(report.Runs) != 2 {
		t.Fatalf("expected graded run + 1 failure run, got %d", len(report.Runs))
	}
}

func TestWriteReport_CreatesParentDirAndFile(t *testing.T) {
	ctx := testCtx()
	report, err := assembleReport(ctx, "source/test", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("assembleReport: %v", err)
	}

	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "nested", "subdir", "out.sarif")

	if err := writeReport(report, outPath); err != nil {
		t.Fatalf("writeReport: %v", err)
	}

	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("output file missing: %v", err)
	}
	if info.Size() == 0 {
		t.Errorf("output file is empty")
	}
}

// GitHub Code Scanning rejects any result without a physicalLocation. A local
// source violation produces a logical-only result and a failure adds an
// AUDIT_ERROR run with another logical-only result; assembleReport must anchor
// both so the report uploads cleanly.
func TestAssembleReport_EveryResultHasPhysicalLocation(t *testing.T) {
	ctx := testCtx()
	local := &violations.AnalysisViolations{
		AnalysisID: "source//abs/path/public-test",
		Violations: []violations.Violation{
			{CheckCode: "SOURCE_NO_LICENSE", Rationale: "No license file found in source repository"},
		},
	}
	report, err := assembleReport(ctx, "source//abs/path/public-test", local, nil, []packageError{
		{Key: "package/npm/x", Name: "x", Err: os.ErrNotExist},
	}, nil)
	if err != nil {
		t.Fatalf("assembleReport: %v", err)
	}

	results := 0
	for _, run := range report.Runs {
		for _, res := range run.Results {
			results++
			hasPhys := false
			for _, loc := range res.Locations {
				if loc != nil && loc.PhysicalLocation != nil {
					hasPhys = true
					break
				}
			}
			if !hasPhys {
				t.Errorf("rule %s: result has no physical location", *res.RuleID)
			}
		}
	}
	if results == 0 {
		t.Fatal("expected at least one result across all runs")
	}
}
