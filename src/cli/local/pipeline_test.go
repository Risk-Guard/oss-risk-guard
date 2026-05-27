package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

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

func TestAssembleReport_LocalAndAuditRuns(t *testing.T) {
	local := sarif.NewRunWithInformationURI("risk-guard", "https://example.invalid")
	a := sarif.NewRunWithInformationURI("risk-guard", "https://example.invalid")
	b := sarif.NewRunWithInformationURI("risk-guard", "https://example.invalid")

	report, err := assembleReport(local, []*sarif.Run{a, b})
	if err != nil {
		t.Fatalf("assembleReport: %v", err)
	}
	if len(report.Runs) != 3 {
		t.Fatalf("expected 3 runs (local + 2 audit), got %d", len(report.Runs))
	}
	if report.Runs[0] != local {
		t.Error("local run should be first")
	}
	if report.Runs[1] != a || report.Runs[2] != b {
		t.Error("audit runs should follow in given order")
	}
}

func TestAssembleReport_NilLocalRun(t *testing.T) {
	a := sarif.NewRunWithInformationURI("risk-guard", "https://example.invalid")
	report, err := assembleReport(nil, []*sarif.Run{a})
	if err != nil {
		t.Fatalf("assembleReport: %v", err)
	}
	if len(report.Runs) != 1 || report.Runs[0] != a {
		t.Errorf("expected single audit run, got %+v", report.Runs)
	}
}

func TestAssembleReport_EmptyEverything(t *testing.T) {
	report, err := assembleReport(nil, nil)
	if err != nil {
		t.Fatalf("assembleReport: %v", err)
	}
	if len(report.Runs) != 0 {
		t.Errorf("expected zero runs, got %d", len(report.Runs))
	}
}

func TestWriteReport_CreatesParentDirAndFile(t *testing.T) {
	a := sarif.NewRunWithInformationURI("risk-guard", "https://example.invalid")
	report, err := assembleReport(nil, []*sarif.Run{a})
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
