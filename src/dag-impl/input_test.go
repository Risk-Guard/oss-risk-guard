package dag_impl

import (
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/models"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

// Mock output for testing - uses BaseOutput with Output field set
func newMockOutput(status executiondag.Status, reason string, sourceURL *string, packages []models.PackageInfo) *BaseOutput {
	baseOutput := NewBaseOutput(status, reason, Input{})

	// Set output field if there's anything to merge
	if sourceURL != nil || packages != nil {
		baseOutput.Output = &Input{
			SourceURL: sourceURL,
			Packages:  packages,
		}
	}

	return &baseOutput
}

// Non-mergeable output for testing
type mockNonMergeableOutput struct {
	executiondag.BaseOutput
}

func TestInput_Merge_AccumulatesPackages(t *testing.T) {
	input := &Input{
		SourceURL: nil,
		Packages:  []models.PackageInfo{},
	}

	pkg1 := models.PackageInfo{Name: "pkg1", Ecosystem: "npm"}
	pkg2 := models.PackageInfo{Name: "pkg2", Ecosystem: "pypi"}
	pkg3 := models.PackageInfo{Name: "pkg3", Ecosystem: "npm"}

	output1 := newMockOutput(executiondag.StatusSuccess, "", nil, []models.PackageInfo{pkg1})
	output2 := newMockOutput(executiondag.StatusSuccess, "", nil, []models.PackageInfo{pkg2, pkg3})

	input.Merge(output1)
	input.Merge(output2)

	if len(input.Packages) != 3 {
		t.Errorf("Expected 3 packages, got %d", len(input.Packages))
	}

	// Verify packages are sorted by ecosystem, then name
	expected := []string{"pkg1", "pkg3", "pkg2"} // npm before pypi
	for idx, exp := range expected {
		if input.Packages[idx].Name != exp {
			t.Errorf("Expected package %d to be '%s', got '%s'", idx, exp, input.Packages[idx].Name)
		}
	}
}

func TestInput_Merge_SourceURLSet(t *testing.T) {
	// Test setting URL from nil
	input := &Input{
		SourceURL: nil,
		Packages:  []models.PackageInfo{},
	}

	url := "https://github.com/test/repo"
	output := newMockOutput(executiondag.StatusSuccess, "", &url, nil)

	input.Merge(output)

	if input.SourceURL == nil {
		t.Fatal("SourceURL should be set")
	}
	if *input.SourceURL != url {
		t.Errorf("Expected URL '%s', got '%s'", url, *input.SourceURL)
	}
}

func TestInput_Merge_SourceURLFromEmpty(t *testing.T) {
	// Test setting URL from empty string
	empty := ""
	input := &Input{
		SourceURL: &empty,
		Packages:  []models.PackageInfo{},
	}

	url := "https://github.com/test/repo"
	output := newMockOutput(executiondag.StatusSuccess, "", &url, nil)

	input.Merge(output)

	if input.SourceURL == nil {
		t.Fatal("SourceURL should be set")
	}
	if *input.SourceURL != url {
		t.Errorf("Expected URL '%s', got '%s'", url, *input.SourceURL)
	}
}

func TestInput_Merge_SourceURLSameValue(t *testing.T) {
	// Test setting same URL (should be no-op, no panic)
	url := "https://github.com/test/repo"
	input := &Input{
		SourceURL: &url,
		Packages:  []models.PackageInfo{},
	}

	output := newMockOutput(executiondag.StatusSuccess, "", &url, nil)

	// Should not panic
	input.Merge(output)

	if *input.SourceURL != url {
		t.Errorf("URL should remain '%s', got '%s'", url, *input.SourceURL)
	}
}

func TestInput_Merge_SourceURLConflict(t *testing.T) {
	// Test URL conflict - should NOT panic
	// The existing URL (user-provided) takes priority
	// The PACKAGE_SOURCE_URL_MISMATCH check will detect and report the conflict
	url1 := "https://github.com/test/repo1"
	url2 := "https://github.com/test/repo2"

	input := &Input{
		SourceURL: &url1,
		Packages:  []models.PackageInfo{},
	}

	output := newMockOutput(executiondag.StatusSuccess, "", &url2, nil)

	// Should not panic
	input.Merge(output)

	// Verify the original URL is kept (user-provided takes priority)
	if input.SourceURL == nil {
		t.Fatal("SourceURL should not be nil")
	}
	if *input.SourceURL != url1 {
		t.Errorf("Expected URL '%s' (original), got '%s'", url1, *input.SourceURL)
	}
}

func TestInput_Merge_OutputURLNil(t *testing.T) {
	// Output with nil URL should not affect input
	url := "https://github.com/test/repo"
	input := &Input{
		SourceURL: &url,
		Packages:  []models.PackageInfo{},
	}

	output := newMockOutput(executiondag.StatusSuccess, "", nil, nil)

	input.Merge(output)

	if *input.SourceURL != url {
		t.Errorf("Input URL should remain '%s', got '%s'", url, *input.SourceURL)
	}
}

func TestInput_Merge_OutputURLEmpty(t *testing.T) {
	// Output with empty URL should not affect input
	url := "https://github.com/test/repo"
	empty := ""
	input := &Input{
		SourceURL: &url,
		Packages:  []models.PackageInfo{},
	}

	output := newMockOutput(executiondag.StatusSuccess, "", &empty, nil)

	input.Merge(output)

	if *input.SourceURL != url {
		t.Errorf("Input URL should remain '%s', got '%s'", url, *input.SourceURL)
	}
}

func TestInput_Merge_NonMergeableOutput(t *testing.T) {
	// Non-mergeable outputs should be ignored gracefully
	input := &Input{
		SourceURL: nil,
		Packages:  []models.PackageInfo{},
	}

	nonMergeableOutput := &mockNonMergeableOutput{
		BaseOutput: executiondag.BaseOutput{
			Status:       executiondag.StatusSuccess,
			StatusReason: "",
		},
	}

	// Should not panic
	input.Merge(nonMergeableOutput)

	// Input should be unchanged
	if input.SourceURL != nil {
		t.Error("SourceURL should remain nil")
	}
	if len(input.Packages) != 0 {
		t.Error("Packages should remain empty")
	}
}

func TestInput_Merge_EmptyPackageSlice(t *testing.T) {
	// Empty package slice should not affect input
	pkg1 := models.PackageInfo{Name: "pkg1", Ecosystem: "npm"}
	input := &Input{
		SourceURL: nil,
		Packages:  []models.PackageInfo{pkg1},
	}

	output := newMockOutput(executiondag.StatusSuccess, "", nil, []models.PackageInfo{})

	input.Merge(output)

	if len(input.Packages) != 1 {
		t.Errorf("Expected 1 package, got %d", len(input.Packages))
	}
}

func TestInput_Merge_NilPackageSlice(t *testing.T) {
	// Nil package slice should not affect input
	pkg1 := models.PackageInfo{Name: "pkg1", Ecosystem: "npm"}
	input := &Input{
		SourceURL: nil,
		Packages:  []models.PackageInfo{pkg1},
	}

	output := newMockOutput(executiondag.StatusSuccess, "", nil, nil)

	input.Merge(output)

	if len(input.Packages) != 1 {
		t.Errorf("Expected 1 package, got %d", len(input.Packages))
	}
}

func TestInput_Merge_MultipleOutputs(t *testing.T) {
	// Test realistic scenario with multiple outputs
	input := &Input{
		SourceURL: nil,
		Packages:  []models.PackageInfo{},
	}

	url := "https://github.com/test/repo"
	pkg1 := models.PackageInfo{Name: "express", Ecosystem: "npm"}
	pkg2 := models.PackageInfo{Name: "flask", Ecosystem: "pypi"}
	pkg3 := models.PackageInfo{Name: "lodash", Ecosystem: "npm"}

	output1 := newMockOutput(executiondag.StatusSuccess, "", &url, []models.PackageInfo{pkg1})
	output2 := newMockOutput(executiondag.StatusSuccess, "", &url, []models.PackageInfo{pkg2})
	output3 := newMockOutput(executiondag.StatusSuccess, "", nil, []models.PackageInfo{pkg3})

	input.Merge(output1)
	input.Merge(output2)
	input.Merge(output3)

	// Verify URL is set
	if input.SourceURL == nil || *input.SourceURL != url {
		t.Errorf("Expected URL '%s'", url)
	}

	// Verify all packages accumulated and sorted (npm before pypi)
	if len(input.Packages) != 3 {
		t.Errorf("Expected 3 packages, got %d", len(input.Packages))
	}

	expectedNames := []string{"express", "lodash", "flask"}
	for idx, exp := range expectedNames {
		if input.Packages[idx].Name != exp {
			t.Errorf("Expected package %d to be '%s', got '%s'", idx, exp, input.Packages[idx].Name)
		}
	}
}

func TestInput_Merge_DeduplicatesPackages(t *testing.T) {
	// Test that duplicate packages are not added multiple times
	// This is the bug fix for the issue found in E&O verification
	gitdb := models.PackageInfo{Name: "gitdb", Ecosystem: "pypi"}

	// Start with one package
	input := &Input{
		SourceURL: nil,
		Packages:  []models.PackageInfo{gitdb},
	}

	// Output with same package (like package_detector detects)
	output := newMockOutput(executiondag.StatusSuccess, "", nil, []models.PackageInfo{gitdb})

	input.Merge(output)

	// Should still have only 1 package, not 2
	if len(input.Packages) != 1 {
		t.Errorf("Expected 1 package after deduplication, got %d", len(input.Packages))
	}

	if input.Packages[0].Name != "gitdb" {
		t.Errorf("Expected package 'gitdb', got '%s'", input.Packages[0].Name)
	}
	if input.Packages[0].Ecosystem != "pypi" {
		t.Errorf("Expected ecosystem 'pypi', got '%s'", input.Packages[0].Ecosystem)
	}
}

func TestInput_Merge_DeduplicatesMultiplePackages(t *testing.T) {
	// Test deduplication with multiple packages
	pkg1 := models.PackageInfo{Name: "express", Ecosystem: "npm"}
	pkg2 := models.PackageInfo{Name: "flask", Ecosystem: "pypi"}
	pkg3 := models.PackageInfo{Name: "lodash", Ecosystem: "npm"}

	// Start with two packages
	input := &Input{
		SourceURL: nil,
		Packages:  []models.PackageInfo{pkg1, pkg2},
	}

	// Output with one duplicate and one new package
	output := newMockOutput(executiondag.StatusSuccess, "", nil, []models.PackageInfo{pkg2, pkg3})

	input.Merge(output)

	// Should have 3 packages total, sorted (npm before pypi)
	if len(input.Packages) != 3 {
		t.Errorf("Expected 3 packages after deduplication, got %d", len(input.Packages))
	}

	expectedNames := []string{"express", "lodash", "flask"}
	for idx, exp := range expectedNames {
		if input.Packages[idx].Name != exp {
			t.Errorf("Expected package %d to be '%s', got '%s'", idx, exp, input.Packages[idx].Name)
		}
	}
}

func TestInput_Merge_DeduplicatesDifferentEcosystems(t *testing.T) {
	// Test that packages with same name but different ecosystems are NOT deduplicated
	npmPkg := models.PackageInfo{Name: "request", Ecosystem: "npm"}
	pypiPkg := models.PackageInfo{Name: "request", Ecosystem: "pypi"}

	input := &Input{
		SourceURL: nil,
		Packages:  []models.PackageInfo{npmPkg},
	}

	output := newMockOutput(executiondag.StatusSuccess, "", nil, []models.PackageInfo{pypiPkg})

	input.Merge(output)

	// Should have 2 packages (different ecosystems)
	if len(input.Packages) != 2 {
		t.Errorf("Expected 2 packages (different ecosystems), got %d", len(input.Packages))
	}

	if input.Packages[0].Ecosystem != "npm" {
		t.Errorf("Expected first package ecosystem 'npm', got '%s'", input.Packages[0].Ecosystem)
	}
	if input.Packages[1].Ecosystem != "pypi" {
		t.Errorf("Expected second package ecosystem 'pypi', got '%s'", input.Packages[1].Ecosystem)
	}
}

func TestInput_Merge_DeterministicPackageOrder(t *testing.T) {
	pkgA := models.PackageInfo{Name: "alpha", Ecosystem: "npm"}
	pkgB := models.PackageInfo{Name: "beta", Ecosystem: "npm"}
	pkgC := models.PackageInfo{Name: "gamma", Ecosystem: "pypi"}
	pkgD := models.PackageInfo{Name: "delta", Ecosystem: "maven"}

	orderings := [][]models.PackageInfo{
		{pkgC, pkgA, pkgD, pkgB},
		{pkgD, pkgB, pkgA, pkgC},
		{pkgB, pkgC, pkgD, pkgA},
		{pkgA, pkgB, pkgC, pkgD},
	}

	expected := []models.PackageInfo{
		{Name: "delta", Ecosystem: "maven"},
		{Name: "alpha", Ecosystem: "npm"},
		{Name: "beta", Ecosystem: "npm"},
		{Name: "gamma", Ecosystem: "pypi"},
	}

	for idx, order := range orderings {
		input := &Input{Packages: []models.PackageInfo{}}
		output := newMockOutput(executiondag.StatusSuccess, "", nil, order)
		input.Merge(output)

		if len(input.Packages) != len(expected) {
			t.Fatalf("ordering %d: expected %d packages, got %d", idx, len(expected), len(input.Packages))
		}
		for j, exp := range expected {
			if input.Packages[j] != exp {
				t.Errorf("ordering %d, position %d: expected %v, got %v", idx, j, exp, input.Packages[j])
			}
		}
	}
}

func TestNewPackageInputWithVersion_NoVersion(t *testing.T) {
	input := NewPackageInputWithVersion("npm", "express", nil, "")

	expected := "package/npm/express"
	if input.AnalysisIdentifier != expected {
		t.Errorf("Expected AnalysisIdentifier '%s', got '%s'", expected, input.AnalysisIdentifier)
	}
	if input.Version != nil {
		t.Errorf("Expected Version nil, got '%v'", input.Version)
	}
}

func TestNewPackageInputWithVersion_WithVersion(t *testing.T) {
	version := "4.18.0"
	input := NewPackageInputWithVersion("npm", "express", &version, "")

	expected := "package/npm/express?version=4.18.0"
	if input.AnalysisIdentifier != expected {
		t.Errorf("Expected AnalysisIdentifier '%s', got '%s'", expected, input.AnalysisIdentifier)
	}
	if input.Version == nil {
		t.Fatal("Expected Version to be set")
	}
	if *input.Version != version {
		t.Errorf("Expected Version '%s', got '%s'", version, *input.Version)
	}
}

func TestNewPackageInputWithVersion_EmptyVersion(t *testing.T) {
	version := ""
	input := NewPackageInputWithVersion("npm", "express", &version, "")

	expected := "package/npm/express"
	if input.AnalysisIdentifier != expected {
		t.Errorf("Expected AnalysisIdentifier '%s', got '%s'", expected, input.AnalysisIdentifier)
	}
	if input.Version == nil || *input.Version != "" {
		t.Errorf("Expected Version to be empty string pointer, got %v", input.Version)
	}
}

func TestNewPackageInputWithVersion_WithPlusCharacter(t *testing.T) {
	version := "1.0.0+build123"
	input := NewPackageInputWithVersion("npm", "express", &version, "")

	// + should be URL-encoded as %2B in the analysis ID
	expected := "package/npm/express?version=1.0.0%2Bbuild123"
	if input.AnalysisIdentifier != expected {
		t.Errorf("Expected AnalysisIdentifier '%s', got '%s'", expected, input.AnalysisIdentifier)
	}
}

func TestNewPackageInputWithVersion_WithVersionAndOverrides(t *testing.T) {
	version := "4.18.0"
	input := NewPackageInputWithVersion("npm", "express", &version, "abc123")

	expected := "package/npm/express?version=4.18.0&overrides=abc123"
	if input.AnalysisIdentifier != expected {
		t.Errorf("Expected AnalysisIdentifier '%s', got '%s'", expected, input.AnalysisIdentifier)
	}
}

func TestNewPackageInputWithVersion_OverridesOnly(t *testing.T) {
	input := NewPackageInputWithVersion("npm", "express", nil, "abc123")

	expected := "package/npm/express?overrides=abc123"
	if input.AnalysisIdentifier != expected {
		t.Errorf("Expected AnalysisIdentifier '%s', got '%s'", expected, input.AnalysisIdentifier)
	}
}
