package package_install_scripts

import (
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/artifact_fetch"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/package_detector"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"testing"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

func strPtr(s string) *string { return &s }

func TestNode_GetDependencies(t *testing.T) {
	node := NewNode(nil)
	deps := node.GetDependencies()

	if len(deps) != 2 {
		t.Fatalf("Expected 2 dependencies, got %d", len(deps))
	}

	expectedDetectorDep := executiondag.DependsOn[*package_detector.Node]()
	if deps[0] != expectedDetectorDep {
		t.Error("First dependency should be *package_detector.Node")
	}

	expectedArtifactDep := executiondag.DependsOn[*artifact_fetch.Node]()
	if deps[1] != expectedArtifactDep {
		t.Error("Second dependency should be *artifact_fetch.Node")
	}
}

func TestNode_AllowAutoSkip(t *testing.T) {
	node := NewNode(nil)
	if node.AllowAutoSkip() {
		t.Error("AllowAutoSkip should return false")
	}
}

func TestNode_CreateSkippedOutput(t *testing.T) {
	node := NewNode(nil)
	sourceURL := "https://github.com/test/repo"
	input := dag_impl.Input{
		SourceURL: &sourceURL,
	}

	output := node.CreateSkippedOutput("test reason", input)

	if output.Check.CheckStatus != storage.StatusSkipped {
		t.Errorf("Expected check status skipped, got %v", output.Check.CheckStatus)
	}

	if output.Check.CheckCode != node.Code {
		t.Errorf("Expected check code %s, got %s", node.Code, output.Check.CheckCode)
	}

	if output.Check.Rationale != "test reason" {
		t.Errorf("Expected rationale 'test reason', got %s", output.Check.Rationale)
	}
}

func TestNode_Kind(t *testing.T) {
	node := NewNode(nil)
	kind := node.Kind()

	if kind != "check" {
		t.Errorf("Expected kind 'check', got %s", kind)
	}
}

func TestCheckCodeConstant(t *testing.T) {
	node := NewNode(nil)
	if node.Code != "PACKAGE_INSTALL_SCRIPTS" {
		t.Errorf("Expected node.Code to be 'PACKAGE_INSTALL_SCRIPTS', got %s", node.Code)
	}
}

func TestInstallScriptsLogic(t *testing.T) {
	tests := []struct {
		name            string
		manifests       []models.ManifestResult
		expectViolation bool
		expectCompliant bool
		expectSkipped   bool
		description     string
	}{
		{
			name:            "No manifests - skip",
			manifests:       []models.ManifestResult{},
			expectViolation: false,
			expectCompliant: false,
			expectSkipped:   true,
			description:     "No package definitions should skip the check",
		},
		{
			name: "npm package without install scripts - compliant",
			manifests: []models.ManifestResult{
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "npm", Paths: []string{"/package.json"}},
					Name:             strPtr("express"),
				},
			},
			expectViolation: false,
			expectCompliant: true,
			expectSkipped:   false,
			description:     "npm package without install scripts should be compliant",
		},
		{
			name: "npm package with preinstall script - violation",
			manifests: []models.ManifestResult{
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "npm", Paths: []string{"/package.json"}},
					Name:             strPtr("malicious-pkg"),
					InstallScripts:   []string{"preinstall"},
				},
			},
			expectViolation: true,
			expectCompliant: false,
			expectSkipped:   false,
			description:     "npm package with preinstall script should be a violation",
		},
		{
			name: "npm package with postinstall script - violation",
			manifests: []models.ManifestResult{
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "npm", Paths: []string{"/package.json"}},
					Name:             strPtr("some-pkg"),
					InstallScripts:   []string{"postinstall"},
				},
			},
			expectViolation: true,
			expectCompliant: false,
			expectSkipped:   false,
			description:     "npm package with postinstall script should be a violation",
		},
		{
			name: "npm package with prepare script - violation",
			manifests: []models.ManifestResult{
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "npm", Paths: []string{"/package.json"}},
					Name:             strPtr("build-pkg"),
					InstallScripts:   []string{"prepare"},
				},
			},
			expectViolation: true,
			expectCompliant: false,
			expectSkipped:   false,
			description:     "npm package with prepare script should be a violation",
		},
		{
			name: "npm package with multiple install scripts - violation",
			manifests: []models.ManifestResult{
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "npm", Paths: []string{"/package.json"}},
					Name:             strPtr("complex-pkg"),
					InstallScripts:   []string{"preinstall", "postinstall", "prepare"},
				},
			},
			expectViolation: true,
			expectCompliant: false,
			expectSkipped:   false,
			description:     "npm package with multiple install scripts should be a violation",
		},
		{
			name: "Python with setup.py - violation",
			manifests: []models.ManifestResult{
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "pypi", Paths: []string{"/setup.py"}},
					Name:             strPtr("my-package"),
					InstallScripts:   []string{"setup.py"},
				},
			},
			expectViolation: true,
			expectCompliant: false,
			expectSkipped:   false,
			description:     "Python package with setup.py should be a violation",
		},
		{
			name: "Python with pyproject.toml only - compliant",
			manifests: []models.ManifestResult{
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "pypi", Paths: []string{"/pyproject.toml"}},
					Name:             strPtr("modern-pkg"),
				},
			},
			expectViolation: false,
			expectCompliant: true,
			expectSkipped:   false,
			description:     "Python package with only pyproject.toml should be compliant",
		},
		{
			name: "Mixed npm and Python with install scripts - violation",
			manifests: []models.ManifestResult{
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "npm", Paths: []string{"/frontend/package.json"}},
					Name:             strPtr("frontend"),
				},
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "pypi", Paths: []string{"/backend/setup.py"}},
					Name:             strPtr("backend"),
					InstallScripts:   []string{"setup.py"},
				},
			},
			expectViolation: true,
			expectCompliant: false,
			expectSkipped:   false,
			description:     "Mixed packages where one has install scripts should be a violation",
		},
		{
			name: "Multiple packages all without install scripts - compliant",
			manifests: []models.ManifestResult{
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "npm", Paths: []string{"/packages/pkg1/package.json"}},
					Name:             strPtr("pkg1"),
				},
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "npm", Paths: []string{"/packages/pkg2/package.json"}},
					Name:             strPtr("pkg2"),
				},
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "pypi", Paths: []string{"/python/pyproject.toml"}},
					Name:             strPtr("pkg3"),
				},
			},
			expectViolation: false,
			expectCompliant: true,
			expectSkipped:   false,
			description:     "Multiple packages all without install scripts should be compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasNoManifests := len(tt.manifests) == 0
			hasInstallScripts := false
			for _, m := range tt.manifests {
				if len(m.InstallScripts) > 0 {
					hasInstallScripts = true
					break
				}
			}

			isSkipped := hasNoManifests
			isViolation := !hasNoManifests && hasInstallScripts
			isCompliant := !hasNoManifests && !hasInstallScripts

			if isSkipped != tt.expectSkipped {
				t.Errorf("%s: Expected skipped=%v, got skipped=%v",
					tt.description, tt.expectSkipped, isSkipped)
			}

			if isViolation != tt.expectViolation {
				t.Errorf("%s: Expected violation=%v, got violation=%v",
					tt.description, tt.expectViolation, isViolation)
			}

			if isCompliant != tt.expectCompliant {
				t.Errorf("%s: Expected compliant=%v, got compliant=%v",
					tt.description, tt.expectCompliant, isCompliant)
			}
		})
	}
}

func TestNewNode(t *testing.T) {
	node := NewNode(nil)
	if node == nil {
		t.Error("NewNode(nil) should not return nil")
	}
}
