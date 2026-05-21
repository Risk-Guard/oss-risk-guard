package source_no_ci

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_clone_content"
	"github.com/Risk-Guard/oss-risk-guard/src/git"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

func TestNode_GetDependencies(t *testing.T) {
	node := NewNode()
	deps := node.GetDependencies()

	if len(deps) != 1 {
		t.Fatalf("Expected 1 dependency, got %d", len(deps))
	}

	expectedDep := executiondag.DependsOn[*git_clone_content.Node]()
	if deps[0] != expectedDep {
		t.Error("Node should depend on *git_clone_content.Node")
	}
}

func TestNode_Kind(t *testing.T) {
	node := NewNode()
	kind := node.Kind()

	if kind != "check" {
		t.Errorf("Expected kind 'check', got %s", kind)
	}
}

func TestCheckCodeConstant(t *testing.T) {
	node := NewNode()
	if node.Code != "SOURCE_NO_CI" {
		t.Errorf("Expected CheckCode to be 'SOURCE_NO_CI', got %s", node.Code)
	}
}

func TestCIDetectionLogic(t *testing.T) {
	tests := []struct {
		name            string
		files           []string
		dirs            []string
		expectViolation bool
	}{
		{
			name:            "No CI files - violation",
			files:           nil,
			expectViolation: true,
		},
		{
			name:            "GitHub Actions with yml - compliant",
			dirs:            []string{".github/workflows"},
			files:           []string{".github/workflows/build.yml"},
			expectViolation: false,
		},
		{
			name:            "GitHub Actions with yaml - compliant",
			dirs:            []string{".github/workflows"},
			files:           []string{".github/workflows/ci.yaml"},
			expectViolation: false,
		},
		{
			name:            "GitHub Actions dir empty - violation",
			dirs:            []string{".github/workflows"},
			expectViolation: true,
		},
		{
			name:            "GitLab CI yml - compliant",
			files:           []string{".gitlab-ci.yml"},
			expectViolation: false,
		},
		{
			name:            "GitLab CI yaml - compliant",
			files:           []string{".gitlab-ci.yaml"},
			expectViolation: false,
		},
		{
			name:            "CircleCI yml - compliant",
			files:           []string{".circleci/config.yml"},
			expectViolation: false,
		},
		{
			name:            "CircleCI yaml - compliant",
			files:           []string{".circleci/config.yaml"},
			expectViolation: false,
		},
		{
			name:            "Travis CI - compliant",
			files:           []string{".travis.yml"},
			expectViolation: false,
		},
		{
			name:            "Jenkins - compliant",
			files:           []string{"Jenkinsfile"},
			expectViolation: false,
		},
		{
			name:            "Azure Pipelines - compliant",
			files:           []string{"azure-pipelines.yml"},
			expectViolation: false,
		},
		{
			name:            "Bitbucket Pipelines - compliant",
			files:           []string{"bitbucket-pipelines.yml"},
			expectViolation: false,
		},
		{
			name:            "AppVeyor - compliant",
			files:           []string{"appveyor.yml"},
			expectViolation: false,
		},
		{
			name:            "Unrelated files only - violation",
			files:           []string{"README.md", "Makefile"},
			expectViolation: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			for _, d := range tt.dirs {
				if err := os.MkdirAll(filepath.Join(tmpDir, d), 0o750); err != nil {
					t.Fatalf("creating directory: %v", err)
				}
			}

			for _, f := range tt.files {
				fullPath := filepath.Join(tmpDir, f)
				if err := os.MkdirAll(filepath.Dir(fullPath), 0o750); err != nil {
					t.Fatalf("creating directory: %v", err)
				}
				if err := os.WriteFile(fullPath, []byte("ci config"), 0o644); err != nil {
					t.Fatalf("creating file: %v", err)
				}
			}

			found := false
			for _, provider := range git.CIProviders {
				ok, _, err := detectProvider(tmpDir, provider)
				if err != nil {
					t.Fatalf("detectProvider error: %v", err)
				}
				if ok {
					found = true
					break
				}
			}

			isViolation := !found
			if isViolation != tt.expectViolation {
				t.Errorf("Expected violation=%v, got violation=%v", tt.expectViolation, isViolation)
			}
		})
	}
}

func TestNewNode(t *testing.T) {
	node := NewNode()
	if node == nil {
		t.Error("NewNode() should not return nil")
	}
}
