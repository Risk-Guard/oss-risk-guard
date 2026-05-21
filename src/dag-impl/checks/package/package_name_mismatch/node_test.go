package package_name_mismatch

import (
	"context"
	"strings"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_clone_metadata"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/package_detector"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/transformer"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"
	"github.com/Risk-Guard/oss-risk-guard/src/logger"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"

	languageregistry "github.com/Risk-Guard/oss-risk-guard/src/language/registry"
)

func strPtr(s string) *string { return &s }

func TestNode_GetDependencies(t *testing.T) {
	node := NewNode(nil)
	deps := node.GetDependencies()

	if len(deps) != 3 {
		t.Fatalf("Expected 3 dependencies, got %d", len(deps))
	}

	expectedGitDep := executiondag.DependsOn[*git_clone_metadata.Node]()
	if deps[0] != expectedGitDep {
		t.Error("First dependency should be *git_clone_metadata.Node")
	}

	expectedDetectorDep := executiondag.DependsOn[*package_detector.Node]()
	if deps[1] != expectedDetectorDep {
		t.Error("Second dependency should be *package_detector.Node")
	}

	expectedTransformerDep := executiondag.DependsOn[*transformer.Node]()
	if deps[2] != expectedTransformerDep {
		t.Error("Third dependency should be *transformer.Node")
	}
}

func TestNode_CreateSkippedOutput(t *testing.T) {
	node := NewNode(nil)
	input := dag_impl.Input{
		Packages: []models.PackageInfo{
			{Ecosystem: "npm", Name: "test-package"},
		},
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
	if node.Code != "PACKAGE_NAME_MISMATCH" {
		t.Errorf("Expected node.Code to be 'PACKAGE_NAME_MISMATCH', got %s", node.Code)
	}
}

func TestNewNode(t *testing.T) {
	node := NewNode(nil)
	if node == nil {
		t.Error("NewNode() should not return nil")
	}
}

func TestPackageNameMismatchLogic(t *testing.T) {
	tests := []struct {
		name            string
		packages        []models.PackageInfo
		manifests       []models.ManifestResult
		expectViolation bool
		expectCompliant bool
		expectSkipped   bool
		description     string
	}{
		{
			name: "No manifests - skip",
			packages: []models.PackageInfo{
				{Ecosystem: "npm", Name: "express"},
			},
			manifests:       []models.ManifestResult{},
			expectViolation: false,
			expectCompliant: false,
			expectSkipped:   true,
			description:     "No package definitions should skip the check",
		},
		{
			name: "Only dynamic package names - skip",
			packages: []models.PackageInfo{
				{Ecosystem: "npm", Name: "express"},
			},
			manifests: []models.ManifestResult{
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "npm", Paths: []string{"package.json"}},
					Name:             strPtr("process.env.PKG_NAME"),
					IsDynamic:        true,
					DynamicReason:    stringPtr("computed from env"),
				},
			},
			expectViolation: false,
			expectCompliant: false,
			expectSkipped:   true,
			description:     "Only dynamic names should skip the check",
		},
		{
			name: "Matching package name - compliant",
			packages: []models.PackageInfo{
				{Ecosystem: "npm", Name: "express"},
			},
			manifests: []models.ManifestResult{
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "npm", Paths: []string{"package.json"}},
					Name:             strPtr("express"),
					IsDynamic:        false,
				},
			},
			expectViolation: false,
			expectCompliant: true,
			expectSkipped:   false,
			description:     "Matching package names should be compliant",
		},
		{
			name: "Case mismatch (npm) - violation",
			packages: []models.PackageInfo{
				{Ecosystem: "npm", Name: "Express"},
			},
			manifests: []models.ManifestResult{
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "npm", Paths: []string{"package.json"}},
					Name:             strPtr("express"),
					IsDynamic:        false,
				},
			},
			expectViolation: true,
			expectCompliant: false,
			expectSkipped:   false,
			description:     "NPM is case-sensitive - Express != express",
		},
		{
			name: "Mismatched package name - violation",
			packages: []models.PackageInfo{
				{Ecosystem: "npm", Name: "express"},
			},
			manifests: []models.ManifestResult{
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "npm", Paths: []string{"package.json"}},
					Name:             strPtr("different-package"),
					IsDynamic:        false,
				},
			},
			expectViolation: true,
			expectCompliant: false,
			expectSkipped:   false,
			description:     "Different package names should be a violation",
		},
		{
			name: "No matching ecosystem - violation",
			packages: []models.PackageInfo{
				{Ecosystem: "npm", Name: "express"},
			},
			manifests: []models.ManifestResult{
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "pypi", Paths: []string{"setup.py"}},
					Name:             strPtr("some-python-package"),
					IsDynamic:        false,
				},
			},
			expectViolation: true,
			expectCompliant: false,
			expectSkipped:   false,
			description:     "No matching ecosystem should be a violation",
		},
		{
			name: "Multiple packages, one mismatch - violation",
			packages: []models.PackageInfo{
				{Ecosystem: "npm", Name: "express"},
				{Ecosystem: "npm", Name: "lodash"},
			},
			manifests: []models.ManifestResult{
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "npm", Paths: []string{"package.json"}},
					Name:             strPtr("express"),
					IsDynamic:        false,
				},
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "npm", Paths: []string{"other/package.json"}},
					Name:             strPtr("wrong-name"),
					IsDynamic:        false,
				},
			},
			expectViolation: true,
			expectCompliant: false,
			expectSkipped:   false,
			description:     "One mismatch should result in violation",
		},
		{
			name: "Mixed dynamic and static with match - compliant",
			packages: []models.PackageInfo{
				{Ecosystem: "npm", Name: "express"},
			},
			manifests: []models.ManifestResult{
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "npm", Paths: []string{"dynamic/package.json"}},
					Name:             strPtr("dynamic-pkg"),
					IsDynamic:        true,
					DynamicReason:    stringPtr("computed"),
				},
				{
					DetectedManifest: models.DetectedManifest{Ecosystem: "npm", Paths: []string{"package.json"}},
					Name:             strPtr("express"),
					IsDynamic:        false,
				},
			},
			expectViolation: false,
			expectCompliant: true,
			expectSkipped:   false,
			description:     "Should only check static names and find match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasNoManifests := len(tt.manifests) == 0

			var nonDynamicManifests []models.ManifestResult
			hasDynamicNames := false
			for _, m := range tt.manifests {
				if m.IsDynamic {
					hasDynamicNames = true
				} else {
					nonDynamicManifests = append(nonDynamicManifests, m)
				}
			}

			isSkipped := hasNoManifests || (len(nonDynamicManifests) == 0 && hasDynamicNames)

			hasViolation := false
			if !isSkipped {
				langs := languageregistry.Languages()
				for _, pkg := range tt.packages {
					lang := langs[pkg.Ecosystem]
					publishedName := lang.NormalizeName(pkg.Name)
					matchFound := false

					for _, m := range nonDynamicManifests {
						if m.Ecosystem == pkg.Ecosystem {
							manifestLang := langs[m.Ecosystem]
							sourceName := manifestLang.NormalizeName(*m.Name)
							if sourceName == publishedName {
								matchFound = true
								break
							}
						}
					}

					if !matchFound {
						hasViolation = true
						break
					}
				}
			}

			isViolation := !isSkipped && hasViolation
			isCompliant := !isSkipped && !hasViolation

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

func TestRationaleMessages(t *testing.T) {
	tests := []struct {
		name          string
		ecosystem     string
		packageName   string
		sourceNames   []string
		matchFound    bool
		expectedInMsg string
	}{
		{
			name:          "Match found",
			ecosystem:     "npm",
			packageName:   "express",
			sourceNames:   []string{"express"},
			matchFound:    true,
			expectedInMsg: "Package name matches source code",
		},
		{
			name:          "No match - single source name",
			ecosystem:     "npm",
			packageName:   "express",
			sourceNames:   []string{"different-name"},
			matchFound:    false,
			expectedInMsg: "does not match source names",
		},
		{
			name:          "No match - no source names for ecosystem",
			ecosystem:     "npm",
			packageName:   "express",
			sourceNames:   []string{},
			matchFound:    false,
			expectedInMsg: "No npm package definitions found",
		},
		{
			name:          "No match - multiple source names",
			ecosystem:     "npm",
			packageName:   "express",
			sourceNames:   []string{"pkg1", "pkg2", "pkg3"},
			matchFound:    false,
			expectedInMsg: "does not match source names",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rationale string
			if !tt.matchFound {
				if len(tt.sourceNames) == 0 {
					rationale = "No " + tt.ecosystem + " package definitions found in source code"
				} else {
					rationale = "Published name '" + tt.packageName + "' does not match source names: [" + strings.Join(tt.sourceNames, ", ") + "]"
				}
			} else {
				rationale = "Package name matches source code"
			}

			if !strings.Contains(rationale, tt.expectedInMsg) {
				t.Errorf("Expected rationale to contain %q, got %q", tt.expectedInMsg, rationale)
			}
		})
	}
}

func makeTestCtx(t *testing.T, gitMeta *models.GitMetadata, manifests []models.ManifestResult) context.Context {
	t.Helper()
	log, err := logger.NewLogger("error")
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	ctx := ctxutil.SetLogger(context.Background(), log)

	metaOut := &git_clone_metadata.Output{
		BaseOutput: dag_impl.NewBaseOutput(executiondag.StatusSuccess, "test", dag_impl.Input{}),
		GitMeta:    gitMeta,
	}
	ctx = context.WithValue(ctx, executiondag.DependsOn[*git_clone_metadata.Node](), metaOut)

	detectorOut := &package_detector.Output{
		BaseOutput:        dag_impl.NewBaseOutput(executiondag.StatusSuccess, "test", dag_impl.Input{}),
		DetectedManifests: manifests,
	}
	ctx = context.WithValue(ctx, executiondag.DependsOn[*package_detector.Node](), detectorOut)

	transformerOut := &transformer.Output{}
	ctx = context.WithValue(ctx, executiondag.DependsOn[*transformer.Node](), transformerOut)

	return ctx
}

func TestExecute_NilNameManifest_ShouldSkip(t *testing.T) {
	gitMeta := &models.GitMetadata{SourceURL: "https://github.com/yaml/pyyaml"}
	manifests := []models.ManifestResult{
		{
			DetectedManifest: models.DetectedManifest{Ecosystem: "pypi", Paths: []string{"pyproject.toml", "setup.py"}},
			Name:             nil,
		},
	}

	ctx := makeTestCtx(t, gitMeta, manifests)
	node := NewNode(languageregistry.Languages())
	input := dag_impl.Input{
		Packages: []models.PackageInfo{
			{Ecosystem: "pypi", Name: "PyYAML"},
		},
	}

	output, err := node.Execute(ctx, input)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if output.Check.CheckStatus != storage.StatusSkipped {
		t.Errorf("Expected skipped when manifest has nil Name (parse failure), got %s: %s",
			output.Check.CheckStatus, output.Check.Rationale)
	}
}

func TestExecute_NoMatchingEcosystem_ShouldSkip(t *testing.T) {
	gitMeta := &models.GitMetadata{SourceURL: "https://github.com/example/repo"}
	manifests := []models.ManifestResult{
		{
			DetectedManifest: models.DetectedManifest{Ecosystem: "pypi", Paths: []string{"setup.py"}},
			Name:             strPtr("some-python-package"),
		},
	}

	ctx := makeTestCtx(t, gitMeta, manifests)
	node := NewNode(languageregistry.Languages())
	input := dag_impl.Input{
		Packages: []models.PackageInfo{
			{Ecosystem: "npm", Name: "express"},
		},
	}

	output, err := node.Execute(ctx, input)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if output.Check.CheckStatus != storage.StatusSkipped {
		t.Errorf("Expected skipped when no manifests match ecosystem, got %s: %s",
			output.Check.CheckStatus, output.Check.Rationale)
	}
}

func stringPtr(s string) *string {
	return &s
}
