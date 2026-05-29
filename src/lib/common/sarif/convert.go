package sarif

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/policy"
	"github.com/Risk-Guard/oss-risk-guard/src/version"

	dag_builder "github.com/Risk-Guard/oss-risk-guard/src/dag-builder"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

const InformationURI = "https://github.com/Risk-Guard/risk-guard"

// RepoRootURI is the artifact URI used to anchor results that have no
// file-specific location (repo-wide source findings, aggregate package checks,
// synthetic audit-error results). GitHub Code Scanning rejects any result whose
// location lacks a physicalLocation, so every result must resolve to at least
// this.
const RepoRootURI = "."

func FromEvaluationResult(result *policy.EvaluationResult, checks []dag_builder.CheckInfo) (*sarif.Report, error) {
	report, err := sarif.New(sarif.Version210, true)
	if err != nil {
		return nil, err
	}

	run := sarif.NewRunWithInformationURI("risk-guard", InformationURI)
	run.Tool.Driver.WithVersion(version.Version)
	run.Tool.Driver.WithSemanticVersion(version.Version)

	addRules(run, checks)

	for _, finding := range result.Findings {
		addResult(run, finding)
	}

	report.AddRun(run)
	return report, nil
}

func addRules(run *sarif.Run, metadata []dag_builder.CheckInfo) {
	for _, info := range metadata {
		if info.Deprecated {
			continue
		}

		rule := run.AddRule(info.Code)
		rule.WithDescription(info.Description)
		rule.WithShortDescription(sarif.NewMultiformatMessageString(info.Description))

		if len(info.Categories) > 0 {
			tags := make([]string, 0, len(info.Categories))
			for cat := range info.Categories {
				tags = append(tags, string(cat))
			}
			sort.Strings(tags)
			rule.WithProperties(sarif.Properties{"tags": tags})
		}
	}
}

func addResult(run *sarif.Run, f policy.Finding) {
	level := mapFindingKindToLevel(f.Kind)
	message := buildMessage(f)

	result := run.CreateResultForRule(f.Check)
	result.WithLevel(level)
	result.WithMessage(sarif.NewTextMessage(message))

	loc := sarif.NewLocation()

	name := normalizeLogicalName(f.Package)
	logicalLoc := &sarif.LogicalLocation{
		Name: &name,
		Kind: ptr("package"),
	}
	if len(f.DependencyPath) > 0 {
		fqn := buildDependencyPathString(f.DependencyPath)
		logicalLoc.FullyQualifiedName = &fqn
	}
	loc.WithLogicalLocations([]*sarif.LogicalLocation{logicalLoc})

	if f.RootLocation != nil && f.RootLocation.File != nil {
		physLoc := sarif.NewPhysicalLocation()
		physLoc.WithArtifactLocation(sarif.NewSimpleArtifactLocation(*f.RootLocation.File))
		if f.RootLocation.LineNumber != nil {
			physLoc.WithRegion(sarif.NewSimpleRegion(*f.RootLocation.LineNumber, *f.RootLocation.LineNumber))
		}
		loc.WithPhysicalLocation(physLoc)
	}

	result.WithLocations([]*sarif.Location{loc})
}

func mapFindingKindToLevel(kind policy.FindingKind) string {
	switch kind {
	case policy.FindingBlocking:
		return "error"
	case policy.FindingWarning:
		return "warning"
	case policy.FindingExpired:
		return "error"
	case policy.FindingAcknowledged:
		return "note"
	case policy.FindingIgnored:
		return "none"
	default:
		return "warning"
	}
}

func buildMessage(f policy.Finding) string {
	var sb strings.Builder
	sb.WriteString(f.Rationale)

	if len(f.Evidence) > 0 {
		sb.WriteString("\n\nEvidence:")
		for _, e := range f.Evidence {
			sb.WriteString("\n- ")
			sb.WriteString(e)
		}
	}

	if f.Note != "" {
		sb.WriteString("\n\nNote: ")
		sb.WriteString(f.Note)
	}

	return sb.String()
}

func buildDependencyPathString(path []string) string {
	return strings.Join(path, " -> ")
}

func ptr(s string) *string {
	return &s
}

// normalizeLogicalName cleans up the logical-location name derived from an
// analysis identifier. A local-source scan keys its analysis on the absolute
// filesystem path it was given, producing names like
// "source//home/runner/work/public-test/public-test" (the "source/" prefix glued
// onto an absolute path). Those are collapsed to "source/<repo-dir>". Remote
// source IDs ("source/github.com/owner/repo") and package IDs
// ("package/pypi/pytest?version=9.0.2") are returned unchanged. The "source/"
// prefix is always preserved because downstream key mapping
// (entityKeyForResult) relies on it.
func normalizeLogicalName(pkg string) string {
	rest, ok := strings.CutPrefix(pkg, "source/")
	if !ok {
		return pkg
	}
	// Drop any query suffix (e.g. "?commit=abc") before inspecting the path.
	if idx := strings.IndexByte(rest, '?'); idx >= 0 {
		rest = rest[:idx]
	}
	// Only an absolute filesystem path needs collapsing; remote URLs don't
	// start with "/".
	if !strings.HasPrefix(rest, "/") {
		return pkg
	}
	return "source/" + filepath.Base(rest)
}

// EnsurePhysicalLocations guarantees every result in every run has a
// physicalLocation, as required by GitHub Code Scanning. Results that already
// carry one (on any of their locations) are left untouched; bare results are
// anchored at the repository root (RepoRootURI) with no region. This is the
// single invariant enforcer for the whole report, so it also covers synthetic
// runs (e.g. audit-error failure runs) and any future result emitter.
func EnsurePhysicalLocations(report *sarif.Report) {
	if report == nil {
		return
	}
	for _, run := range report.Runs {
		if run == nil {
			continue
		}
		for _, res := range run.Results {
			if res == nil || hasPhysicalLocation(res) {
				continue
			}
			if len(res.Locations) == 0 {
				res.Locations = []*sarif.Location{sarif.NewLocation()}
			}
			res.Locations[0].WithPhysicalLocation(
				sarif.NewPhysicalLocation().
					WithArtifactLocation(sarif.NewSimpleArtifactLocation(RepoRootURI)),
			)
		}
	}
}

func hasPhysicalLocation(res *sarif.Result) bool {
	for _, loc := range res.Locations {
		if loc != nil && loc.PhysicalLocation != nil {
			return true
		}
	}
	return false
}
