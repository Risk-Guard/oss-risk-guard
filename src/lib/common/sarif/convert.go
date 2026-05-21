package sarif

import (
	"sort"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/policy"
	"github.com/Risk-Guard/oss-risk-guard/src/version"

	dag_builder "github.com/Risk-Guard/oss-risk-guard/src/dag-builder"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

const InformationURI = "https://github.com/Risk-Guard/risk-guard"

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

	logicalLoc := &sarif.LogicalLocation{
		Name: &f.Package,
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
