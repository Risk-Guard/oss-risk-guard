package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/helpers"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"
	"github.com/Risk-Guard/oss-risk-guard/src/overrides"
	"github.com/Risk-Guard/oss-risk-guard/src/runpath"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"

	"go.uber.org/zap"
)

// CheckOutputProvider is an interface for types that wrap checks.Output
// Each check's unique output type should implement this interface
type CheckOutputProvider interface {
	GetCheckOutput() *Output
}

const MaxEvidenceItems = 5

type Output struct {
	dag_impl.BaseOutput `json:",inline"`
	Check               storage.Check `json:",inline"`
	metadata            map[string]any
}

func NewCompliantOutput(checkCode string, rationale string, input dag_impl.Input) *Output {
	return &Output{
		BaseOutput: dag_impl.NewBaseOutput(executiondag.StatusSuccess, "", input),
		Check: storage.Check{
			CheckCode:   checkCode,
			CheckStatus: storage.StatusCompliant,
			Rationale:   rationale,
			Evidence:    nil,
			Thresholds:  map[string]any{},
		},
	}
}

func NewViolationOutput(checkCode string, rationale string, evidence []string, input dag_impl.Input) *Output {
	return &Output{
		BaseOutput: dag_impl.NewBaseOutput(executiondag.StatusSuccess, "", input),
		Check: storage.Check{
			CheckCode:   checkCode,
			CheckStatus: storage.StatusViolation,
			Rationale:   rationale,
			Evidence:    evidence,
			Thresholds:  map[string]any{},
		},
	}
}

func NewSkippedOutput(checkCode string, reason string, input dag_impl.Input) *Output {
	return &Output{
		BaseOutput: dag_impl.NewBaseOutput(executiondag.StatusSuccess, "", input),
		Check: storage.Check{
			CheckCode:   checkCode,
			CheckStatus: storage.StatusSkipped,
			Rationale:   reason,
			Evidence:    nil,
			Thresholds:  map[string]any{},
		},
	}
}

// WithThresholds sets the thresholds and returns the output for chaining
func (o *Output) WithThresholds(thresholds map[string]any) *Output {
	o.Check.Thresholds = thresholds
	return o
}

// WithEvidencef appends a formatted evidence string and returns the output for chaining
func (o *Output) WithEvidence(evidence string) *Output {
	o.Check.Evidence = append(o.Check.Evidence, evidence)
	return o
}

// WithEvidencef appends a formatted evidence string and returns the output for chaining
func (o *Output) WithEvidencef(format string, args ...any) *Output {
	o.Check.Evidence = append(o.Check.Evidence, fmt.Sprintf(format, args...))
	return o
}

func (o *Output) Metadata() map[string]any {
	return o.metadata
}

func (o *Output) WithMetadata(key string, value any) *Output {
	if o.metadata == nil {
		o.metadata = make(map[string]any)
	}
	o.metadata[key] = value
	return o
}

func (o *Output) Write(ctx context.Context) error {
	return nil
}

func outputFilepath(ctx context.Context, input dag_impl.Input) (string, error) {
	if p := runpath.GetChecksOutputPath(ctx); p != "" {
		return p, nil
	}
	return filepath.Join(runpath.GetOutputDir(ctx), input.BasePath(), "checks.yml"), nil
}

func WriteCheckOutputs(ctx context.Context, input dag_impl.Input, checkOutputs []Output) error {
	log := ctxutil.GetLogger(ctx)

	checksPath, err := outputFilepath(ctx, input)
	if err != nil {
		return fmt.Errorf("determining checks output path: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(checksPath), 0o750); err != nil {
		return fmt.Errorf("creating checks directory: %w", err)
	}

	// Wrap checks with metadata including timestamp
	analyzedAt := time.Now()
	checks := []storage.Check{}
	for _, co := range checkOutputs {
		checks = append(checks, co.Check)
	}

	doc := storage.ChecksResult{
		AnalysisIdentifier: input.AnalysisIdentifier,
		AnalyzedAt:         &analyzedAt,
		Checks:             checks,
	}
	if store := overrides.GetStore(ctx); store != nil {
		doc.AppliedOverrides = store.GetApplied()
	}

	if err := helpers.WriteYAML(checksPath, doc); err != nil {
		return fmt.Errorf("writing checks YAML: %w", err)
	}

	log.Debug("wrote checks aggregation",
		zap.String("path", checksPath),
		zap.Int("check_count", len(checkOutputs)))

	if writer := GetChecksWriter(ctx); writer != nil {
		if err := writer(ctx, doc, input); err != nil {
			return fmt.Errorf("writing checks to backend: %w", err)
		}
	}

	return nil
}

func WriteSummary(ctx context.Context, input dag_impl.Input, summary any) error {
	log := ctxutil.GetLogger(ctx)

	summaryPath := summaryFilepath(ctx, input)

	if err := os.MkdirAll(filepath.Dir(summaryPath), 0o750); err != nil {
		return fmt.Errorf("creating summary directory: %w", err)
	}

	if err := helpers.WriteYAML(summaryPath, summary); err != nil {
		return fmt.Errorf("writing summary YAML: %w", err)
	}

	log.Debug("wrote analysis summary",
		zap.String("path", summaryPath))

	return nil
}

func summaryFilepath(ctx context.Context, input dag_impl.Input) string {
	outputDir := runpath.GetOutputDir(ctx)
	return filepath.Join(outputDir, input.BasePath(), "summary.yml")
}
