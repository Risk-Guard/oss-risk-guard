package transformer

import (
	"fmt"

	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"github.com/Risk-Guard/oss-risk-guard/src/overrides"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

type RejectedSourceURL struct {
	Ecosystem    string `json:"ecosystem"`
	PackageName  string `json:"package_name"`
	InvalidURL   string `json:"invalid_url"`
	RejectReason string `json:"reject_reason"`
}

// PackageOutput represents the transformed metadata for a single package.
type PackageOutput struct {
	Ecosystem string                  `json:"ecosystem"`
	Name      string                  `json:"name"`
	Metadata  *models.PackageMetadata `json:"metadata"`
}

// Output is the output of the TransformerNode.
// It contains the status and parsed package metadata for all transformed packages.
type Output struct {
	dag_impl.BaseOutput `json:",inline"`

	// Outputs contains the transformed package metadata for each package.
	Outputs []PackageOutput `json:"outputs"`

	// RejectedSourceURLs contains source URLs that were rejected during validation.
	// These are surfaced as security check violations.
	RejectedSourceURLs []RejectedSourceURL `json:"rejected_source_urls"`
}

// getSingleSourceURL extracts and validates the source URL from package outputs.
// Returns error if packages have conflicting source URLs.
func getSingleSourceURL(outputs []PackageOutput) (*string, error) {
	var sourceURL *string

	for _, output := range outputs {
		if output.Metadata == nil || output.Metadata.SourceURL == nil || *output.Metadata.SourceURL == "" {
			continue
		}

		pkgSourceURL := output.Metadata.SourceURL
		if sourceURL == nil {
			sourceURL = pkgSourceURL
		} else if *sourceURL != *pkgSourceURL {
			return nil, fmt.Errorf("conflicting source URLs: %s vs %s", *sourceURL, *pkgSourceURL)
		}
	}

	return sourceURL, nil
}

func NewOutput(status executiondag.Status, statusReason string, outputs []PackageOutput, input dag_impl.Input, nextInput *dag_impl.Input) *Output {
	baseOutput := dag_impl.NewBaseOutput(status, statusReason, input)
	baseOutput.Output = nextInput

	return &Output{
		BaseOutput:         baseOutput,
		Outputs:            outputs,
		RejectedSourceURLs: []RejectedSourceURL{},
	}
}

func NewOutputWithRejections(status executiondag.Status, statusReason string, outputs []PackageOutput, rejections []RejectedSourceURL, input dag_impl.Input, nextInput *dag_impl.Input) *Output {
	baseOutput := dag_impl.NewBaseOutput(status, statusReason, input)
	baseOutput.Output = nextInput

	return &Output{
		BaseOutput:         baseOutput,
		Outputs:            outputs,
		RejectedSourceURLs: rejections,
	}
}

func (o *Output) GetSupportedOverrides() []overrides.FieldInfo {
	return []overrides.FieldInfo{
		{
			Path:        "source_url",
			Type:        "string",
			Description: "Override the source repository URL used for git clone and source analysis",
		},
	}
}

func (o *Output) ApplyOverridesV2(overrideList []overrides.Override) ([]overrides.AppliedOverride, error) {
	var applied []overrides.AppliedOverride
	for _, override := range overrideList {
		switch override.Path {
		case "source_url":
			sourceURL, ok := override.Value.(string)
			if !ok || sourceURL == "" {
				return nil, fmt.Errorf("source_url override must be a non-empty string, got %v", override.Value)
			}
			if len(o.Outputs) != 1 {
				return nil, fmt.Errorf("source_url override requires exactly 1 package, got %d", len(o.Outputs))
			}
			if o.Outputs[0].Metadata != nil {
				o.Outputs[0].Metadata.SourceURL = &sourceURL
			}
			if o.Output != nil {
				o.Output.SourceURL = &sourceURL
			}
			applied = append(applied, overrides.AppliedOverride{Path: override.Path, Reason: override.Reason})
		default:
			continue
		}
	}
	return applied, nil
}

func (o *Output) GetPackageMetadata(ecosystem, name string) *models.PackageMetadata {
	for _, output := range o.Outputs {
		if output.Ecosystem == ecosystem && output.Name == name {
			return output.Metadata
		}
	}
	return nil
}

func (o *Output) PersistKey() string { return "package" }
