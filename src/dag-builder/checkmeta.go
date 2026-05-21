package dag_builder

import (
	"context"
	"fmt"
	"sort"

	"github.com/Risk-Guard/oss-risk-guard/src/category"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/environment"
	languageregistry "github.com/Risk-Guard/oss-risk-guard/src/language/registry"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"

	"go.uber.org/zap"
)

type CheckMetadata interface {
	GetCode() string
	GetDescription() string
}

type ExtendedCheckMetadata interface {
	CheckMetadata
	GetCategories() map[category.RiskCategory]string
}

type DocumentedCheckMetadata interface {
	GetWhyThisMatters() string
	GetOutcomes() storage.Outcomes
	GetDisclaimers() []string
	GetThresholds() map[string]any
}

type DeprecatedCheckMetadata interface {
	GetDeprecated() bool
}

type CheckInfo struct {
	Code           string                           `json:"code"`
	Description    string                           `json:"description"`
	WhyThisMatters string                           `json:"why_this_matters,omitempty"`
	Categories     map[category.RiskCategory]string `json:"categories,omitempty"`
	Outcomes       storage.Outcomes                 `json:"outcomes,omitempty"`
	Disclaimers    []string                         `json:"disclaimers,omitempty"`
	Thresholds     map[string]any                   `json:"thresholds,omitempty"`
	Deprecated     bool                             `json:"deprecated,omitempty"`
	DataSources    []string                         `json:"data_sources,omitempty"`
}

func IsDeprecated(underlying any) bool {
	iDeprecated, ok := underlying.(DeprecatedCheckMetadata)
	if !ok {
		return false
	}

	return iDeprecated.GetDeprecated()
}

func GetAllCheckMetadata(builder DagBuilder) ([]CheckInfo, map[string]executiondag.Source) {
	ctx := context.Background()
	cfg := &environment.Config{}
	ctx = environment.SetConfig(ctx, cfg)
	ctx = environment.SetSharedConfig(ctx, cfg)
	ctx = ctxutil.SetLogger(ctx, zap.NewNop())

	langs := languageregistry.Languages()
	input := dag_impl.Input{SourceURL: nil, Packages: nil}

	dag := executiondag.NewDAG[dag_impl.Input]()
	_ = builder(dag, &input, langs, ctx)

	allSources := make(map[string]executiondag.Source)
	var result []CheckInfo

	for _, node := range dag.GetNodes() {
		if node.GetKind() != "check" {
			continue
		}

		underlying := node.GetNodeForReflection()
		meta, ok := underlying.(CheckMetadata)
		if !ok {
			panic(fmt.Sprintf("check node %T does not implement CheckMetadata", underlying))
		}

		info := CheckInfo{
			Code:        meta.GetCode(),
			Description: meta.GetDescription(),
		}

		if extended, ok := underlying.(ExtendedCheckMetadata); ok {
			info.Categories = extended.GetCategories()
		}

		if documented, ok := underlying.(DocumentedCheckMetadata); ok {
			info.WhyThisMatters = documented.GetWhyThisMatters()
			info.Outcomes = documented.GetOutcomes()
			info.Disclaimers = documented.GetDisclaimers()
			info.Thresholds = documented.GetThresholds()
		}

		info.Deprecated = IsDeprecated(underlying)

		upstream := dag.CollectUpstreamSources(node)
		keys := make([]string, 0, len(upstream))
		for key := range upstream {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			allSources[key] = upstream[key]
			info.DataSources = append(info.DataSources, key)
		}

		result = append(result, info)
	}

	return result, allSources
}

func BuildCheckCategoryMap(builder DagBuilder) map[string][]category.RiskCategory {
	metadata, _ := GetAllCheckMetadata(builder)
	m := make(map[string][]category.RiskCategory)
	for _, info := range metadata {
		cats := make([]category.RiskCategory, 0, len(info.Categories))
		for cat := range info.Categories {
			cats = append(cats, cat)
		}
		m[info.Code] = cats
	}
	return m
}
