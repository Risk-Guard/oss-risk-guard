package rubygems

import (
	"net/url"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/def"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

var Definition = def.Definition{
	Name:        "rubygems",
	DisplayName: "Ruby (RubyGems)",
	Source: executiondag.Source{
		Name:        "RubyGems Registry",
		URL:         "https://rubygems.org",
		Description: "Package registry for Ruby (RubyGems)",
		Category:    executiondag.SourceCategoryRegistry,
	},
	OSVEcosystem:         "RubyGems",
	GHSAEcosystem:        "rubygems",
	PURLType:             "gem",
	PackageAPIURLFormat:  "%s/api/v1/gems/%s.json",
	PackagePageURLFormat: "https://rubygems.org/gems/%s",
	DependencyFilePatterns: []string{
		"**/Gemfile",
		"**/Gemfile.lock",
		"**/*.gemspec",
	},
	SkipDirectories: []string{".git", "node_modules", "vendor", "tmp"},
	EncodePURLName:  encodeRubyGemsName,
	NormalizeName:   normalizeRubyGemsName,
}

func encodeRubyGemsName(name string) string {
	return url.PathEscape(name)
}

func normalizeRubyGemsName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.Trim(name, "-")
	return name
}
