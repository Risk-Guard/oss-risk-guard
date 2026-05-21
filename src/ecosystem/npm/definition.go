package npm

import (
	"net/url"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/def"
	"strings"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

var Definition = def.Definition{
	Name:        "npm",
	DisplayName: "JavaScript (NPM)",
	Source: executiondag.Source{
		Name:        "NPM Registry",
		URL:         "https://registry.npmjs.org",
		Description: "Package registry for JavaScript (NPM)",
		Category:    executiondag.SourceCategoryRegistry,
	},
	OSVEcosystem:         "npm",
	GHSAEcosystem:        "npm",
	PURLType:             "npm",
	PackageAPIURLFormat:  "%s/%s",
	PackagePageURLFormat: "https://www.npmjs.com/package/%s",
	DependencyFilePatterns: []string{
		"**/package.json",
		"**/package-lock.json",
		"**/yarn.lock",
		"**/pnpm-lock.yaml",
		"**/bun.lock",
		"**/bun.lockb",
	},
	SkipDirectories: []string{"node_modules"},
	EncodePURLName:  encodeNPMName,
	NormalizeName:   normalizeName,
}

func encodeNPMName(name string) string {
	if strings.HasPrefix(name, "@") {
		parts := strings.SplitN(name, "/", 2)
		if len(parts) == 2 {
			namespace := strings.TrimPrefix(parts[0], "@")
			return "%40" + url.PathEscape(namespace) + "/" + url.PathEscape(parts[1])
		}
	}
	return url.PathEscape(name)
}

func normalizeName(name string) string {
	return strings.TrimSpace(name)
}
