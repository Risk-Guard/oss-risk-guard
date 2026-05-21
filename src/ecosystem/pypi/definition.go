package pypi

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/def"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

var Definition = def.Definition{
	Name:        "pypi",
	DisplayName: "Python (PyPI)",
	Source: executiondag.Source{
		Name:        "PyPI Registry",
		URL:         "https://pypi.org/pypi",
		Description: "Package registry for Python (PyPI)",
		Category:    executiondag.SourceCategoryRegistry,
	},
	OSVEcosystem:         "PyPI",
	GHSAEcosystem:        "pip",
	PURLType:             "pypi",
	PackageAPIURLFormat:  "%s/%s/json",
	PackagePageURLFormat: "https://pypi.org/project/%s",
	DependencyFilePatterns: []string{
		"**/pyproject.toml",
		"**/setup.cfg",
		"**/setup.py",
		"**/requirements.txt",
		"**/poetry.lock",
		"**/Pipfile.lock",
		"**/pdm.lock",
		"**/uv.lock",
	},
	SkipDirectories: []string{".git", "node_modules", "__pycache__", ".venv", "venv", ".tox"},
	EncodePURLName:  encodePyPIName,
	NormalizeName:   normalizePyPIName,
}

func encodePyPIName(name string) string {
	return url.PathEscape(normalizePyPIName(name))
}

// normalizePyPIName normalizes a PyPI package name according to PEP 503.
// Converts runs of [-_.] to a single dash and lowercases.
func normalizePyPIName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ToLower(name)

	re := regexp.MustCompile(`[-_.]+`)
	name = re.ReplaceAllString(name, "-")

	name = strings.Trim(name, "-")

	return name
}
