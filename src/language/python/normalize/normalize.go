package normalize

import (
	"regexp"
	"strings"
)

// NormalizePyPIName normalizes a PyPI package name according to PEP 503
// Converts runs of [-_.] to a single dash and lowercases
// Example: "Flask_Core" -> "flask-core", "my__package" -> "my-package"
func NormalizePyPIName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ToLower(name)

	// Replace runs of [-_.] with a single dash
	re := regexp.MustCompile(`[-_.]+`)
	name = re.ReplaceAllString(name, "-")

	// Trim leading and trailing dashes
	name = strings.Trim(name, "-")

	return name
}
