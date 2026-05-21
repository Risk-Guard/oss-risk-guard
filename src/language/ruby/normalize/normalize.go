package normalize

import (
	"strings"
)

func NormalizeRubyGemsName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.Trim(name, "-")

	return name
}
