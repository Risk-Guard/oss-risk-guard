package purl

import (
	"net/url"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/language/python/normalize"
)

var ecosystemToType = map[string]string{
	"npm":      "npm",
	"pypi":     "pypi",
	"rubygems": "gem",
	"golang":   "golang",
	"cargo":    "cargo",
	"maven":    "maven",
	"nuget":    "nuget",
}

func Build(ecosystem, name, version string) string {
	purlType, ok := ecosystemToType[strings.ToLower(ecosystem)]
	if !ok {
		purlType = strings.ToLower(ecosystem)
	}

	encodedName := encodeName(purlType, name)

	if version == "" {
		return "pkg:" + purlType + "/" + encodedName
	}
	return "pkg:" + purlType + "/" + encodedName + "@" + url.PathEscape(version)
}

func encodeName(purlType, name string) string {
	switch purlType {
	case "npm":
		return encodeNPMName(name)
	case "pypi":
		return url.PathEscape(normalize.NormalizePyPIName(name))
	default:
		return url.PathEscape(name)
	}
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

// typeToEcosystem inverts ecosystemToType. Only the entries whose purl type
// differs from the ecosystem name need listing; the rest round-trip as-is.
var typeToEcosystem = map[string]string{
	"gem": "rubygems",
}

// ToAnalysisKey converts a purl into an analysis-identifier key
// ("package/{eco}/{name}" or "package/{eco}/{name}?version={v}"), inverting
// Build. Qualifiers and subpaths are discarded, so a foreign purl such as
// "pkg:npm/lodash@4.17.23?source=UNKNOWN" yields the same key as one without
// them. Reports false when the string is not a purl or carries no name.
func ToAnalysisKey(purlStr string) (string, bool) {
	rest, found := strings.CutPrefix(purlStr, "pkg:")
	if !found {
		return "", false
	}
	rest, _, _ = strings.Cut(rest, "#")
	rest, _, _ = strings.Cut(rest, "?")

	purlType, nameVersion, found := strings.Cut(rest, "/")
	if !found {
		return "", false
	}
	purlType = strings.ToLower(purlType)
	if purlType == "" || nameVersion == "" {
		return "", false
	}

	// The only unescaped '@' is the version separator: a scoped npm namespace
	// is carried encoded as %40.
	name, version := nameVersion, ""
	if i := strings.LastIndex(nameVersion, "@"); i > 0 {
		name, version = nameVersion[:i], nameVersion[i+1:]
	}

	name, err := decodeName(purlType, name)
	if err != nil || name == "" {
		return "", false
	}

	ecosystem := purlType
	if eco, ok := typeToEcosystem[purlType]; ok {
		ecosystem = eco
	}

	key := "package/" + ecosystem + "/" + name
	if version == "" {
		return key, true
	}
	// Keys carry the version verbatim (see makeKey in the lockfile parsers),
	// so unescape without re-escaping.
	version, err = url.PathUnescape(version)
	if err != nil || version == "" {
		return key, true
	}
	return key + "?version=" + version, true
}

func decodeName(purlType, name string) (string, error) {
	decoded, err := url.PathUnescape(name)
	if err != nil {
		return "", err
	}
	if purlType == "pypi" {
		return normalize.NormalizePyPIName(decoded), nil
	}
	return decoded, nil
}
