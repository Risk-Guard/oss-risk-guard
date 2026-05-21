package purl

import (
	"net/url"
	"github.com/Risk-Guard/oss-risk-guard/src/language/python/normalize"
	"strings"
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
