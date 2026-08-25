package models

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

func MakeSimplePackageAnalysisIdentifier(ecosystem, name string) string {
	return fmt.Sprintf("package/%s/%s", ecosystem, name)
}

// MakeVersionedPackageAnalysisIdentifier builds an analysis key carrying a
// resolved version ("package/<eco>/<name>?version=<v>"), falling back to the
// unversioned form when version is empty.
//
// The version is query-escaped because readers unescape it (see
// parseKeyIdentity): a PEP 440 local version such as "1.0+local" would
// otherwise decode with the "+" turned into a space.
func MakeVersionedPackageAnalysisIdentifier(ecosystem, name, version string) string {
	if version == "" {
		return MakeSimplePackageAnalysisIdentifier(ecosystem, name)
	}
	return fmt.Sprintf("package/%s/%s?version=%s", ecosystem, name, url.QueryEscape(version))
}

type LocationInfo struct {
	File       *string `json:"file,omitempty"`
	LineNumber *int    `json:"ln,omitempty"`
}

type Dependency struct {
	AnalysisIdentifier string   `json:"analysis_identifier"`
	Specifiers         []string `json:"specifiers"`
	EnvironmentMarker  *string  `json:"environment_marker,omitempty"`
	Extras             []string `json:"extras,omitempty"`
	ExtraMarker        *string  `json:"extra_marker,omitempty"`
	// Dev indicates this package would not exist in a production install.
	// True when the package is only reachable through dev dependency paths from root.
	Dev        bool          `json:"dev,omitempty"`
	ParseError *string       `json:"parse_error,omitempty"`
	Location   *LocationInfo `json:"source,omitempty"`
}

func (d Dependency) GetName() string {
	parts := strings.Split(d.AnalysisIdentifier, "/")
	if len(parts) >= 3 {
		// Identifiers may carry a "?version=" suffix, which is not part of the name.
		name, _, _ := strings.Cut(strings.Join(parts[2:], "/"), "?")
		return name
	}
	return ""
}

func (d Dependency) GetEcosystem() string {
	parts := strings.Split(d.AnalysisIdentifier, "/")
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

type Package struct {
	Name         string       `json:"name"`
	Ecosystem    string       `json:"ecosystem"`
	Dependencies []Dependency `json:"dependencies"`
	Version      *string      `json:"version,omitempty"`
	License      *string      `json:"license,omitempty"`
	SourceURL    *string      `json:"source_url,omitempty"`
	SourceURLKey *string      `json:"source_url_key,omitempty"`
	ReleaseDate  *time.Time   `json:"release_date,omitempty"`
	Status       string       `json:"status"`
}
