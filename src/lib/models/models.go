package models

import (
	"fmt"
	"strings"
	"time"
)

func MakeSimplePackageAnalysisIdentifier(ecosystem, name string) string {
	return fmt.Sprintf("package/%s/%s", ecosystem, name)
}

type LocationInfo struct {
	File       *string `json:"file,omitempty"`
	LineNumber *int    `json:"ln,omitempty"`
}

func CopyLocation(l *LocationInfo) *LocationInfo {
	if l == nil {
		return nil
	}
	return &LocationInfo{File: l.File, LineNumber: l.LineNumber}
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
		return strings.Join(parts[2:], "/")
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
