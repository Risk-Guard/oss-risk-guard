package spdx30

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

// DirectDep pairs an analysis-identifier key with optional manifest-source
// provenance. Location is nil when the SBOM did not record it.
type DirectDep struct {
	Key      string
	Location *models.LocationInfo
}

// ReadDirectDeps returns the analysis-identifier keys for the SBOM's direct
// (depth=1) dependencies. Keys are decoded from the SPDX spdxId suffix
// produced by Builder (base64 of the original key).
func ReadDirectDeps(raw []byte) ([]string, error) {
	deps, err := ReadDirectDepsWithLocations(raw)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(deps))
	for _, d := range deps {
		out = append(out, d.Key)
	}
	return out, nil
}

// ReadDirectDepsWithLocations is the same as ReadDirectDeps but also returns
// each direct dep's manifest-file provenance, parsed from hasDependencyManifest
// relationships. The target is either a software_File (file-only) or a
// software_Snippet pointing at a software_File and carrying a software_lineRange
// (file + line).
func ReadDirectDepsWithLocations(raw []byte) ([]DirectDep, error) {
	var doc struct {
		Graph []json.RawMessage `json:"@graph"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decoding SPDX: %w", err)
	}

	type rel struct {
		RelationshipType string   `json:"relationshipType"`
		From             string   `json:"from"`
		To               []string `json:"to"`
	}

	type snippet struct {
		SpdxID          string                `json:"spdxId"`
		SnippetFromFile string                `json:"software_snippetFromFile"`
		LineRange       *PositiveIntegerRange `json:"software_lineRange"`
	}

	rels := make([]rel, 0)
	var rootElement string
	files := make(map[string]string)     // spdxId -> file name
	snippets := make(map[string]snippet) // spdxId -> snippet
	for _, node := range doc.Graph {
		var head struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(node, &head); err != nil {
			continue
		}
		switch head.Type {
		case "Relationship":
			var r rel
			if err := json.Unmarshal(node, &r); err == nil {
				rels = append(rels, r)
			}
		case "SpdxDocument":
			var d struct {
				RootElement []string `json:"rootElement"`
			}
			if err := json.Unmarshal(node, &d); err == nil && len(d.RootElement) > 0 {
				rootElement = d.RootElement[0]
			}
		case "software_File":
			var f struct {
				SpdxID string `json:"spdxId"`
				Name   string `json:"name"`
			}
			if err := json.Unmarshal(node, &f); err == nil && f.SpdxID != "" {
				files[f.SpdxID] = f.Name
			}
		case "software_Snippet":
			var s snippet
			if err := json.Unmarshal(node, &s); err == nil && s.SpdxID != "" {
				snippets[s.SpdxID] = s
			}
		}
	}

	if rootElement == "" {
		return nil, fmt.Errorf("SPDX missing rootElement")
	}

	locByPkgID := make(map[string]*models.LocationInfo)
	for _, r := range rels {
		if r.RelationshipType != RelationshipHasDependencyManifest || len(r.To) == 0 {
			continue
		}
		target := r.To[0]
		if fileName, ok := files[target]; ok {
			locByPkgID[r.From] = &models.LocationInfo{File: strPtr(fileName)}
			continue
		}
		if s, ok := snippets[target]; ok {
			fileName, fileOK := files[s.SnippetFromFile]
			if !fileOK {
				continue
			}
			loc := &models.LocationInfo{File: strPtr(fileName)}
			if s.LineRange != nil && s.LineRange.BeginIntegerRange > 0 {
				ln := s.LineRange.BeginIntegerRange
				loc.LineNumber = &ln
			}
			locByPkgID[r.From] = loc
		}
	}

	var directIDs []string
	for _, r := range rels {
		if r.RelationshipType == RelationshipDependsOn && r.From == rootElement {
			directIDs = append(directIDs, r.To...)
		}
	}

	out := make([]DirectDep, 0, len(directIDs))
	for _, id := range directIDs {
		suffix := id
		if i := strings.LastIndex(id, "#"); i >= 0 {
			suffix = id[i+1:]
		}
		decoded, err := base64.RawURLEncoding.DecodeString(suffix)
		if err != nil {
			continue
		}
		out = append(out, DirectDep{Key: string(decoded), Location: locByPkgID[id]})
	}
	return out, nil
}

func strPtr(s string) *string { return &s }
