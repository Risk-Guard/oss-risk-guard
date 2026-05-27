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

type spdxRel struct {
	RelationshipType string   `json:"relationshipType"`
	From             string   `json:"from"`
	To               []string `json:"to"`
}

type spdxSnippet struct {
	SpdxID          string                `json:"spdxId"`
	SnippetFromFile string                `json:"software_snippetFromFile"`
	LineRange       *PositiveIntegerRange `json:"software_lineRange"`
}

type spdxGraph struct {
	rels        []spdxRel
	files       map[string]string // spdxId -> file name
	snippets    map[string]spdxSnippet
	rootElement string
}

func parseSPDXGraph(raw []byte) (*spdxGraph, error) {
	var doc struct {
		Graph []json.RawMessage `json:"@graph"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decoding SPDX: %w", err)
	}

	g := &spdxGraph{
		files:    make(map[string]string),
		snippets: make(map[string]spdxSnippet),
	}
	for _, node := range doc.Graph {
		var head struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(node, &head); err != nil {
			continue
		}
		g.ingestNode(head.Type, node)
	}
	return g, nil
}

func (g *spdxGraph) ingestNode(typ string, node json.RawMessage) {
	switch typ {
	case "Relationship":
		var r spdxRel
		if err := json.Unmarshal(node, &r); err == nil {
			g.rels = append(g.rels, r)
		}
	case "SpdxDocument":
		var d struct {
			RootElement []string `json:"rootElement"`
		}
		if err := json.Unmarshal(node, &d); err == nil && len(d.RootElement) > 0 {
			g.rootElement = d.RootElement[0]
		}
	case "software_File":
		var f struct {
			SpdxID string `json:"spdxId"`
			Name   string `json:"name"`
		}
		if err := json.Unmarshal(node, &f); err == nil && f.SpdxID != "" {
			g.files[f.SpdxID] = f.Name
		}
	case "software_Snippet":
		var s spdxSnippet
		if err := json.Unmarshal(node, &s); err == nil && s.SpdxID != "" {
			g.snippets[s.SpdxID] = s
		}
	}
}

func (g *spdxGraph) locationsByPkgID() map[string]*models.LocationInfo {
	out := make(map[string]*models.LocationInfo)
	for _, r := range g.rels {
		if r.RelationshipType != RelationshipHasDependencyManifest || len(r.To) == 0 {
			continue
		}
		if loc := g.resolveLocation(r.To[0]); loc != nil {
			out[r.From] = loc
		}
	}
	return out
}

func (g *spdxGraph) resolveLocation(target string) *models.LocationInfo {
	if fileName, ok := g.files[target]; ok {
		return &models.LocationInfo{File: strPtr(fileName)}
	}
	s, ok := g.snippets[target]
	if !ok {
		return nil
	}
	fileName, fileOK := g.files[s.SnippetFromFile]
	if !fileOK {
		return nil
	}
	loc := &models.LocationInfo{File: strPtr(fileName)}
	if s.LineRange != nil && s.LineRange.BeginIntegerRange > 0 {
		ln := s.LineRange.BeginIntegerRange
		loc.LineNumber = &ln
	}
	return loc
}

func (g *spdxGraph) directDepIDs() []string {
	var ids []string
	for _, r := range g.rels {
		if r.RelationshipType == RelationshipDependsOn && r.From == g.rootElement {
			ids = append(ids, r.To...)
		}
	}
	return ids
}

// ReadDirectDepsWithLocations is the same as ReadDirectDeps but also returns
// each direct dep's manifest-file provenance, parsed from hasDependencyManifest
// relationships. The target is either a software_File (file-only) or a
// software_Snippet pointing at a software_File and carrying a software_lineRange
// (file + line).
func ReadDirectDepsWithLocations(raw []byte) ([]DirectDep, error) {
	g, err := parseSPDXGraph(raw)
	if err != nil {
		return nil, err
	}
	if g.rootElement == "" {
		return nil, fmt.Errorf("SPDX missing rootElement")
	}

	locByPkgID := g.locationsByPkgID()
	directIDs := g.directDepIDs()

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
