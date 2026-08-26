package spdx30

import (
	"encoding/json"
	"fmt"

	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom/sbomkey"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

// DirectDep pairs an analysis-identifier key with optional manifest-source
// provenance. Location is nil when the SBOM did not record it.
type DirectDep struct {
	Key      string
	Location *models.LocationInfo
}

// ReadDirectDeps returns the analysis-identifier keys for the SBOM's direct
// (depth=1) dependencies.
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

// spdxPkg is a software_Package node reduced to the fields needed for display.
type spdxPkg struct {
	SpdxID  string
	Name    string
	Version string
	PURL    string
}

type spdxGraph struct {
	rels        []spdxRel
	files       map[string]string // spdxId -> file name
	snippets    map[string]spdxSnippet
	packages    []spdxPkg
	pkgByID     map[string]spdxPkg // spdxId -> package
	specVersion string
	toolName    string
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
		pkgByID:  make(map[string]spdxPkg),
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
	case "software_Package":
		var p struct {
			SpdxID  string `json:"spdxId"`
			Name    string `json:"name"`
			Version string `json:"software_packageVersion"`
			PURL    string `json:"software_packageUrl"`
		}
		if err := json.Unmarshal(node, &p); err == nil && p.SpdxID != "" {
			pkg := spdxPkg{SpdxID: p.SpdxID, Name: p.Name, Version: p.Version, PURL: p.PURL}
			g.packages = append(g.packages, pkg)
			g.pkgByID[p.SpdxID] = pkg
		}
	case "CreationInfo":
		var ci struct {
			SpecVersion string `json:"specVersion"`
		}
		if err := json.Unmarshal(node, &ci); err == nil && ci.SpecVersion != "" {
			g.specVersion = ci.SpecVersion
		}
	case "Tool":
		var t struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(node, &t); err == nil && g.toolName == "" {
			g.toolName = t.Name
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

// dependsChildrenByFrom collects every dependsOn relationship into a map from
// the source element's spdxId to the spdxIds it depends on — the full
// dependency graph, root included.
func (g *spdxGraph) dependsChildrenByFrom() map[string][]string {
	out := make(map[string][]string)
	for _, r := range g.rels {
		if r.RelationshipType != RelationshipDependsOn {
			continue
		}
		out[r.From] = append(out[r.From], r.To...)
	}
	return out
}

// resolveKey recovers the analysis-identifier key for an element, using the
// package's purl where the document records one.
func (g *spdxGraph) resolveKey(id string) (string, bool) {
	return sbomkey.Resolve(id, g.pkgByID[id].PURL)
}

// resolveKeys resolves a list of spdxIds to analysis keys, dropping any that do
// not resolve.
func (g *spdxGraph) resolveKeys(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if key, ok := g.resolveKey(id); ok {
			out = append(out, key)
		}
	}
	return out
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
		key, ok := g.resolveKey(id)
		if !ok {
			continue
		}
		out = append(out, DirectDep{Key: key, Location: locByPkgID[id]})
	}
	return out, nil
}

// PackageInfo is one software package enumerated from an SPDX document for
// display: its analysis-identifier key, the stored name/version, its purl,
// manifest provenance, and the keys of its own dependencies (Deps) from the
// document's dependsOn relationships.
type PackageInfo struct {
	Key      string
	Name     string
	Version  string
	PURL     string
	Location *models.LocationInfo
	Deps     []string
}

// Overview is a read-only, display-oriented view of an SPDX document: its spec
// version, generating tool, root package name, the root's direct dependency
// keys (RootDeps), and every enumerated package (the root package is excluded).
// Together RootDeps and each package's Deps form the dependency graph needed to
// render a tree.
type Overview struct {
	SpecVersion string
	Tool        string
	RootName    string
	RootDeps    []string
	Packages    []PackageInfo
}

// ReadOverview parses an SPDX 3.0.1 document and returns its metadata, the
// dependency graph, and the full software_Package set minus the root, each with
// its resolved analysis key and manifest provenance. Packages whose identity
// cannot be resolved are skipped.
func ReadOverview(raw []byte) (*Overview, error) {
	g, err := parseSPDXGraph(raw)
	if err != nil {
		return nil, err
	}

	ov := &Overview{SpecVersion: g.specVersion, Tool: g.toolName}
	if root, ok := g.pkgByID[g.rootElement]; ok {
		ov.RootName = root.Name
	}

	childIDsByFrom := g.dependsChildrenByFrom()
	ov.RootDeps = g.resolveKeys(childIDsByFrom[g.rootElement])

	locByPkgID := g.locationsByPkgID()
	for _, p := range g.packages {
		if p.SpdxID == g.rootElement {
			continue
		}
		key, ok := g.resolveKey(p.SpdxID)
		if !ok {
			continue
		}
		ov.Packages = append(ov.Packages, PackageInfo{
			Key:      key,
			Name:     p.Name,
			Version:  p.Version,
			PURL:     p.PURL,
			Deps:     g.resolveKeys(childIDsByFrom[p.SpdxID]),
			Location: locByPkgID[p.SpdxID],
		})
	}
	return ov, nil
}

func strPtr(s string) *string { return &s }
