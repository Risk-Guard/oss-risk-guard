// Package spdx23 reads SPDX 2.3 JSON documents as produced by osv-scalibr,
// using the same spdx/tools-golang library scalibr writes them with. Unlike
// the cdx16/spdx30 readers, package identity comes from purls (there is no
// analysis-key bom-ref encoding), so keys are derived here.
package spdx23

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/models"

	"github.com/package-url/packageurl-go"
	spdxjson "github.com/spdx/tools-golang/json"
	spdx "github.com/spdx/tools-golang/spdx/v2/common"
	spdx23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

// PackageInfo is one package enumerated from an SPDX 2.3 document: its derived
// analysis-identifier key, name/version, purl, manifest provenance (from
// DEPENDENCY_MANIFEST_OF relationships), and the keys of its own dependencies
// (from DEPENDS_ON relationships, when the producer recorded them).
type PackageInfo struct {
	Key      string
	Name     string
	Version  string
	PURL     string
	Location *models.LocationInfo
	Deps     []string
}

// Overview is a read-only, display-oriented view of an SPDX 2.3 document,
// mirroring the cdx16/spdx30 Overview shape so the format-agnostic sbom
// package can dispatch to it.
type Overview struct {
	SpecVersion string
	Tool        string
	RootName    string
	RootDeps    []string
	Packages    []PackageInfo
}

// purlTypeToEcosystem maps purl types whose name differs from the ecosystem
// name used in analysis-identifier keys. Unlisted types pass through as-is.
var purlTypeToEcosystem = map[string]string{
	packageurl.TypeGem:    "rubygems",
	packageurl.TypeGolang: "go",
}

// ReadOverview parses an SPDX 2.3 JSON document and returns its metadata, the
// dependency edges, and every package that carries a purl (the root package is
// excluded). Direct dependencies are the root's DEPENDS_ON targets; documents
// without DEPENDS_ON edges (scalibr's current output) fall back to the root's
// CONTAINS targets, which flattens every package to depth 1.
func ReadOverview(raw []byte) (*Overview, error) {
	doc, err := spdxjson.Read(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("decoding SPDX 2.3: %w", err)
	}

	ov := &Overview{SpecVersion: strings.TrimPrefix(doc.SPDXVersion, "SPDX-")}
	if doc.CreationInfo != nil {
		for _, c := range doc.CreationInfo.Creators {
			if c.CreatorType == "Tool" {
				ov.Tool = c.Creator
				break
			}
		}
	}

	rootID := findRootID(doc)
	filePathByID := make(map[spdx.ElementID]string, len(doc.Files))
	for _, f := range doc.Files {
		filePathByID[f.FileSPDXIdentifier] = f.FileName
	}

	dependsByID := make(map[spdx.ElementID][]spdx.ElementID)
	containsByID := make(map[spdx.ElementID][]spdx.ElementID)
	manifestByID := make(map[spdx.ElementID]string)
	for _, rel := range doc.Relationships {
		a, b := rel.RefA.ElementRefID, rel.RefB.ElementRefID
		if a == "" || b == "" {
			continue
		}
		switch rel.Relationship {
		case "DEPENDS_ON":
			dependsByID[a] = append(dependsByID[a], b)
		case "CONTAINS":
			containsByID[a] = append(containsByID[a], b)
		case "DEPENDENCY_MANIFEST_OF":
			// RefA is the manifest file, RefB the package it declares.
			if path, ok := filePathByID[a]; ok {
				if _, exists := manifestByID[b]; !exists {
					manifestByID[b] = path
				}
			}
		}
	}

	keyByID := make(map[spdx.ElementID]string, len(doc.Packages))
	infoByKey := make(map[spdx.ElementID]*PackageInfo, len(doc.Packages))
	for _, p := range doc.Packages {
		if p.PackageSPDXIdentifier == rootID {
			ov.RootName = p.PackageName
			continue
		}
		purlStr := packagePURL(p)
		if purlStr == "" {
			continue
		}
		key, name, version, err := keyFromPURL(purlStr)
		if err != nil {
			continue
		}
		keyByID[p.PackageSPDXIdentifier] = key
		info := &PackageInfo{Key: key, Name: name, Version: version, PURL: purlStr}
		if path := manifestByID[p.PackageSPDXIdentifier]; path != "" {
			info.Location = &models.LocationInfo{File: &path}
		}
		infoByKey[p.PackageSPDXIdentifier] = info
	}

	// Direct deps are the root's DEPENDS_ON targets plus, for extractors that
	// don't record edges yet, every root-CONTAINS package that no DEPENDS_ON
	// edge points at (i.e. not a known transitive). When no edges exist at all
	// this degrades to the flat CONTAINS list. The comparison is by derived key,
	// not SPDXID, because the same logical package can be enumerated more than
	// once (lockfile + installed node_modules manifest) under different IDs.
	dependedOnKeys := make(map[string]bool)
	for _, targets := range dependsByID {
		for _, id := range targets {
			if key, ok := keyByID[id]; ok {
				dependedOnKeys[key] = true
			}
		}
	}
	rootChildIDs := append([]spdx.ElementID{}, dependsByID[rootID]...)
	for _, id := range containsByID[rootID] {
		if key, ok := keyByID[id]; ok && !dependedOnKeys[key] {
			rootChildIDs = append(rootChildIDs, id)
		}
	}
	ov.RootDeps = dedupeKeys(rootChildIDs, keyByID)

	seen := make(map[string]bool, len(infoByKey))
	for _, p := range doc.Packages {
		info, ok := infoByKey[p.PackageSPDXIdentifier]
		if !ok {
			continue
		}
		info.Deps = dedupeKeys(dependsByID[p.PackageSPDXIdentifier], keyByID)
		// Documents can enumerate the same logical package more than once (e.g.
		// found via both a lockfile and an installed node_modules manifest); the
		// first occurrence wins.
		if seen[info.Key] {
			continue
		}
		seen[info.Key] = true
		ov.Packages = append(ov.Packages, *info)
	}
	return ov, nil
}

// findRootID returns the SPDXID of the package the document DESCRIBES, or ""
// when there is none.
func findRootID(doc *spdx23.Document) spdx.ElementID {
	for _, rel := range doc.Relationships {
		if rel.Relationship == "DESCRIBES" && rel.RefA.ElementRefID == "DOCUMENT" {
			return rel.RefB.ElementRefID
		}
	}
	return ""
}

// packagePURL returns the package's purl external reference, or "".
func packagePURL(p *spdx23.Package) string {
	for _, ref := range p.PackageExternalReferences {
		if ref.RefType == "purl" {
			return ref.Locator
		}
	}
	return ""
}

// keyFromPURL derives the analysis-identifier key ("package/{eco}/{name}" plus
// "?version={v}" when versioned) from a purl, along with the decoded full name
// and version.
func keyFromPURL(purlStr string) (key, name, version string, err error) {
	p, err := packageurl.FromString(purlStr)
	if err != nil {
		return "", "", "", err
	}
	eco := p.Type
	if mapped, ok := purlTypeToEcosystem[eco]; ok {
		eco = mapped
	}
	name = p.Name
	if p.Namespace != "" {
		name = p.Namespace + "/" + p.Name
	}
	key = models.MakeSimplePackageAnalysisIdentifier(eco, name)
	if p.Version != "" {
		key += "?version=" + p.Version
	}
	return key, name, p.Version, nil
}

// dedupeKeys maps element IDs to their derived keys, dropping IDs without a
// key (the root, purl-less packages) and duplicate keys, preserving order.
func dedupeKeys(ids []spdx.ElementID, keyByID map[spdx.ElementID]string) []string {
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		key, ok := keyByID[id]
		if !ok || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	return out
}
