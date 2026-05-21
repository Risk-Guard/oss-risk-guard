package spdx30

import (
	"encoding/json"
	"risk-guard/src/depsgraph"
	"risk-guard/src/violations"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuilder_EmptyNodes(t *testing.T) {
	builder := NewBuilder("source/github.com/test/repo", []depsgraph.SBOMNode{}, "risk-guard-test")
	doc, err := builder.Build()

	require.NoError(t, err)
	assert.Equal(t, Context, doc.Context)

	var hasCreationInfo, hasOrg, hasTool, hasSpdxDoc bool
	for _, elem := range doc.Graph {
		switch v := elem.(type) {
		case CreationInfo:
			hasCreationInfo = true
			assert.Equal(t, SpecVer, v.SpecVersion)
		case Organization:
			hasOrg = true
		case Tool:
			hasTool = true
		case SpdxDocument:
			hasSpdxDoc = true
			assert.Empty(t, v.RootElement)
		}
	}
	assert.True(t, hasCreationInfo)
	assert.True(t, hasOrg)
	assert.True(t, hasTool)
	assert.True(t, hasSpdxDoc)
}

func TestBuilder_SinglePackage(t *testing.T) {
	eco := "npm"
	name := "express"
	version := "4.18.2"

	nodes := []depsgraph.SBOMNode{
		{
			Key:            "package/npm/express",
			Ecosystem:      &eco,
			PackageName:    &name,
			PackageVersion: &version,
		},
	}

	builder := NewBuilder("package/npm/express", nodes, "risk-guard-test")
	doc, err := builder.Build()

	require.NoError(t, err)

	var pkg *Package
	var describesCount int
	for _, elem := range doc.Graph {
		switch v := elem.(type) {
		case Package:
			pkg = &v
		case Relationship:
			if v.RelationshipType == RelationshipDescribes {
				describesCount++
			}
		}
	}

	require.NotNil(t, pkg)
	assert.Equal(t, "express", pkg.Name)
	assert.Equal(t, "4.18.2", pkg.PackageVersion)
	assert.Equal(t, NoAssertion, pkg.DownloadLocation)
	assert.Equal(t, "software_Package", pkg.Type)
	assert.Equal(t, "pkg:npm/express@4.18.2", pkg.PackageURL)
	assert.Equal(t, 1, describesCount)
}

func TestBuilder_WithDependencies(t *testing.T) {
	npmEco := "npm"
	expressName := "express"
	expressVersion := "4.18.2"
	debugName := "debug"
	debugVersion := "4.3.4"

	nodes := []depsgraph.SBOMNode{
		{
			Key:            "package/npm/express",
			Ecosystem:      &npmEco,
			PackageName:    &expressName,
			PackageVersion: &expressVersion,
			Deps:           []string{"package/npm/debug"},
		},
		{
			Key:            "package/npm/debug",
			Ecosystem:      &npmEco,
			PackageName:    &debugName,
			PackageVersion: &debugVersion,
		},
	}

	builder := NewBuilder("package/npm/express", nodes, "risk-guard-test")
	doc, err := builder.Build()

	require.NoError(t, err)

	var pkgCount, describesCount, dependsOnCount int
	for _, elem := range doc.Graph {
		switch v := elem.(type) {
		case Package:
			pkgCount++
		case Relationship:
			switch v.RelationshipType {
			case RelationshipDescribes:
				describesCount++
				assert.Len(t, v.To, 1)
			case RelationshipDependsOn:
				dependsOnCount++
				assert.Len(t, v.To, 1)
			}
		}
	}
	assert.Equal(t, 2, pkgCount)
	assert.Equal(t, 1, describesCount)
	assert.Equal(t, 1, dependsOnCount)
}

func TestBuilder_MissingMetadata(t *testing.T) {
	nodes := []depsgraph.SBOMNode{
		{
			Key: "package/npm/unknown",
		},
	}

	builder := NewBuilder("package/npm/unknown", nodes, "risk-guard-test")
	doc, err := builder.Build()

	require.NoError(t, err)

	var pkg *Package
	for _, elem := range doc.Graph {
		if v, ok := elem.(Package); ok {
			pkg = &v
			break
		}
	}

	require.NotNil(t, pkg)
	assert.Equal(t, "package/npm/unknown", pkg.Name)
	assert.Equal(t, NoAssertion, pkg.DownloadLocation)
	assert.Equal(t, NoAssertion, pkg.CopyrightText)
	assert.Empty(t, pkg.PackageURL)
}

func TestBuilder_DocumentMetadata(t *testing.T) {
	builder := NewBuilder("source/github.com/test/repo", []depsgraph.SBOMNode{}, "risk-guard-v1.0.0")
	doc, err := builder.Build()

	require.NoError(t, err)
	assert.Equal(t, Context, doc.Context)

	var creationInfo *CreationInfo
	var spdxDoc *SpdxDocument
	var tool *Tool
	for _, elem := range doc.Graph {
		switch v := elem.(type) {
		case CreationInfo:
			creationInfo = &v
		case SpdxDocument:
			spdxDoc = &v
		case Tool:
			tool = &v
		}
	}

	require.NotNil(t, creationInfo)
	assert.Equal(t, SpecVer, creationInfo.SpecVersion)
	assert.Equal(t, "CreationInfo", creationInfo.Type)

	require.NotNil(t, spdxDoc)
	assert.Equal(t, "SBOM for source/github.com/test/repo", spdxDoc.Name)
	assert.Contains(t, spdxDoc.SpdxID, "app.ossriskguard/")
	assert.Equal(t, []string{ProfileSoftware}, spdxDoc.ProfileConformance)

	require.NotNil(t, tool)
	assert.Equal(t, "risk-guard-v1.0.0", tool.Name)
}

func TestBuilder_SkipsUnknownDeps(t *testing.T) {
	npmEco := "npm"
	name := "mypackage"

	nodes := []depsgraph.SBOMNode{
		{
			Key:         "package/npm/mypackage",
			Ecosystem:   &npmEco,
			PackageName: &name,
			Deps:        []string{"package/npm/real-dep", "package/npm/not-in-nodes"},
		},
		{
			Key:       "package/npm/real-dep",
			Ecosystem: &npmEco,
		},
	}

	builder := NewBuilder("package/npm/mypackage", nodes, "risk-guard-test")
	doc, err := builder.Build()

	require.NoError(t, err)

	var dependsOnCount int
	for _, elem := range doc.Graph {
		if v, ok := elem.(Relationship); ok && v.RelationshipType == RelationshipDependsOn {
			dependsOnCount++
		}
	}
	assert.Equal(t, 1, dependsOnCount)
}

func TestBuilder_JSONLDStructure(t *testing.T) {
	eco := "npm"
	name := "express"
	version := "4.18.2"

	nodes := []depsgraph.SBOMNode{
		{
			Key:            "package/npm/express",
			Ecosystem:      &eco,
			PackageName:    &name,
			PackageVersion: &version,
		},
	}

	builder := NewBuilder("package/npm/express", nodes, "risk-guard-test")
	doc, err := builder.Build()
	require.NoError(t, err)

	data, err := json.Marshal(doc)
	require.NoError(t, err)

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &raw))

	var ctx string
	require.NoError(t, json.Unmarshal(raw["@context"], &ctx))
	assert.Equal(t, Context, ctx)

	var graph []map[string]any
	require.NoError(t, json.Unmarshal(raw["@graph"], &graph))
	assert.GreaterOrEqual(t, len(graph), 4)

	typeSet := make(map[string]bool)
	for _, elem := range graph {
		if t, ok := elem["type"].(string); ok {
			typeSet[t] = true
		}
	}
	assert.True(t, typeSet["CreationInfo"])
	assert.True(t, typeSet["Organization"])
	assert.True(t, typeSet["Tool"])
	assert.True(t, typeSet["SpdxDocument"])
	assert.True(t, typeSet["software_Package"])
}

func TestBuilder_WithViolations(t *testing.T) {
	eco := "npm"
	name := "risky-pkg"
	version := "1.0.0"

	nodes := []depsgraph.SBOMNode{
		{
			Key:            "package/npm/risky-pkg",
			Ecosystem:      &eco,
			PackageName:    &name,
			PackageVersion: &version,
			Violations: []violations.Violation{
				{
					CheckCode: "SCV001",
					Rationale: "No verified publisher",
					Evidence:  []string{"registry metadata missing publisher verification"},
				},
				{
					CheckCode: "SCV002",
					Rationale: "Known vulnerability CVE-2024-1234",
				},
			},
		},
	}

	builder := NewBuilder("package/npm/risky-pkg", nodes, "risk-guard-test")
	doc, err := builder.Build()
	require.NoError(t, err)

	var pkg *Package
	for _, elem := range doc.Graph {
		if v, ok := elem.(Package); ok {
			pkg = &v
			break
		}
	}

	require.NotNil(t, pkg)
	require.Len(t, pkg.Extensions, 1)
	ext := pkg.Extensions[0]
	assert.Equal(t, "extension_CdxPropertiesExtension", ext.Type)
	require.Len(t, ext.Properties, 3)

	assert.Equal(t, "extension_CdxPropertyEntry", ext.Properties[0].Type)
	assert.Equal(t, "riskguard:violation:SCV001", ext.Properties[0].Name)
	assert.Equal(t, "No verified publisher", ext.Properties[0].Value)

	assert.Equal(t, "extension_CdxPropertyEntry", ext.Properties[1].Type)
	assert.Equal(t, "riskguard:evidence:SCV001", ext.Properties[1].Name)
	assert.Equal(t, `["registry metadata missing publisher verification"]`, ext.Properties[1].Value)

	assert.Equal(t, "extension_CdxPropertyEntry", ext.Properties[2].Type)
	assert.Equal(t, "riskguard:violation:SCV002", ext.Properties[2].Name)
	assert.Equal(t, "Known vulnerability CVE-2024-1234", ext.Properties[2].Value)
}

func TestBuilder_NoViolationsOmitsField(t *testing.T) {
	eco := "npm"
	name := "clean-pkg"

	nodes := []depsgraph.SBOMNode{
		{
			Key:         "package/npm/clean-pkg",
			Ecosystem:   &eco,
			PackageName: &name,
		},
	}

	builder := NewBuilder("package/npm/clean-pkg", nodes, "risk-guard-test")
	doc, err := builder.Build()
	require.NoError(t, err)

	data, err := json.Marshal(doc)
	require.NoError(t, err)

	assert.False(t, strings.Contains(string(data), "extension"),
		"JSON should not contain extension key when no violations exist")
}
