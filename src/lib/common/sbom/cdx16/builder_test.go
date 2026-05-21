package cdx16

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/depsgraph"
	"github.com/Risk-Guard/oss-risk-guard/src/violations"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuilder_EmptyBOM(t *testing.T) {
	builder := NewBuilder("source/github.com/test/repo", []depsgraph.SBOMNode{}, "risk-guard-test")
	bom, err := builder.Build()

	require.NoError(t, err)
	assert.Equal(t, BOMFormat, bom.BOMFormat)
	assert.Equal(t, SpecVersion, bom.SpecVersion)
	assert.Equal(t, 1, bom.Version)
	assert.True(t, strings.HasPrefix(bom.SerialNumber, "urn:uuid:"))
	assert.Empty(t, bom.Components)
	assert.Empty(t, bom.Dependencies)
	assert.Nil(t, bom.Metadata.Component)
	require.NotNil(t, bom.Metadata.Tools)
	require.Len(t, bom.Metadata.Tools.Components, 1)
	assert.Equal(t, "risk-guard-test", bom.Metadata.Tools.Components[0].Name)
}

func TestBuilder_SingleComponent(t *testing.T) {
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
	bom, err := builder.Build()

	require.NoError(t, err)
	require.Len(t, bom.Components, 1)

	comp := bom.Components[0]
	assert.Equal(t, "library", comp.Type)
	assert.Equal(t, "express", comp.Name)
	assert.Equal(t, "4.18.2", comp.Version)
	assert.Equal(t, "pkg:npm/express@4.18.2", comp.PURL)
	assert.Nil(t, comp.Properties)

	require.NotNil(t, bom.Metadata.Component)
	assert.Equal(t, "express", bom.Metadata.Component.Name)
}

func TestBuilder_Dependencies(t *testing.T) {
	npmEco := "npm"
	expressName := "express"
	debugName := "debug"

	nodes := []depsgraph.SBOMNode{
		{
			Key:         "package/npm/express",
			Ecosystem:   &npmEco,
			PackageName: &expressName,
			Deps:        []string{"package/npm/debug"},
		},
		{
			Key:         "package/npm/debug",
			Ecosystem:   &npmEco,
			PackageName: &debugName,
		},
	}

	builder := NewBuilder("package/npm/express", nodes, "risk-guard-test")
	bom, err := builder.Build()

	require.NoError(t, err)
	assert.Len(t, bom.Components, 2)
	assert.Len(t, bom.Dependencies, 2)

	depMap := make(map[string][]string)
	for _, dep := range bom.Dependencies {
		depMap[dep.Ref] = dep.DependsOn
	}

	expressDeps := depMap[bomRef("package/npm/express")]
	require.Len(t, expressDeps, 1)
	assert.Equal(t, bomRef("package/npm/debug"), expressDeps[0])
}

func TestBuilder_ViolationsAsProperties(t *testing.T) {
	eco := "npm"
	name := "risky-pkg"

	nodes := []depsgraph.SBOMNode{
		{
			Key:         "package/npm/risky-pkg",
			Ecosystem:   &eco,
			PackageName: &name,
			Violations: []violations.Violation{
				{
					CheckCode: "SCV001",
					Rationale: "No verified publisher",
					Evidence:  []string{"missing publisher verification"},
				},
				{
					CheckCode: "SCV002",
					Rationale: "Known vulnerability",
				},
			},
		},
	}

	builder := NewBuilder("package/npm/risky-pkg", nodes, "risk-guard-test")
	bom, err := builder.Build()

	require.NoError(t, err)
	require.Len(t, bom.Components, 1)

	comp := bom.Components[0]
	require.Len(t, comp.Properties, 3)

	assert.Equal(t, "riskguard:violation:SCV001", comp.Properties[0].Name)
	assert.Equal(t, "No verified publisher", comp.Properties[0].Value)

	assert.Equal(t, "riskguard:evidence:SCV001", comp.Properties[1].Name)
	assert.Equal(t, `["missing publisher verification"]`, comp.Properties[1].Value)

	assert.Equal(t, "riskguard:violation:SCV002", comp.Properties[2].Name)
	assert.Equal(t, "Known vulnerability", comp.Properties[2].Value)
}

func TestBuilder_NoPropertiesWhenClean(t *testing.T) {
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
	bom, err := builder.Build()

	require.NoError(t, err)
	require.Len(t, bom.Components, 1)

	data, err := json.Marshal(bom)
	require.NoError(t, err)

	assert.False(t, strings.Contains(string(data), "properties"),
		"JSON should not contain properties key when no violations exist")
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
	bom, err := builder.Build()

	require.NoError(t, err)

	depMap := make(map[string][]string)
	for _, dep := range bom.Dependencies {
		depMap[dep.Ref] = dep.DependsOn
	}

	myPkgDeps := depMap[bomRef("package/npm/mypackage")]
	assert.Len(t, myPkgDeps, 1)
	assert.Equal(t, bomRef("package/npm/real-dep"), myPkgDeps[0])
}
