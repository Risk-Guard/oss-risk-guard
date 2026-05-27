package spdx30

import (
	"encoding/json"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/depsgraph"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReader_RoundTripWithAndWithoutLocation(t *testing.T) {
	eco := "npm"
	lodash, requests, dateFns := "lodash", "requests", "date-fns"
	pkgJSON, reqTxt := "package.json", "requirements.txt"
	line := 12

	nodes := []depsgraph.SBOMNode{
		{Key: "source/repo", Deps: []string{
			"package/npm/lodash",
			"package/pypi/requests",
			"package/npm/date-fns",
		}},
		{
			Key:         "package/npm/lodash",
			Ecosystem:   &eco,
			PackageName: &lodash,
			Location:    &models.LocationInfo{File: &pkgJSON, LineNumber: &line},
		},
		{
			Key:         "package/pypi/requests",
			Ecosystem:   &eco,
			PackageName: &requests,
			Location:    &models.LocationInfo{File: &reqTxt},
		},
		{
			Key:         "package/npm/date-fns",
			Ecosystem:   &eco,
			PackageName: &dateFns,
		},
	}

	doc, err := NewBuilder("source/repo", nodes, "test-tool").Build()
	require.NoError(t, err)
	raw, err := json.Marshal(doc)
	require.NoError(t, err)

	deps, err := ReadDirectDepsWithLocations(raw)
	require.NoError(t, err)

	byKey := make(map[string]*models.LocationInfo)
	for _, d := range deps {
		byKey[d.Key] = d.Location
	}

	require.Contains(t, byKey, "package/npm/lodash")
	loc := byKey["package/npm/lodash"]
	require.NotNil(t, loc, "lodash should have a location via Snippet")
	require.NotNil(t, loc.File)
	assert.Equal(t, "package.json", *loc.File)
	require.NotNil(t, loc.LineNumber)
	assert.Equal(t, 12, *loc.LineNumber)

	require.Contains(t, byKey, "package/pypi/requests")
	loc = byKey["package/pypi/requests"]
	require.NotNil(t, loc, "requests should have a file-only location via direct File ref")
	require.NotNil(t, loc.File)
	assert.Equal(t, "requirements.txt", *loc.File)
	assert.Nil(t, loc.LineNumber, "no line number expected")

	require.Contains(t, byKey, "package/npm/date-fns")
	assert.Nil(t, byKey["package/npm/date-fns"], "date-fns should have no location")
}
