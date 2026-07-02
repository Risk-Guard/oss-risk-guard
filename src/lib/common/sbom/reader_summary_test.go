package sbom

import (
	"encoding/json"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/depsgraph"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom/cdx16"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom/spdx30"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fixture keys, shared by the graph builders and the assertions.
const (
	fxRoot     = "source/example.com/repo"
	fxLodash   = "package/npm/lodash?version=4.17.21"
	fxMs       = "package/npm/ms?version=2.1.3"
	fxRequests = "package/pypi/requests"
	fxRails    = "package/rubygems/rails?version=7.0.0"
)

// summaryFixtureNodes returns a small dependency graph spanning three
// ecosystems, with a transitive (lodash -> ms) and mixed version/location
// coverage, used to round-trip both SBOM formats through ReadSummary.
func summaryFixtureNodes() (string, []depsgraph.SBOMNode) {
	npm, pypi, rubygems := "npm", "pypi", "rubygems"
	lodash, ms, requests, rails := "lodash", "ms", "requests", "rails"
	lodashVer, msVer, railsVer := "4.17.21", "2.1.3", "7.0.0"
	pkgJSON, reqTxt := "package.json", "requirements.txt"
	line := 12

	nodes := []depsgraph.SBOMNode{
		{Key: fxRoot, Deps: []string{fxLodash, fxRequests, fxRails}},
		{
			Key:            fxLodash,
			Deps:           []string{fxMs},
			Ecosystem:      &npm,
			PackageName:    &lodash,
			PackageVersion: &lodashVer,
			Location:       &models.LocationInfo{File: &pkgJSON, LineNumber: &line},
		},
		{
			Key:            fxMs,
			Ecosystem:      &npm,
			PackageName:    &ms,
			PackageVersion: &msVer,
		},
		{
			Key:         fxRequests,
			Ecosystem:   &pypi,
			PackageName: &requests,
			Location:    &models.LocationInfo{File: &reqTxt},
		},
		{
			Key:            fxRails,
			Ecosystem:      &rubygems,
			PackageName:    &rails,
			PackageVersion: &railsVer,
		},
	}
	return fxRoot, nodes
}

// assertFixtureSummary checks a Summary parsed from either format against the
// summaryFixtureNodes graph: sorted packages, ecosystem recovered from the key
// (rubygems, not the purl type "gem"), versions, manifest provenance, and the
// dependency graph (root deps + the lodash -> ms transitive edge).
func assertFixtureSummary(t *testing.T, s *Summary) {
	t.Helper()

	assert.Equal(t, "risk-guard", s.Tool)
	assert.Contains(t, s.RootName, "example.com/repo")

	// Root's direct dependencies (order-independent).
	assert.ElementsMatch(t, []string{fxLodash, fxRequests, fxRails}, s.RootDeps)

	require.Len(t, s.Packages, 4)
	byKey := make(map[string]Package, len(s.Packages))
	for _, p := range s.Packages {
		byKey[p.Key] = p
	}

	// Packages are sorted by ecosystem then name: npm/lodash, npm/ms, pypi, gem.
	assert.Equal(t, []string{fxLodash, fxMs, fxRequests, fxRails},
		[]string{s.Packages[0].Key, s.Packages[1].Key, s.Packages[2].Key, s.Packages[3].Key})

	lodash := byKey[fxLodash]
	assert.Equal(t, "npm", lodash.Ecosystem)
	assert.Equal(t, "lodash", lodash.Name)
	assert.Equal(t, "4.17.21", lodash.Version)
	assert.Equal(t, []string{fxMs}, lodash.Deps) // the transitive edge survives
	require.NotNil(t, lodash.Location)
	require.NotNil(t, lodash.Location.File)
	assert.Equal(t, "package.json", *lodash.Location.File)
	require.NotNil(t, lodash.Location.LineNumber)
	assert.Equal(t, 12, *lodash.Location.LineNumber)

	ms := byKey[fxMs]
	assert.Equal(t, "npm", ms.Ecosystem)
	assert.Empty(t, ms.Deps)

	requests := byKey[fxRequests]
	assert.Equal(t, "pypi", requests.Ecosystem)
	assert.Empty(t, requests.Version)
	require.NotNil(t, requests.Location)
	require.NotNil(t, requests.Location.File)
	assert.Equal(t, "requirements.txt", *requests.Location.File)
	assert.Nil(t, requests.Location.LineNumber)

	rails := byKey[fxRails]
	assert.Equal(t, "rubygems", rails.Ecosystem)
	assert.Equal(t, "7.0.0", rails.Version)
	assert.Nil(t, rails.Location)
}

func TestReadSummary_SPDX(t *testing.T) {
	rootKey, nodes := summaryFixtureNodes()
	doc, err := spdx30.NewBuilder(rootKey, nodes, "risk-guard").Build()
	require.NoError(t, err)
	raw, err := json.Marshal(doc)
	require.NoError(t, err)

	s, err := ReadSummary(raw)
	require.NoError(t, err)

	assert.Equal(t, "SPDX", s.Format)
	assert.Equal(t, "3.0.1", s.SpecVersion)
	assertFixtureSummary(t, s)
}

func TestReadSummary_CycloneDX(t *testing.T) {
	rootKey, nodes := summaryFixtureNodes()
	bom, err := cdx16.NewBuilder(rootKey, nodes, "risk-guard").Build()
	require.NoError(t, err)
	raw, err := json.Marshal(bom)
	require.NoError(t, err)

	s, err := ReadSummary(raw)
	require.NoError(t, err)

	assert.Equal(t, "CycloneDX", s.Format)
	assert.Equal(t, "1.6", s.SpecVersion)
	assertFixtureSummary(t, s)
}

func TestReadSummary_UnrecognizedFormat(t *testing.T) {
	_, err := ReadSummary([]byte(`{"hello":"world"}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unrecognized SBOM format")
}

func TestReadSummary_InvalidJSON(t *testing.T) {
	_, err := ReadSummary([]byte(`not json`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not valid JSON")
}

func TestEcosystemFromKey(t *testing.T) {
	cases := map[string]string{
		"package/npm/lodash":                   "npm",
		"package/rubygems/rails?version=7.0.0": "rubygems",
		"source/example.com/repo":              "",
		"package/":                             "",
		"garbage":                              "",
	}
	for key, want := range cases {
		assert.Equalf(t, want, ecosystemFromKey(key), "ecosystemFromKey(%q)", key)
	}
}
