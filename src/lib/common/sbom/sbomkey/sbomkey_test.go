package sbomkey

import (
	"encoding/base64"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/depsgraph"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom/purl"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func encode(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func TestResolve_PrefersEncodedRefOverPURL(t *testing.T) {
	// The ref is what the document wires its dependency edges with, so it wins
	// over a purl built from metadata that disagrees with it.
	key, ok := Resolve(encode("package/pypi/requests"), "pkg:npm/requests")
	require.True(t, ok)
	assert.Equal(t, "package/pypi/requests", key)
}

func TestResolve_FallsBackToPURLForForeignRefs(t *testing.T) {
	key, ok := Resolve("f2fdf419-eaf4-4409-9d2b-85a345d2cac9", "pkg:npm/lodash@4.17.23")
	require.True(t, ok)
	assert.Equal(t, "package/npm/lodash?version=4.17.23", key)
}

func TestResolve_RejectsForeignRefWithoutPURL(t *testing.T) {
	// A UUID is 36 characters of the base64url alphabet and decodes cleanly to
	// 27 bytes of binary. Without the key-prefix check it would pass for one.
	_, ok := Resolve("f2fdf419-eaf4-4409-9d2b-85a345d2cac9", "")
	assert.False(t, ok)
}

func TestDecodeRef_StripsSPDXNamespace(t *testing.T) {
	key, ok := DecodeRef("app.ossriskguard/abc.2026-01-01T00:00:00Z#" + encode("source/repo"))
	require.True(t, ok)
	assert.Equal(t, "source/repo", key)
}

func TestStableNodePURL(t *testing.T) {
	npm, pypi := "npm", "pypi"
	lodash, requests := "lodash", "requests"
	v := "4.17.23"

	t.Run("round-trips", func(t *testing.T) {
		node := depsgraph.SBOMNode{Ecosystem: &npm, PackageName: &lodash, PackageVersion: &v}
		assert.Equal(t, "pkg:npm/lodash@4.17.23",
			StableNodePURL(node, "package/npm/lodash?version=4.17.23"))
	})

	t.Run("rejected when it denotes a different package", func(t *testing.T) {
		node := depsgraph.SBOMNode{Ecosystem: &npm, PackageName: &requests}
		assert.Empty(t, StableNodePURL(node, "package/pypi/requests"))
	})

	t.Run("empty without a package name", func(t *testing.T) {
		node := depsgraph.SBOMNode{Ecosystem: &pypi}
		assert.Empty(t, StableNodePURL(node, "package/pypi/requests"))
	})
}

func TestToAnalysisKey_RoundTripsEveryEcosystem(t *testing.T) {
	cases := []struct {
		ecosystem string
		name      string
		version   string
		wantKey   string
	}{
		{"npm", "lodash", "4.17.23", "package/npm/lodash?version=4.17.23"},
		{"npm", "@scope/pkg", "1.0.0", "package/npm/@scope/pkg?version=1.0.0"},
		{"npm", "is-odd", "", "package/npm/is-odd"},
		{"pypi", "requests", "2.31.0", "package/pypi/requests?version=2.31.0"},
		{"pypi", "Flask_Core", "1.0", "package/pypi/flask-core?version=1.0"},
		{"rubygems", "rails", "7.1.0", "package/rubygems/rails?version=7.1.0"},
		{"golang", "golang.org/x/net", "0.17.0", "package/golang/golang.org/x/net?version=0.17.0"},
		{"cargo", "serde", "1.0.0", "package/cargo/serde?version=1.0.0"},
		{"maven", "junit", "4.13.2", "package/maven/junit?version=4.13.2"},
		{"nuget", "Newtonsoft.Json", "13.0.3", "package/nuget/Newtonsoft.Json?version=13.0.3"},
	}

	for _, tc := range cases {
		t.Run(tc.ecosystem+"/"+tc.name, func(t *testing.T) {
			key, ok := purl.ToAnalysisKey(purl.Build(tc.ecosystem, tc.name, tc.version))
			require.True(t, ok)
			assert.Equal(t, tc.wantKey, key)
		})
	}
}

func TestToAnalysisKey_IgnoresQualifiersAndSubpath(t *testing.T) {
	// scalibr emits the same package twice, distinguished only by a qualifier.
	bare, ok := purl.ToAnalysisKey("pkg:npm/is-buffer@1.1.6")
	require.True(t, ok)
	qualified, ok := purl.ToAnalysisKey("pkg:npm/is-buffer@1.1.6?source=UNKNOWN")
	require.True(t, ok)
	assert.Equal(t, bare, qualified)

	subpath, ok := purl.ToAnalysisKey("pkg:golang/golang.org/x/net@0.17.0#html")
	require.True(t, ok)
	assert.Equal(t, "package/golang/golang.org/x/net?version=0.17.0", subpath)
}

func TestToAnalysisKey_Rejects(t *testing.T) {
	for _, s := range []string{"", "lodash", "pkg:", "pkg:npm", "pkg:npm/", "pkg:/lodash"} {
		_, ok := purl.ToAnalysisKey(s)
		assert.False(t, ok, "expected %q to be rejected", s)
	}
}
