package pep508

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An exactly pinned requirement must carry its version into the analysis key.
// Without it, version-sensitive checks score the registry's latest release
// instead of the version the manifest installs.
func TestParseRequirementsTxt_ExactPinCarriesVersion(t *testing.T) {
	deps, err := ParseRequirementsTxt("gunicorn==22.0.0\n", "requirements.txt")
	require.NoError(t, err)
	require.Len(t, deps, 1)

	assert.Equal(t, "package/pypi/gunicorn?version=22.0.0", deps[0].AnalysisIdentifier)
	assert.Equal(t, []string{"==22.0.0"}, deps[0].Specifiers)
	assert.Equal(t, "gunicorn", deps[0].GetName())
	assert.Equal(t, "pypi", deps[0].GetEcosystem())
}

func TestParseRequirementsTxt_AnalysisIdentifiers(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{name: "exact pin", line: "gunicorn==22.0.0", want: "package/pypi/gunicorn?version=22.0.0"},
		{name: "pin with extras", line: "gunicorn[gevent]==22.0.0", want: "package/pypi/gunicorn?version=22.0.0"},
		{name: "pin with environment marker", line: `gunicorn==22.0.0; python_version < "3.9"`, want: "package/pypi/gunicorn?version=22.0.0"},
		{name: "pin with hash option", line: "gunicorn==22.0.0 --hash=sha256:abc123", want: "package/pypi/gunicorn?version=22.0.0"},
		{name: "pin in parenthesized form", line: "gunicorn (==22.0.0)", want: "package/pypi/gunicorn?version=22.0.0"},
		{name: "name is normalized alongside the pin", line: "Flask_SQLAlchemy==3.1.1", want: "package/pypi/flask-sqlalchemy?version=3.1.1"},

		// Local versions must survive the QueryUnescape readers apply, so "+"
		// is escaped rather than left to decode as a space.
		{name: "local version is escaped", line: "gunicorn==1.0+local", want: "package/pypi/gunicorn?version=1.0%2Blocal"},

		// Anything that leaves the version open stays unversioned.
		{name: "range", line: "gunicorn>=20.0", want: "package/pypi/gunicorn"},
		{name: "wildcard", line: "gunicorn==22.*", want: "package/pypi/gunicorn"},
		{name: "compatible release", line: "gunicorn~=22.0", want: "package/pypi/gunicorn"},
		{name: "bare name", line: "gunicorn", want: "package/pypi/gunicorn"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, err := ParseRequirementsTxt(tt.line+"\n", "requirements.txt")
			require.NoError(t, err)
			require.Len(t, deps, 1)
			assert.Equal(t, tt.want, deps[0].AnalysisIdentifier)
		})
	}
}

// A malformed line yields only the specifiers that parsed before the error,
// which is too little to pin on.
func TestParseRequirementsTxt_MalformedLineDoesNotPin(t *testing.T) {
	deps, err := ParseRequirementsTxt("gunicorn==22.0.0,>=\n", "requirements.txt")
	require.NoError(t, err)
	require.Len(t, deps, 1)

	assert.Equal(t, "package/pypi/gunicorn", deps[0].AnalysisIdentifier)
	assert.NotNil(t, deps[0].ParseError)
}

// Line numbers and file locations are unaffected by the added version.
func TestParseRequirementsTxt_PinKeepsLocation(t *testing.T) {
	deps, err := ParseRequirementsTxt("# comment\nflask==3.0.0\ngunicorn==22.0.0\n", "requirements.txt")
	require.NoError(t, err)
	require.Len(t, deps, 2)

	assert.Equal(t, "package/pypi/flask?version=3.0.0", deps[0].AnalysisIdentifier)
	require.NotNil(t, deps[0].Location.LineNumber)
	assert.Equal(t, 2, *deps[0].Location.LineNumber)

	assert.Equal(t, "package/pypi/gunicorn?version=22.0.0", deps[1].AnalysisIdentifier)
	require.NotNil(t, deps[1].Location.LineNumber)
	assert.Equal(t, 3, *deps[1].Location.LineNumber)
}
