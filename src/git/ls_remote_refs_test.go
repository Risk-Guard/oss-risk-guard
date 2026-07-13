package git

import (
	"context"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/environment"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestIsSafeTagVersion(t *testing.T) {
	cases := map[string]bool{
		"6.3.1":        true,
		"1.0.0-beta.1": true,
		"2.0.0+build":  true,
		"1.2.3~rc1":    true,
		"v1.2.3":       true, // leading letter is allowed; the glob still works
		"":             false,
		"-1.2.3":       false, // leading dash → option injection risk
		"1.2.3 4":      false, // whitespace
		"1.2.3;rm":     false, // shell metachar
		"*":            false, // glob char in the version itself
		"a/b":          false, // slash
	}
	for in, want := range cases {
		if got := IsSafeTagVersion(in); got != want {
			t.Errorf("IsSafeTagVersion(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestValidateTagPattern(t *testing.T) {
	valid := []string{"*6.3.1", "*@dnd-kit/core@6.3.1", "v1.2.3", "*1.0.0-beta.1"}
	for _, p := range valid {
		require.NoErrorf(t, ValidateTagPattern(p), "expected %q to be valid", p)
	}
	invalid := []string{"", "-6.3.1", "*6.3.1;rm", "* 6.3.1", "*`whoami`"}
	for _, p := range invalid {
		require.Errorf(t, ValidateTagPattern(p), "expected %q to be rejected", p)
	}
}

func TestParseRemoteRefs(t *testing.T) {
	// A lightweight tag (no ^{} line) and an annotated tag (base + dereferenced
	// ^{} commit). The annotated tag must resolve to the dereferenced commit.
	out := "1111111111111111111111111111111111111111\trefs/tags/v1.0.0\n" +
		"2222222222222222222222222222222222222222\trefs/tags/v2.0.0\n" +
		"3333333333333333333333333333333333333333\trefs/tags/v2.0.0^{}\n"

	refs := parseRemoteRefs(out)
	require.Len(t, refs, 2)

	require.Equal(t, "refs/tags/v1.0.0", refs[0].Name)
	require.Equal(t, "1111111111111111111111111111111111111111", refs[0].SHA)

	require.Equal(t, "refs/tags/v2.0.0", refs[1].Name)
	require.Equal(t, "3333333333333333333333333333333333333333", refs[1].SHA,
		"annotated tag must resolve to the dereferenced commit, not the tag object")
}

func TestParseRemoteRefs_Empty(t *testing.T) {
	require.Nil(t, parseRemoteRefs(""))
}

// TestListRemoteRefs_Glob exercises the real ls-remote glob against a monorepo
// whose tags are package-scoped (@dnd-kit/core@6.3.1), the motivating case for
// the version-tag fallback.
func TestListRemoteRefs_Glob(t *testing.T) {
	ctx := context.Background()
	cfg := &environment.Config{SecureGit: true}
	ctx = environment.SetConfig(ctx, cfg)
	ctx = environment.SetSharedConfig(ctx, cfg)
	ctx = ctxutil.SetLogger(ctx, zap.NewNop())

	refs, err := ListRemoteRefs(ctx, "https://github.com/clauderic/dnd-kit", "*6.3.1")
	require.NoError(t, err)
	require.NotEmpty(t, refs, "expected at least one tag ending in 6.3.1")

	var found bool
	for _, r := range refs {
		if r.Name == "refs/tags/@dnd-kit/core@6.3.1" {
			found = true
			require.Len(t, r.SHA, 40)
		}
	}
	require.True(t, found, "expected refs/tags/@dnd-kit/core@6.3.1 in %v", refs)
}
