package git_clone_published_content

import (
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/git"

	"github.com/stretchr/testify/require"
)

func ref(name, sha string) git.RemoteRef { return git.RemoteRef{Name: name, SHA: sha} }

const (
	shaCore = "1111111111111111111111111111111111111111"
	shaSort = "2222222222222222222222222222222222222222"
	shaV    = "3333333333333333333333333333333333333333"
)

func TestSelectVersionTag(t *testing.T) {
	tests := []struct {
		name     string
		refs     []git.RemoteRef
		pkgName  string
		version  string
		wantName string
		wantSHA  string
	}{
		{
			name: "monorepo package-scoped tag preferred over sibling and bare tags",
			refs: []git.RemoteRef{
				ref("refs/tags/@dnd-kit/sortable@6.3.1", shaSort),
				ref("refs/tags/v6.3.1", shaV),
				ref("refs/tags/@dnd-kit/core@6.3.1", shaCore),
			},
			pkgName:  "@dnd-kit/core",
			version:  "6.3.1",
			wantName: "@dnd-kit/core@6.3.1",
			wantSHA:  shaCore,
		},
		{
			name:     "root-hosted v-prefixed tag",
			refs:     []git.RemoteRef{ref("refs/tags/v4.22.1", shaV)},
			pkgName:  "express",
			version:  "4.22.1",
			wantName: "v4.22.1",
			wantSHA:  shaV,
		},
		{
			name:     "bare version tag when no v-prefix",
			refs:     []git.RemoteRef{ref("refs/tags/1.2.3", shaV)},
			pkgName:  "somepkg",
			version:  "1.2.3",
			wantName: "1.2.3",
			wantSHA:  shaV,
		},
		{
			name:     "coarse glob match for a different version is rejected",
			refs:     []git.RemoteRef{ref("refs/tags/v16.3.1", shaV)},
			pkgName:  "somepkg",
			version:  "6.3.1",
			wantName: "",
			wantSHA:  "",
		},
		{
			name:     "branch ref that isn't a tag is ignored",
			refs:     []git.RemoteRef{ref("refs/heads/v1.2.3", shaV)},
			pkgName:  "somepkg",
			version:  "1.2.3",
			wantName: "",
			wantSHA:  "",
		},
		{
			name:     "no matching refs",
			refs:     []git.RemoteRef{ref("refs/tags/v9.9.9", shaV)},
			pkgName:  "somepkg",
			version:  "1.2.3",
			wantName: "",
			wantSHA:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, sha := selectVersionTag(tt.refs, tt.pkgName, tt.version)
			require.Equal(t, tt.wantName, name)
			require.Equal(t, tt.wantSHA, sha)
		})
	}
}
