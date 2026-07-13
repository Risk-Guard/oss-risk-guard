package checks

import "testing"

func TestSourceRefScanned(t *testing.T) {
	tests := []struct {
		name   string
		ref    SourceRef
		pkgRef string
		want   string
	}{
		{
			name: "gitHead wording is unchanged",
			ref:  SourceRef{Kind: ProvenanceGitHead, Commit: "deadbeefcafe0000000000000000000000000000"},
			want: "Scanned source as published (gitHead deadbee)",
		},
		{
			name: "tag discloses the resolved ref and short SHA",
			ref:  SourceRef{Kind: ProvenanceTag, Commit: "34781e0d9d757d35d8e44177fc7003286d562484", Name: "@dnd-kit/core@6.3.1"},
			want: "Scanned source at tag @dnd-kit/core@6.3.1 (34781e0)",
		},
		{
			name:   "head wording is unchanged and names the package",
			ref:    SourceRef{Kind: ProvenanceHead},
			pkgRef: "npm/@dnd-kit/core@6.3.1",
			want:   "Scanned repository HEAD — no gitHead recorded for npm/@dnd-kit/core@6.3.1, so source may differ from the published artifact",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ref.Scanned(tt.pkgRef); got != tt.want {
				t.Errorf("Scanned() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSourceRefPublished(t *testing.T) {
	if !(SourceRef{Kind: ProvenanceGitHead}).Published() {
		t.Error("gitHead should be Published")
	}
	if !(SourceRef{Kind: ProvenanceTag}).Published() {
		t.Error("tag should be Published")
	}
	if (SourceRef{Kind: ProvenanceHead}).Published() {
		t.Error("head should not be Published")
	}
}
