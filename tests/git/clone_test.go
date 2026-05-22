package git_test

import (
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/git"
)

func TestValidateGitRef_Valid(t *testing.T) {
	validRefs := []string{
		"main",
		"v1.0.0",
		"4.18.0",
		"feature/my-branch",
		"553c2077f0edc3d5dc5d17262f6aa498e69d6f8e",
		"HEAD",
		"refs/tags/v1.0",
	}

	for _, ref := range validRefs {
		if err := git.ValidateGitRef(ref); err != nil {
			t.Errorf("ValidateGitRef(%q) returned error: %v", ref, err)
		}
	}
}

func TestValidateGitRef_Invalid(t *testing.T) {
	invalidRefs := []struct {
		ref    string
		reason string
	}{
		{"", "empty"},
		{"--version", "starts with dash (option injection)"},
		{"-n", "starts with dash"},
		{"main; rm -rf /", "shell metacharacter semicolon"},
		{"main | cat /etc/passwd", "shell metacharacter pipe"},
		{"$(whoami)", "command substitution"},
		{"main`id`", "backtick command substitution"},
		{"ref with spaces", "contains spaces"},
		{"ref\nwith\nnewlines", "contains newlines"},
		{"ref&background", "ampersand"},
	}

	for _, tc := range invalidRefs {
		if err := git.ValidateGitRef(tc.ref); err == nil {
			t.Errorf("ValidateGitRef(%q) should have failed (%s)", tc.ref, tc.reason)
		}
	}
}
