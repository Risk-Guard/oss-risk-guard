package git

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyGitCeiling_SetsAbsolutePath(t *testing.T) {
	cmd := exec.Command("git", "status")
	applyGitCeiling(cmd, "scratch/clones/pkg")

	want := "GIT_CEILING_DIRECTORIES="
	var got string
	for _, e := range cmd.Env {
		if v, ok := strings.CutPrefix(e, want); ok {
			got = v
		}
	}
	if got == "" {
		t.Fatalf("expected GIT_CEILING_DIRECTORIES to be set; cmd.Env=%v", cmd.Env)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("ceiling must be absolute, got %q", got)
	}
}

func TestApplyGitCeiling_AppendsToExistingEnv(t *testing.T) {
	cmd := exec.Command("git", "status")
	cmd.Env = []string{"FOO=bar"}
	applyGitCeiling(cmd, "/tmp/destdir")

	if len(cmd.Env) != 2 {
		t.Fatalf("expected env to be appended (len=2), got %v", cmd.Env)
	}
	if cmd.Env[0] != "FOO=bar" {
		t.Errorf("existing env stripped: %v", cmd.Env)
	}
	if !strings.HasPrefix(cmd.Env[1], "GIT_CEILING_DIRECTORIES=") {
		t.Errorf("ceiling not appended: %v", cmd.Env)
	}
}
