package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlatformDefaultCacheDir(t *testing.T) {
	got := platformDefaultCacheDir()
	base, err := os.UserCacheDir()
	if err != nil {
		if got != "" {
			t.Errorf("expected empty when UserCacheDir is unavailable, got %q", got)
		}
		return
	}
	if want := filepath.Join(base, "risk-guard"); got != want {
		t.Errorf("platformDefaultCacheDir() = %q, want %q", got, want)
	}
}

func TestResolveCacheDir_FlagWins(t *testing.T) {
	t.Setenv("RISK_GUARD_CACHE_DIR", "/env/cache")
	got, err := resolveCacheDir("/flag/cache")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/flag/cache" {
		t.Errorf("flag should win, got %q", got)
	}
}

func TestResolveCacheDir_EnvFallback(t *testing.T) {
	t.Setenv("RISK_GUARD_CACHE_DIR", "/env/cache")
	got, err := resolveCacheDir("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/env/cache" {
		t.Errorf("env should be used when flag empty, got %q", got)
	}
}

func TestResolveCacheDir_UserCacheDefault(t *testing.T) {
	t.Setenv("RISK_GUARD_CACHE_DIR", "")
	got, err := resolveCacheDir("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "risk-guard") {
		t.Errorf("default should include risk-guard, got %q", got)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("default should be absolute, got %q", got)
	}
	if _, err := os.UserCacheDir(); err == nil {
		base, _ := os.UserCacheDir()
		if !strings.HasPrefix(got, base) {
			t.Errorf("default should be under UserCacheDir %q, got %q", base, got)
		}
	}
}
