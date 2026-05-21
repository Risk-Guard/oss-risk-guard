package auditcache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

func newRun(t *testing.T) *sarif.Run {
	t.Helper()
	return sarif.NewRunWithInformationURI("test", "https://example.invalid")
}

func TestKeyDeterministic(t *testing.T) {
	a := Key("package/npm/lodash?version=1", "ph", "bh")
	b := Key("package/npm/lodash?version=1", "ph", "bh")
	if a != b {
		t.Errorf("Key not deterministic: %q vs %q", a, b)
	}
}

func TestKeyDifferentiates(t *testing.T) {
	a := Key("package/npm/lodash?version=1", "ph", "bh")
	b := Key("package/npm/lodash?version=2", "ph", "bh")
	c := Key("package/npm/lodash?version=1", "ph2", "bh")
	d := Key("package/npm/lodash?version=1", "ph", "bh2")
	if a == b || a == c || a == d {
		t.Errorf("Key collisions: a=%s b=%s c=%s d=%s", a, b, c, d)
	}
}

func TestPutGetRoundTrip(t *testing.T) {
	dir := t.TempDir()
	key := Key("package/npm/lodash?version=4.17.20", "", "")
	if err := Put(dir, key, newRun(t)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, savedAt, hit, err := Get(dir, key, time.Hour)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !hit {
		t.Fatalf("expected hit")
	}
	if got == nil {
		t.Fatalf("expected non-nil run")
	}
	if time.Since(savedAt) > time.Minute {
		t.Errorf("savedAt seems off: %v", savedAt)
	}
}

func TestGetMiss(t *testing.T) {
	dir := t.TempDir()
	_, _, hit, err := Get(dir, "deadbeef", time.Hour)
	if err != nil {
		t.Fatalf("Get on missing: %v", err)
	}
	if hit {
		t.Errorf("expected miss on empty dir")
	}
}

func TestGetExpired(t *testing.T) {
	dir := t.TempDir()
	key := Key("package/npm/lodash", "", "")
	if err := Put(dir, key, newRun(t)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	_, _, hit, err := Get(dir, key, time.Nanosecond)
	if err != nil {
		t.Fatalf("Get on expired: %v", err)
	}
	if hit {
		t.Errorf("expected expired -> miss")
	}
}

func TestGetMaxAgeZeroDisablesTTL(t *testing.T) {
	dir := t.TempDir()
	key := Key("package/npm/lodash", "", "")
	if err := Put(dir, key, newRun(t)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	_, _, hit, err := Get(dir, key, 0)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !hit {
		t.Errorf("expected hit when maxAge=0 (TTL disabled); caller must short-circuit before calling Get when --no-cache is set")
	}
}

func TestParseMaxAge(t *testing.T) {
	tests := []struct {
		in   string
		want time.Duration
		err  bool
	}{
		{"", 0, false},
		{"0", 0, false},
		{"30m", 30 * time.Minute, false},
		{"48h", 48 * time.Hour, false},
		{"2d", 48 * time.Hour, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"-5m", 0, true},
		{"bogus", 0, true},
		{"-1d", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseMaxAge(tt.in)
		if tt.err {
			if err == nil {
				t.Errorf("ParseMaxAge(%q): expected error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseMaxAge(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseMaxAge(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestPolicyHashStableOnEmpty(t *testing.T) {
	a, err := PolicyHash("", "")
	if err != nil {
		t.Fatalf("PolicyHash empty: %v", err)
	}
	b, err := PolicyHash("", "")
	if err != nil {
		t.Fatalf("PolicyHash empty 2nd: %v", err)
	}
	if a != b {
		t.Errorf("PolicyHash empty should be deterministic")
	}
}

func TestPolicyHashSensitiveToOrder(t *testing.T) {
	dir := t.TempDir()
	p1 := filepath.Join(dir, "p1.yaml")
	p2 := filepath.Join(dir, "p2.yaml")
	if err := os.WriteFile(p1, []byte("policy: a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p2, []byte("policy: b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := PolicyHash(p1, p2)
	if err != nil {
		t.Fatal(err)
	}
	b, err := PolicyHash(p2, p1)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Errorf("PolicyHash should differ when override/default swap")
	}
}

func TestBuilderHashStable(t *testing.T) {
	a := BuilderHash([]string{"CODE_A", "CODE_B"})
	b := BuilderHash([]string{"CODE_A", "CODE_B"})
	c := BuilderHash([]string{"CODE_B", "CODE_A"})
	if a != b {
		t.Errorf("BuilderHash not deterministic")
	}
	if a == c {
		t.Errorf("BuilderHash should depend on order (order represents registration order)")
	}
}
