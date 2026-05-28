package auditcache

import (
	"testing"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/violations"
)

func newAnalysis(t *testing.T, id string) *violations.AnalysisViolations {
	t.Helper()
	return &violations.AnalysisViolations{
		AnalysisID: id,
		Violations: []violations.Violation{{CheckCode: "TEST_CHECK", Rationale: "test"}},
	}
}

func TestKeyDeterministic(t *testing.T) {
	a := Key("package/npm/lodash?version=1")
	b := Key("package/npm/lodash?version=1")
	if a != b {
		t.Errorf("Key not deterministic: %q vs %q", a, b)
	}
}

func TestKeyDifferentiates(t *testing.T) {
	a := Key("package/npm/lodash?version=1")
	b := Key("package/npm/lodash?version=2")
	if a == b {
		t.Errorf("Key collisions: a=%s b=%s", a, b)
	}
}

func TestPutGetRoundTrip(t *testing.T) {
	dir := t.TempDir()
	id := "package/npm/lodash?version=4.17.20"
	key := Key(id)
	if err := Put(dir, key, newAnalysis(t, id)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, savedAt, hit, err := Get(dir, key, time.Hour)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !hit {
		t.Fatalf("expected hit")
	}
	if got == nil || got.AnalysisID != id {
		t.Fatalf("got %+v, want AnalysisID=%q", got, id)
	}
	if len(got.Violations) != 1 || got.Violations[0].CheckCode != "TEST_CHECK" {
		t.Errorf("violations did not survive round trip: %+v", got.Violations)
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
	id := "package/npm/lodash"
	key := Key(id)
	if err := Put(dir, key, newAnalysis(t, id)); err != nil {
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
	id := "package/npm/lodash"
	key := Key(id)
	if err := Put(dir, key, newAnalysis(t, id)); err != nil {
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
