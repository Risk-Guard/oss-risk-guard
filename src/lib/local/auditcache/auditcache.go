// Package auditcache stores per-package raw violations from the local audit
// pipeline on disk so repeat audits over the same SBOM are fast. Each entry
// is keyed by a sha256 of the analysis identifier alone and stored as a
// single JSON file under the configured cache dir.
//
// The cache holds raw violations (pre-grading), not graded SARIF, so editing
// .risk-guard.yml does not invalidate any entry. The rulebook is applied
// once at merge time, against the union of all cached violations. Cross-
// project sharing is therefore safe: the same package@version cached by one
// project is reused by every other project pinning the same version.
package auditcache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/violations"
)

// Entry is the on-disk representation of one cached audit result.
type Entry struct {
	Key      string                         `json:"key"`
	SavedAt  time.Time                      `json:"saved_at"`
	Analysis *violations.AnalysisViolations `json:"analysis"`
}

// Key produces the on-disk filename component for an analysisID. The
// identifier already encodes ecosystem, name, version, and overrides, so no
// other input is needed to disambiguate two entries.
func Key(analysisID string) string {
	h := sha256.New()
	h.Write([]byte(analysisID))
	return hex.EncodeToString(h.Sum(nil))
}

// Get loads cached violations for key if present and not older than maxAge.
// Returns (analysis, savedAt, true) on hit, (nil, zero, false) on miss or
// expiry. A read error other than not-found is returned to the caller —
// the cache is expected to be writable by the same user so corruption is a
// real signal.
func Get(dir, key string, maxAge time.Duration) (*violations.AnalysisViolations, time.Time, bool, error) {
	path := filepath.Join(dir, key+".json")
	data, err := os.ReadFile(path) //nolint:gosec // dir is operator-controlled
	if err != nil {
		if os.IsNotExist(err) {
			return nil, time.Time{}, false, nil
		}
		return nil, time.Time{}, false, fmt.Errorf("reading cache entry %s: %w", path, err)
	}
	var entry Entry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, time.Time{}, false, fmt.Errorf("decoding cache entry %s: %w", path, err)
	}
	if maxAge > 0 && time.Since(entry.SavedAt) > maxAge {
		return nil, entry.SavedAt, false, nil
	}
	return entry.Analysis, entry.SavedAt, true, nil
}

// Put writes a violations result to the cache. Creates the directory if needed.
func Put(dir, key string, analysis *violations.AnalysisViolations) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("creating cache directory %s: %w", dir, err)
	}
	entry := Entry{
		Key:      key,
		SavedAt:  time.Now().UTC(),
		Analysis: analysis,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encoding cache entry: %w", err)
	}
	path := filepath.Join(dir, key+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing cache entry %s: %w", path, err)
	}
	return nil
}

// ParseMaxAge accepts time.ParseDuration syntax plus "Nd" (days). Returns 0
// for empty/zero (caller should treat 0 as "no caching").
func ParseMaxAge(s string) (time.Duration, error) {
	if s == "" || s == "0" {
		return 0, nil
	}
	if n := len(s); n > 1 && s[n-1] == 'd' {
		var days int
		if _, err := fmt.Sscanf(s[:n-1], "%d", &days); err != nil || days < 0 {
			return 0, fmt.Errorf("invalid days value in --max-age %q", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid --max-age %q: %w", s, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("--max-age must be non-negative, got %q", s)
	}
	return d, nil
}
