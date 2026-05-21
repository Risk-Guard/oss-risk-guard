// Package auditcache stores per-package SARIF Runs from the local audit
// command on disk so repeat audits over the same SBOM are fast. Each entry is
// keyed by a sha256 of (analysis identifier, policy hash, builder revision
// hash) and stored as a single JSON file under the configured cache dir.
package auditcache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

// Entry is the on-disk representation of one cached audit result. Run is
// stored as raw JSON so the cache layer doesn't have to track sarif library
// versions on round-trip.
type Entry struct {
	Key     string          `json:"key"`
	SavedAt time.Time       `json:"saved_at"`
	Run     json.RawMessage `json:"run"`
}

// Key produces the on-disk filename component for a (analysisID, policyHash,
// builderHash) tuple. analysisID is the AnalysisIdentifier from dag-impl
// (already encodes ecosystem/name/version/overrides). policyHash and
// builderHash invalidate cache entries when policy files or the registered
// check set change.
func Key(analysisID, policyHash, builderHash string) string {
	h := sha256.New()
	h.Write([]byte(analysisID))
	h.Write([]byte{0})
	h.Write([]byte(policyHash))
	h.Write([]byte{0})
	h.Write([]byte(builderHash))
	return hex.EncodeToString(h.Sum(nil))
}

// Get loads a cached Run for key if present and not older than maxAge.
// Returns (run, savedAt, true) on hit, (nil, zero, false) on miss or expiry.
// A read error other than not-found is returned to the caller — the cache is
// expected to be writable by the same user so corruption is a real signal.
func Get(dir, key string, maxAge time.Duration) (*sarif.Run, time.Time, bool, error) {
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
	var run sarif.Run
	if err := json.Unmarshal(entry.Run, &run); err != nil {
		return nil, time.Time{}, false, fmt.Errorf("decoding cached SARIF run from %s: %w", path, err)
	}
	return &run, entry.SavedAt, true, nil
}

// Put writes a Run to the cache. Creates the directory if needed.
func Put(dir, key string, run *sarif.Run) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("creating cache directory %s: %w", dir, err)
	}
	runJSON, err := json.Marshal(run)
	if err != nil {
		return fmt.Errorf("encoding SARIF run: %w", err)
	}
	entry := Entry{
		Key:     key,
		SavedAt: time.Now().UTC(),
		Run:     runJSON,
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

// BuilderHash returns a stable hash of the registered check codes from a
// builder's metadata, so a check addition/removal invalidates cached entries.
func BuilderHash(checkCodes []string) string {
	h := sha256.New()
	for _, c := range checkCodes {
		h.Write([]byte(c))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// PolicyHash returns a stable hash of two optional policy file paths' contents.
// Missing files contribute nothing; the same paths in different order produce
// different hashes (override vs default are not interchangeable).
func PolicyHash(policyOverridePath, policyDefaultPath string) (string, error) {
	h := sha256.New()
	for _, p := range []string{policyOverridePath, policyDefaultPath} {
		if p == "" {
			h.Write([]byte{0})
			continue
		}
		data, err := os.ReadFile(p) //nolint:gosec // user-provided flag
		if err != nil {
			return "", fmt.Errorf("reading policy file %s: %w", p, err)
		}
		h.Write(data)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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
