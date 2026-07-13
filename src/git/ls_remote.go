package git

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/common"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
)

const lsRemoteTimeout = 10 * time.Second

// safeTagVersionPattern matches a version string safe to embed in an ls-remote
// match pattern: alphanumeric plus the punctuation semver uses (dot, plus, tilde,
// underscore, hyphen for prereleases). Must not begin with a hyphen so it can
// never be mistaken for a git option.
var safeTagVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_~-]*$`)

// IsSafeTagVersion reports whether v can be embedded in a "*<version>" ls-remote
// glob without risking option injection or a malformed refspec.
func IsSafeTagVersion(v string) bool {
	return safeTagVersionPattern.MatchString(v)
}

// validTagPatternChars allows the glob metacharacter, monorepo scope characters
// (@, /), and semver punctuation. Leading-dash is rejected separately.
var validTagPatternChars = regexp.MustCompile(`^[A-Za-z0-9*][A-Za-z0-9.+_~*@/-]*$`)

// ValidateTagPattern validates a git ls-remote match pattern (a ref name or glob)
// contains only safe characters and cannot be read as a git option.
func ValidateTagPattern(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("ref pattern cannot be empty")
	}
	if strings.HasPrefix(pattern, "-") {
		return fmt.Errorf("ref pattern cannot start with dash (potential option injection): %s", pattern)
	}
	if !validTagPatternChars.MatchString(pattern) {
		return fmt.Errorf("ref pattern contains invalid characters: %s", pattern)
	}
	return nil
}

// RemoteRef is a single ref advertised by a remote: its full name (e.g.
// "refs/tags/v6.3.1") and the commit SHA it resolves to. Annotated tags are
// dereferenced so SHA is always the commit the ref ultimately points at.
type RemoteRef struct {
	Name string
	SHA  string
}

// lsRemoteRaw runs `git ls-remote <url> <ref>` and returns the trimmed stdout.
// The ref/pattern must be validated by the caller (ValidateGitRef or
// ValidateTagPattern). Returns ("", nil) when the remote advertises no match.
func lsRemoteRaw(ctx context.Context, sourceURL, ref string) (string, error) {
	if err := common.ValidateRemoteURL(sourceURL); err != nil {
		return "", fmt.Errorf("validating URL: %w", err)
	}

	lsURL := sourceURL
	if token := ctxutil.GetSourceToken(ctx); token != "" {
		var err error
		lsURL, err = embedTokenInURL(sourceURL, token)
		if err != nil {
			return "", fmt.Errorf("embedding token: %w", err)
		}
	}

	lsCtx, cancel := context.WithTimeout(ctx, lsRemoteTimeout)
	defer cancel()

	//nolint:gosec // G204: URL is validated by ValidateRemoteURL, ref validated by caller
	cmd := exec.CommandContext(lsCtx, "git", "ls-remote", lsURL, ref)
	applyGitEnv(ctx, cmd)
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	output, err := cmd.Output()
	if err != nil {
		rawErr := fmt.Errorf("git ls-remote: %s: %w", sanitizeGitOutput(stderrBuf.String()), err)
		return "", classifyCloneError(sourceURL, rawErr)
	}

	return strings.TrimSpace(string(output)), nil
}

// lsRemote runs `git ls-remote <url> <ref>` and returns the single resolved SHA.
// For tags, if both a ref and its dereferenced form (^{}) are returned, the dereferenced SHA is used.
// Returns ("", nil) when the ref exists but has no output (e.g. empty repo HEAD).
func lsRemote(ctx context.Context, sourceURL, ref string) (string, error) {
	trimmed, err := lsRemoteRaw(ctx, sourceURL, ref)
	if err != nil {
		return "", err
	}
	if trimmed == "" {
		return "", nil
	}

	// ls-remote may return multiple lines for tags (ref + ref^{}).
	// Prefer the dereferenced (^{}) line as it points to the commit SHA.
	var sha string
	for line := range strings.SplitSeq(trimmed, "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		sha = parts[0]
		if strings.HasSuffix(parts[1], "^{}") {
			break
		}
	}

	if sha == "" {
		return "", fmt.Errorf("unexpected ls-remote output: %q", trimmed)
	}
	if len(sha) != 40 {
		return "", fmt.Errorf("invalid SHA from ls-remote: %q", sha)
	}

	return sha, nil
}

// ListRemoteRefs runs `git ls-remote <url> <pattern>` and returns every matching
// ref. pattern is a git match pattern (glob) — e.g. "*6.3.1" to find any tag
// ending in that version. Annotated tags are dereferenced so each RemoteRef.SHA
// is the commit the ref points to. Returns an empty slice when nothing matches.
func ListRemoteRefs(ctx context.Context, sourceURL, pattern string) ([]RemoteRef, error) {
	if err := ValidateTagPattern(pattern); err != nil {
		return nil, fmt.Errorf("invalid ref pattern: %w", err)
	}
	trimmed, err := lsRemoteRaw(ctx, sourceURL, pattern)
	if err != nil {
		return nil, err
	}
	return parseRemoteRefs(trimmed), nil
}

// parseRemoteRefs collapses ls-remote output into one RemoteRef per ref name,
// preferring the dereferenced (^{}) commit SHA for annotated tags. Ref order is
// preserved as advertised by the remote.
func parseRemoteRefs(output string) []RemoteRef {
	if output == "" {
		return nil
	}
	shaByName := map[string]string{}
	derefd := map[string]bool{}
	var order []string
	for line := range strings.SplitSeq(output, "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		sha, name := parts[0], parts[1]
		deref := strings.HasSuffix(name, "^{}")
		base := strings.TrimSuffix(name, "^{}")
		if _, seen := shaByName[base]; !seen {
			order = append(order, base)
		}
		// Take the dereferenced commit when available; otherwise the first SHA seen.
		if deref || !derefd[base] {
			shaByName[base] = sha
		}
		if deref {
			derefd[base] = true
		}
	}
	refs := make([]RemoteRef, 0, len(order))
	for _, name := range order {
		refs = append(refs, RemoteRef{Name: name, SHA: shaByName[name]})
	}
	return refs
}

// GetRemoteHeadSHA returns the commit SHA that HEAD points to on the remote, without cloning.
// Returns ("", nil) for empty repos that have no HEAD ref.
func GetRemoteHeadSHA(ctx context.Context, sourceURL string) (string, error) {
	return lsRemote(ctx, sourceURL, "HEAD")
}

// GetRemoteRefSHA resolves an arbitrary git ref (branch, tag, commit prefix) to a full SHA via ls-remote.
func GetRemoteRefSHA(ctx context.Context, sourceURL, ref string) (string, error) {
	if err := ValidateGitRef(ref); err != nil {
		return "", fmt.Errorf("invalid git ref: %w", err)
	}

	sha, err := lsRemote(ctx, sourceURL, ref)
	if err != nil {
		return "", err
	}
	if sha == "" {
		return "", fmt.Errorf("ref %q not found on remote %s", ref, sourceURL)
	}
	return sha, nil
}
