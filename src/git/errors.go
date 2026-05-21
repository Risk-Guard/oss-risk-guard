package git

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// validGitRefPattern matches valid git ref characters: alphanumeric, hyphens, underscores, slashes, dots.
// Rejects shell metacharacters, spaces, and git option flags (--).
var validGitRefPattern = regexp.MustCompile(`^[a-zA-Z0-9._/-]+$`)

// ValidateGitRef validates that a git ref (commit, tag, branch) contains only safe characters.
func ValidateGitRef(ref string) error {
	if ref == "" {
		return fmt.Errorf("git ref cannot be empty")
	}
	if strings.HasPrefix(ref, "-") {
		return fmt.Errorf("git ref cannot start with dash (potential option injection): %s", ref)
	}
	if !validGitRefPattern.MatchString(ref) {
		return fmt.Errorf("git ref contains invalid characters: %s", ref)
	}
	return nil
}

type CloneError struct {
	URL       string
	Type      string
	Message   string
	GitOutput string
	Err       error
}

func (e *CloneError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Type, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

func (e *CloneError) Unwrap() error {
	return e.Err
}

func isValidProtocol(url string) bool {
	validPrefixes := []string{"https://", "http://", "git://", "ssh://", "git@"}
	for _, prefix := range validPrefixes {
		if strings.HasPrefix(url, prefix) {
			return true
		}
	}
	return false
}

// sanitizeGitOutput removes sensitive data (tokens, credentials) from git output.
var tokenPattern = regexp.MustCompile(`(https?://)[^@\s]+@`)

func sanitizeGitOutput(output string) string {
	return tokenPattern.ReplaceAllString(output, "${1}[REDACTED]@")
}

// extractGitErrorLine extracts the most relevant error line from git output.
func extractGitErrorLine(output string) string {
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "fatal:") || strings.Contains(lower, "error:") {
			if trimmed := strings.TrimSpace(line); trimmed != "" {
				return trimmed
			}
		}
	}

	for i := len(lines) - 1; i >= 0; i-- {
		if trimmed := strings.TrimSpace(lines[i]); trimmed != "" {
			return trimmed
		}
	}

	return ""
}

func classifyCloneError(url string, err error) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()
	errLower := strings.ToLower(errStr)
	sanitizedOutput := sanitizeGitOutput(extractGitErrorLine(errStr))

	if err == context.DeadlineExceeded {
		return &CloneError{
			URL:       url,
			Type:      ErrTypeTimeout,
			Message:   fmt.Sprintf("clone operation timed out after %v", MaxCloneTime),
			GitOutput: sanitizedOutput,
			Err:       err,
		}
	}

	// Check permanent DNS errors (domain doesn't exist)
	permanentDNSPatterns := []string{
		"could not resolve host",
		"name or service not known",
	}

	for _, pattern := range permanentDNSPatterns {
		if strings.Contains(errLower, pattern) {
			return &CloneError{
				URL:       url,
				Type:      ErrTypeNotFound,
				Message:   "host not found (DNS lookup failed)",
				GitOutput: sanitizedOutput,
				Err:       err,
			}
		}
	}

	// Check transient network errors BEFORE "not found" patterns
	transientPatterns := []string{
		"connection refused",
		"connection reset by peer",
		"connection timed out",
		"temporary failure in name resolution",
		"network is unreachable",
		"no route to host",
		"failed to connect",
		"ssl handshake",
		"tls handshake",
		"gnutls_handshake",
		"couldn't connect to server",
	}

	for _, pattern := range transientPatterns {
		if strings.Contains(errLower, pattern) {
			return &CloneError{
				URL:       url,
				Type:      ErrTypeNetworkTransient,
				Message:   "transient network error",
				GitOutput: sanitizedOutput,
				Err:       err,
			}
		}
	}

	if strings.Contains(errLower, "not found") ||
		strings.Contains(errLower, "repository not found") ||
		strings.Contains(errLower, "404") {
		// Check if this might be an unsupported VCS instead of a truly missing repo
		vcsType, supported := DetectVCSFromURL(url)
		if !supported && vcsType != VCSTypeUnknown {
			return &CloneError{
				URL:       url,
				Type:      ErrTypeUnsupportedVCS,
				Message:   fmt.Sprintf("repository uses %s version control, only Git is supported", GetVCSName(vcsType)),
				GitOutput: sanitizedOutput,
				Err:       err,
			}
		}

		return &CloneError{
			URL:       url,
			Type:      ErrTypeNotFound,
			Message:   "repository not found (404)",
			GitOutput: sanitizedOutput,
			Err:       err,
		}
	}

	if strings.Contains(errLower, "authentication required") ||
		strings.Contains(errLower, "authentication failed") ||
		strings.Contains(errLower, "could not read username") ||
		strings.Contains(errLower, "terminal prompts disabled") ||
		strings.Contains(errLower, "401") ||
		strings.Contains(errLower, "403") {
		return &CloneError{
			URL:       url,
			Type:      ErrTypePrivateRepo,
			Message:   "authentication required (private repository)",
			GitOutput: sanitizedOutput,
			Err:       err,
		}
	}

	// Generic git error
	return &CloneError{
		URL:       url,
		Type:      ErrTypeOther,
		Message:   "git clone failed",
		GitOutput: sanitizedOutput,
		Err:       err,
	}
}
