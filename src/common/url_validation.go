package common

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// ValidateRemoteURL validates that a URL is safe for git clone operations.
// This MUST be called on ALL URLs from untrusted sources (package metadata).
//
// Security policy: ONLY https:// URLs are accepted.
// - http:// is rejected (insecure)
// - git://, ssh://, git@ are rejected (not supported)
// - file:// is rejected (security risk)
// - localhost/loopback addresses are rejected (security risk)
// - URLs with git command flags are rejected (command injection risk)
// - URLs with path traversal are rejected (security risk)
// ValidateAndNormalizeURL validates the raw URL, normalizes it, then validates the normalized form.
// Returns:
//   - normalized: the normalized URL (always set on success)
//   - finding: non-nil if the raw URL used an unsafe protocol that was normalized away
//   - err: non-nil only when both raw and normalized URLs fail validation (hard rejection)
func ValidateAndNormalizeURL(rawURL string) (normalized string, finding *string, err error) {
	rawErr := ValidateRemoteURL(rawURL)
	normalized = NormalizeSourceURL(rawURL)

	if rawErr != nil {
		if normErr := ValidateRemoteURL(normalized); normErr != nil {
			return normalized, nil, normErr
		}
		f := rawErr.Error()
		return normalized, &f, nil
	}
	return normalized, nil, nil
}

func ValidateRemoteURL(sourceURL string) error {
	if sourceURL == "" {
		return fmt.Errorf("empty URL")
	}

	// 1. Check for required protocol
	if !strings.Contains(sourceURL, "://") {
		// Special case: git@ is not supported
		if strings.HasPrefix(sourceURL, "git@") {
			return fmt.Errorf("git@ SSH URLs not supported (use https:// instead)")
		}
		return fmt.Errorf("invalid URL: missing protocol (use https://)")
	}

	// 2. Explicitly reject file:// protocol (case-insensitive)
	lowerURL := strings.ToLower(sourceURL)
	if strings.HasPrefix(lowerURL, "file://") {
		return fmt.Errorf("file:// protocol not allowed")
	}

	// 3. Parse URL safely
	parsed, err := url.Parse(sourceURL)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	// 4. STRICT: Only allow https:// and git+https:// protocols
	if parsed.Scheme != "https" && parsed.Scheme != "git+https" {
		switch parsed.Scheme {
		case "http":
			return fmt.Errorf("http:// is insecure (use https:// instead)")
		case "git+http":
			return fmt.Errorf("git+http:// is insecure (use git+https:// or https:// instead)")
		case "git":
			return fmt.Errorf("git:// protocol not supported (use https:// instead)")
		case "ssh":
			return fmt.Errorf("ssh:// protocol not supported (use https:// instead)")
		case "ftp":
			return fmt.Errorf("ftp:// protocol not supported (use https:// instead)")
		default:
			return fmt.Errorf("unsupported protocol: %s (only https:// is allowed)", parsed.Scheme)
		}
	}

	// 5. Reject localhost/loopback addresses
	if isLocalhost(parsed.Host) {
		return fmt.Errorf("localhost URLs not allowed")
	}

	// 6. Check for git command injection (space followed by dashes)
	if strings.Contains(sourceURL, " --") {
		return fmt.Errorf("invalid URL: contains git flags (potential command injection)")
	}

	// 7. Check for path traversal
	if strings.Contains(parsed.Path, "..") {
		return fmt.Errorf("invalid URL: path traversal detected")
	}

	// 8. Reject URLs with null bytes or other suspicious characters
	if strings.ContainsRune(sourceURL, '\x00') {
		return fmt.Errorf("invalid URL: contains null byte")
	}

	return nil
}

// isLocalhost checks if a host string refers to localhost or loopback addresses.
// Supports: localhost, 127.0.0.1, ::1, 0.0.0.0
// Also handles hosts with ports (e.g., "localhost:8080")
func isLocalhost(host string) bool {
	// Strip port if present
	hostname := host

	// Check if this is an IPv6 address (contains brackets)
	if strings.Contains(host, "[") && strings.Contains(host, "]") {
		// Extract hostname from [ipv6]:port format
		if closeBracket := strings.Index(host, "]"); closeBracket != -1 {
			hostname = host[1:closeBracket]
		}
	} else if colonIdx := strings.LastIndex(host, ":"); colonIdx != -1 {
		// For IPv4/hostname with port, strip the port
		// But only if it's not IPv6 without brackets (::1)
		// IPv6 addresses have multiple colons
		if strings.Count(host, ":") == 1 {
			// Single colon = IPv4/hostname with port
			hostname = host[:colonIdx]
		}
		// If multiple colons and no brackets, it's IPv6 without port (like ::1)
	}

	// List of localhost identifiers
	localhosts := []string{
		"localhost",
		"127.0.0.1",
		"::1",
		"0.0.0.0",
		"",
	}

	// Check exact match
	if slices.Contains(localhosts, hostname) {
		return true
	}

	// Check for 127.x.x.x range
	if strings.HasPrefix(hostname, "127.") {
		return true
	}

	return false
}
