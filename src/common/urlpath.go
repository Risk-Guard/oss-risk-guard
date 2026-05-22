package common

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Known hosts that support HTTPS for git operations
var knownHTTPSHosts = []string{
	"github.com",
	"gitlab.com",
	"bitbucket.org",
	"codeberg.org",
}

// Matches git@{hostname}:{path}
var scpStylePattern = regexp.MustCompile(`^git@([^:]+):(.+)$`)

// ExtractOwnerRepo extracts the first two path segments (owner/repo) from a URL path.
// Handles any trailing path segments (tree/blob/commit/etc) by ignoring them.
func ExtractOwnerRepo(urlPath string) (owner, repo string, ok bool) {
	pathStr := strings.TrimPrefix(urlPath, "/")
	parts := strings.SplitN(pathStr, "/", 3) // at most 3 parts
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	repo = strings.TrimSuffix(parts[1], ".git")
	return parts[0], repo, true
}

func NormalizeSourceURL(sourceURL string) string {
	if strings.Contains(sourceURL, "://") {
		parsed, err := url.Parse(sourceURL)
		if err != nil {
			return sourceURL
		}
		// Upgrade http:// to https:// for known hosts
		if parsed.Scheme == "http" && slices.Contains(knownHTTPSHosts, parsed.Host) {
			parsed.Scheme = "https"
		}
		if slices.Contains(knownHTTPSHosts, parsed.Host) {
			owner, repo, ok := ExtractOwnerRepo(parsed.Path)
			if !ok {
				return sourceURL
			}
			return "https://" + parsed.Host + "/" + owner + "/" + repo
		}
		return sourceURL
	}

	// Parse git@{hostname}:{path} (SCP-style SSH)
	if match := scpStylePattern.FindStringSubmatch(sourceURL); match != nil {
		host := match[1]
		pathStr := match[2]
		if slices.Contains(knownHTTPSHosts, host) {
			owner, repo, ok := ExtractOwnerRepo(pathStr)
			if !ok {
				return sourceURL
			}
			return "https://" + host + "/" + owner + "/" + repo
		}
	}

	return sourceURL
}

func IsLocalPath(input string) (bool, error) {
	input = strings.TrimSpace(input)

	if input == "" {
		return false, fmt.Errorf("empty path")
	}

	// Check for explicit URL schemes (secure format)
	if strings.Contains(input, "://") {
		// Remote URL with explicit scheme
		return false, nil
	}

	// Accept explicit local paths
	if strings.HasPrefix(input, "/") || // absolute unix path
		strings.HasPrefix(input, "./") || // relative path
		strings.HasPrefix(input, "../") { // relative parent path
		return true, nil
	}

	// Reject anything else as ambiguous
	return false, fmt.Errorf("ambiguous path format - use explicit scheme (https://...) or local path (/path, ./path, ../path)")
}
