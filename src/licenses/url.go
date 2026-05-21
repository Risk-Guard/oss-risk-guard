package licenses

import (
	"fmt"
	"net/url"
	"strings"
)

func encodePathSegments(path string) string {
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		segments[i] = url.PathEscape(seg)
	}
	return strings.Join(segments, "/")
}

func ConstructTextURL(sourceURL *string, commit, path string) *string {
	if sourceURL == nil || *sourceURL == "" {
		sentinel := "<unsupported>"
		return &sentinel
	}

	parsed, err := url.Parse(*sourceURL)
	if err != nil {
		sentinel := "<unsupported>"
		return &sentinel
	}

	host := strings.ToLower(parsed.Host)
	pathParts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(pathParts) < 2 {
		sentinel := "<unsupported>"
		return &sentinel
	}
	owner, repo := pathParts[0], pathParts[1]

	encodedPath := encodePathSegments(path)

	var rawURL string
	switch {
	case strings.Contains(host, "github.com"):
		rawURL = fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", owner, repo, commit, encodedPath)
	case strings.Contains(host, "gitlab.com"):
		rawURL = fmt.Sprintf("https://gitlab.com/%s/%s/-/raw/%s/%s", owner, repo, commit, encodedPath)
	case strings.Contains(host, "bitbucket.org"):
		rawURL = fmt.Sprintf("https://bitbucket.org/%s/%s/raw/%s/%s", owner, repo, commit, encodedPath)
	default:
		sentinel := "<unsupported>"
		return &sentinel
	}
	return &rawURL
}
