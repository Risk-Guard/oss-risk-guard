package git

import (
	"net/url"
	"strings"
)

// VCSType represents the type of version control system
type VCSType string

const (
	VCSTypeGit     VCSType = "git"
	VCSTypeBazaar  VCSType = "bazaar"
	VCSTypeSVN     VCSType = "svn"
	VCSTypeMercur  VCSType = "mercurial"
	VCSTypeUnknown VCSType = "unknown"
)

// DetectVCSFromURL attempts to determine the VCS type from a repository URL
// Returns the detected VCS type and whether it's supported by Risk Guard
// Assumes Git unless a known non-Git alternative is detected
func DetectVCSFromURL(urlStr string) (vcsType VCSType, supported bool) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		// If we can't parse the URL, assume Git
		return VCSTypeGit, true
	}

	hostname := strings.ToLower(parsed.Hostname())

	// Bazaar (Launchpad)
	if strings.HasSuffix(hostname, "launchpad.net") {
		return VCSTypeBazaar, false
	}

	// Assume Git for everything else
	return VCSTypeGit, true
}

// GetVCSName returns a human-readable name for the VCS type
func GetVCSName(vcsType VCSType) string {
	switch vcsType {
	case VCSTypeGit:
		return "Git"
	case VCSTypeBazaar:
		return "Bazaar"
	case VCSTypeSVN:
		return "Subversion"
	case VCSTypeMercur:
		return "Mercurial"
	case VCSTypeUnknown:
		return "Unknown"
	default:
		return string(vcsType)
	}
}
