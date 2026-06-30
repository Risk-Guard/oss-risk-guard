package git

import (
	"context"
	"net/url"

	"github.com/Risk-Guard/oss-risk-guard/src/common"
)

// GetOriginOwnerRepo resolves the host (e.g. github.com), owner, and repo from the repo's git "origin"
// remote, handling both SSH (git@host:owner/repo.git) and HTTPS remote forms. ok is false when no origin
// is configured or the remote is not an owner/repo URL (e.g. a local-path remote).
func GetOriginOwnerRepo(ctx context.Context, repoPath string) (host, owner, repo string, ok bool, err error) {
	raw, found, err := getRemoteURL(ctx, repoPath)
	if err != nil {
		return "", "", "", false, err
	}
	if !found {
		return "", "", "", false, nil
	}

	parsed, err := url.Parse(common.NormalizeSourceURL(raw))
	if err != nil {
		return "", "", "", false, nil
	}

	owner, repo, ok = common.ExtractOwnerRepo(parsed.Path)
	return parsed.Host, owner, repo, ok, nil
}
