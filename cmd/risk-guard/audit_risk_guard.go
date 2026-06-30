package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/Risk-Guard/oss-risk-guard/src/git"
	rghttp "github.com/Risk-Guard/oss-risk-guard/src/http"

	"github.com/fatih/color"
)

// uploadAuditToRiskGuard offloads a deps audit: it resolves the repo's owner/repo/commit, uploads the
// SBOM to the Risk Guard server, and prints the dashboard URL. The server ingests the SBOM and scores
// its dependencies asynchronously; the result is then readable by `policy add-expected-failures
// --risk-guard` and rendered on the dashboard.
func uploadAuditToRiskGuard(ctx context.Context, repoPath string, sbomBytes []byte) error {
	host, owner, repo, ok, err := git.GetOriginOwnerRepo(ctx, repoPath)
	if err != nil {
		return fmt.Errorf("resolving git origin: %w", err)
	}
	if !ok {
		fmt.Fprintln(os.Stderr, color.YellowString("Could not determine the owner/repo from the git 'origin' remote of %s.", repoPath))
		return errReported
	}

	commit := auditRGCommit
	if commit == "" {
		commit, err = git.GetHeadCommit(ctx, repoPath)
		if err != nil {
			return fmt.Errorf("resolving HEAD commit: %w", err)
		}
	}

	token, tokenSource, err := resolveRiskGuardToken(auditRGToken)
	if err != nil {
		return err
	}

	server := resolveRiskGuardServer(auditRGServer)
	endpoint := fmt.Sprintf("%s/api/cli/v1/audit?owner=%s&repo=%s&commit=%s",
		server, url.QueryEscape(owner), url.QueryEscape(repo), url.QueryEscape(commit))
	dashboard := fmt.Sprintf("%s/%s/%s/%s/statuses/%s", server, host, owner, repo, commit)

	fmt.Fprintf(os.Stderr, "%s %s %s\n",
		color.HiBlackString("Uploading SBOM to Risk Guard:"),
		color.CyanString("%s", dashboard),
		color.HiBlackString("(auth: %s)", tokenSource))

	body, status, err := rghttp.PostJSONBytes(ctx, endpoint, sbomBytes, rghttp.WithHeader("Authorization", "Bearer "+token))
	switch status {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		fmt.Fprintln(os.Stderr, color.YellowString("Risk Guard rejected the GitHub token (HTTP %d). Ensure it can read %s/%s.", status, owner, repo))
		fmt.Fprintln(os.Stderr, color.HiBlackString("Pass --token, set GITHUB_TOKEN, or run 'gh auth login'."))
		return errReported
	default:
		if err != nil {
			return fmt.Errorf("uploading SBOM to %s: %w", server, err)
		}
		return fmt.Errorf("unexpected status %d uploading SBOM to %s", status, server)
	}

	var resp struct {
		Key    string `json:"key"`
		RunURL string `json:"runUrl"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("parsing Risk Guard response: %w", err)
	}

	runURL := resp.RunURL
	if runURL == "" {
		runURL = dashboard
	}
	fmt.Fprintln(os.Stderr, color.HiBlackString("Audit started — dependencies are scored on the server asynchronously."))
	fmt.Fprintf(os.Stderr, "%s %s\n", color.HiBlackString("View results:"), color.CyanString("%s", runURL))
	return nil
}
