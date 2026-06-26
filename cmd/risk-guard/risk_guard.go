package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/git"
	rghttp "github.com/Risk-Guard/oss-risk-guard/src/http"

	"github.com/fatih/color"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

const defaultRiskGuardServer = "https://ossriskguard.app"

// fetchRiskGuardReport resolves the current repo's owner/repo and commit, then fetches that run's SARIF
// from the Risk Guard server so add-expected-failures can baseline against a server-side run instead of
// a local report.
func fetchRiskGuardReport(ctx context.Context, repoPath string) (*sarif.Report, error) {
	owner, repo, ok, err := git.GetOriginOwnerRepo(ctx, repoPath)
	if err != nil {
		return nil, fmt.Errorf("resolving git origin: %w", err)
	}
	if !ok {
		fmt.Fprintln(os.Stderr, color.YellowString("Could not determine the owner/repo from the git 'origin' remote of %s.", repoPath))
		return nil, errReported
	}

	commit := addEFRiskGuardCommit
	if commit == "" {
		commit, err = git.GetHeadCommit(ctx, repoPath)
		if err != nil {
			return nil, fmt.Errorf("resolving HEAD commit: %w", err)
		}
	}

	token, err := resolveRiskGuardToken()
	if err != nil {
		return nil, err
	}

	server := resolveRiskGuardServer()
	endpoint := fmt.Sprintf("%s/api/cli/v1/runs/%s/%s/%s/sarif", server, owner, repo, commit)

	body, status, err := rghttp.GetJSONBytes(ctx, endpoint, rghttp.WithHeader("Authorization", "Bearer "+token))
	switch status {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		fmt.Fprintln(os.Stderr, color.YellowString("Risk Guard rejected the GitHub token (HTTP %d). Ensure it can read %s/%s.", status, owner, repo))
		fmt.Fprintln(os.Stderr, color.HiBlackString("Pass --token, set GITHUB_TOKEN, or run 'gh auth login'."))
		return nil, errReported
	case http.StatusNotFound:
		fmt.Fprintln(os.Stderr, color.YellowString("No Risk Guard run for %s/%s@%s.", owner, repo, shortSHA(commit)))
		fmt.Fprintln(os.Stderr, color.HiBlackString("Push the commit and let a scan finish, or pass --commit <sha> for a scanned commit."))
		return nil, errReported
	default:
		if err != nil {
			return nil, fmt.Errorf("fetching run from %s: %w", server, err)
		}
		return nil, fmt.Errorf("unexpected status %d fetching run from %s", status, server)
	}

	report, err := sarif.FromBytes(body)
	if err != nil {
		return nil, fmt.Errorf("parsing SARIF from %s: %w", server, err)
	}
	return report, nil
}

func resolveRiskGuardServer() string {
	if addEFRiskGuardServer != "" {
		return strings.TrimRight(addEFRiskGuardServer, "/")
	}
	if v := strings.TrimSpace(os.Getenv("RISK_GUARD_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return defaultRiskGuardServer
}

// resolveRiskGuardToken finds a GitHub token from, in order, --token, RISK_GUARD_TOKEN, GITHUB_TOKEN,
// GH_TOKEN, then `gh auth token`. The server verifies it against github.com.
func resolveRiskGuardToken() (string, error) {
	if addEFRiskGuardToken != "" {
		return addEFRiskGuardToken, nil
	}
	for _, name := range []string{"RISK_GUARD_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"} {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			return v, nil
		}
	}
	if tok := ghAuthToken(); tok != "" {
		return tok, nil
	}
	fmt.Fprintln(os.Stderr, color.YellowString("No GitHub token found to authenticate with Risk Guard."))
	fmt.Fprintln(os.Stderr, color.HiBlackString("Pass --token, set GITHUB_TOKEN/GH_TOKEN, or run 'gh auth login'."))
	return "", errReported
}

func ghAuthToken() string {
	out, err := exec.Command("gh", "auth", "token").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
