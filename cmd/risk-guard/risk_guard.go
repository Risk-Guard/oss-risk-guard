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

// fetchRiskGuardReport resolves the current repo's host/owner/repo and commit, then fetches that run's
// SARIF from the Risk Guard server so add-expected-failures can baseline against a server-side run
// instead of a local report.
func fetchRiskGuardReport(ctx context.Context, repoPath string) (*sarif.Report, error) {
	host, owner, repo, ok, err := git.GetOriginOwnerRepo(ctx, repoPath)
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

	token, tokenSource, err := resolveRiskGuardToken(addEFRiskGuardToken)
	if err != nil {
		return nil, err
	}

	server := resolveRiskGuardServer(addEFRiskGuardServer)
	endpoint := fmt.Sprintf("%s/api/cli/v1/runs/%s/%s/%s/sarif", server, owner, repo, commit)
	dashboard := fmt.Sprintf("%s/%s/%s/%s/statuses/%s", server, host, owner, repo, commit)

	fmt.Fprintf(os.Stderr, "%s %s %s\n",
		color.HiBlackString("Fetching Risk Guard run:"),
		color.CyanString("%s", dashboard),
		color.HiBlackString("(auth: %s)", tokenSource))

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

	total, errors, warnings := countResultLevels(report)
	fmt.Fprintln(os.Stderr, color.HiBlackString("Fetched %d findings: %d blocking, %d warning", total, errors, warnings))

	// Persist the fetched report so --risk-guard leaves the same on-disk artifact (with evidence) a
	// local scan would. Non-fatal: a failed save must not sink the baseline operation.
	if writeErr := writeReport(report, addEFSarif); writeErr != nil {
		fmt.Fprintln(os.Stderr, color.YellowString("Could not save SARIF to %s: %v", addEFSarif, writeErr))
	}

	return report, nil
}

func resolveRiskGuardServer(serverFlag string) string {
	if serverFlag != "" {
		return strings.TrimRight(serverFlag, "/")
	}
	if v := strings.TrimSpace(os.Getenv("RISK_GUARD_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return defaultRiskGuardServer
}

// resolveRiskGuardToken finds a GitHub token from, in order, --token, RISK_GUARD_TOKEN, GITHUB_TOKEN,
// GH_TOKEN, then `gh auth token`, returning the token and a human label for where it came from. The
// server verifies it against github.com.
func resolveRiskGuardToken(tokenFlag string) (token, source string, err error) {
	if tokenFlag != "" {
		return tokenFlag, "--token", nil
	}
	for _, name := range []string{"RISK_GUARD_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"} {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			return v, "$" + name, nil
		}
	}
	if tok := ghAuthToken(); tok != "" {
		return tok, "gh auth token", nil
	}
	fmt.Fprintln(os.Stderr, color.YellowString("No GitHub token found to authenticate with Risk Guard."))
	fmt.Fprintln(os.Stderr, color.HiBlackString("Pass --token, set GITHUB_TOKEN/GH_TOKEN, or run 'gh auth login'."))
	return "", "", errReported
}

func ghAuthToken() string {
	out, err := exec.Command("gh", "auth", "token").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func countResultLevels(report *sarif.Report) (total, errors, warnings int) {
	for _, run := range report.Runs {
		for _, res := range run.Results {
			total++
			if res.Level == nil {
				continue
			}
			switch *res.Level {
			case "error":
				errors++
			case "warning":
				warnings++
			}
		}
	}
	return total, errors, warnings
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
