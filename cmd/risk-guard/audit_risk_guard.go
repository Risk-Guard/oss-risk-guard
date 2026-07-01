package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"

	"github.com/Risk-Guard/oss-risk-guard/src/git"
	rghttp "github.com/Risk-Guard/oss-risk-guard/src/http"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"
	"github.com/Risk-Guard/oss-risk-guard/src/violations"

	"github.com/fatih/color"
)

// violationsToChecks turns the local source scan's violations into storage.Check records (all with
// "violation" status) so the server grades them with the org policy as the run's source-level findings,
// consistent with how it grades the dependencies.
func violationsToChecks(av *violations.AnalysisViolations) []storage.Check {
	if av == nil {
		return nil
	}
	checks := make([]storage.Check, 0, len(av.Violations))
	for _, v := range av.Violations {
		checks = append(checks, storage.Check{
			CheckCode:   v.CheckCode,
			CheckStatus: storage.StatusViolation,
			Rationale:   v.Rationale,
			Evidence:    v.Evidence,
		})
	}
	return checks
}

// uploadSBOMToRiskGuard offloads an audit: it resolves the repo's owner/repo/commit and uploads the SBOM
// (and, for a full audit, the local source-check results) to the Risk Guard server, which scores the
// dependencies asynchronously and records the run. sourceChecks is nil for a deps-only audit.
func uploadSBOMToRiskGuard(ctx context.Context, repoPath string, sbomBytes []byte, sourceChecks []storage.Check, commitOverride, tokenFlag, serverFlag string) error {
	host, owner, repo, ok, err := git.GetOriginOwnerRepo(ctx, repoPath)
	if err != nil {
		return fmt.Errorf("resolving git origin: %w", err)
	}
	if !ok {
		fmt.Fprintln(os.Stderr, color.YellowString("Could not determine the owner/repo from the git 'origin' remote of %s.", repoPath))
		return errReported
	}

	commit := commitOverride
	if commit == "" {
		commit, err = git.GetHeadCommit(ctx, repoPath)
		if err != nil {
			return fmt.Errorf("resolving HEAD commit: %w", err)
		}
	}

	token, tokenSource, err := resolveRiskGuardToken(tokenFlag)
	if err != nil {
		return err
	}

	server := resolveRiskGuardServer(serverFlag)
	endpoint := fmt.Sprintf("%s/api/cli/v1/audit?owner=%s&repo=%s&commit=%s",
		server, url.QueryEscape(owner), url.QueryEscape(repo), url.QueryEscape(commit))
	dashboard := fmt.Sprintf("%s/%s/%s/%s/statuses/%s", server, host, owner, repo, commit)

	what := "SBOM"
	if len(sourceChecks) > 0 {
		what = fmt.Sprintf("SBOM + %d source finding(s)", len(sourceChecks))
	}
	fmt.Fprintf(os.Stderr, "%s %s %s\n",
		color.HiBlackString("Uploading %s to Risk Guard:", what),
		color.CyanString("%s", dashboard),
		color.HiBlackString("(auth: %s)", tokenSource))

	body, status, err := postAudit(ctx, endpoint, sbomBytes, sourceChecks, token)
	switch status {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		fmt.Fprintln(os.Stderr, color.YellowString("Risk Guard rejected the GitHub token (HTTP %d). Ensure it can read %s/%s.", status, owner, repo))
		fmt.Fprintln(os.Stderr, color.HiBlackString("Pass --token, set GITHUB_TOKEN, or run 'gh auth login'."))
		return errReported
	default:
		if err != nil {
			return fmt.Errorf("uploading to %s: %w", server, err)
		}
		return fmt.Errorf("unexpected status %d uploading to %s", status, server)
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

// postAudit sends the payload to the front door: a raw SBOM body for a deps-only audit, or
// multipart/form-data (sbom + source_checks) when local source findings are included.
func postAudit(ctx context.Context, endpoint string, sbomBytes []byte, sourceChecks []storage.Check, token string) ([]byte, int, error) {
	auth := rghttp.WithHeader("Authorization", "Bearer "+token)
	if len(sourceChecks) == 0 {
		return rghttp.PostJSONBytes(ctx, endpoint, sbomBytes, auth)
	}

	checksJSON, err := json.Marshal(sourceChecks)
	if err != nil {
		return nil, 0, fmt.Errorf("encoding source checks: %w", err)
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, err := mw.CreateFormFile("sbom", "sbom.json")
	if err != nil {
		return nil, 0, fmt.Errorf("building multipart body: %w", err)
	}
	if _, err := part.Write(sbomBytes); err != nil {
		return nil, 0, fmt.Errorf("building multipart body: %w", err)
	}
	if err := mw.WriteField("source_checks", string(checksJSON)); err != nil {
		return nil, 0, fmt.Errorf("building multipart body: %w", err)
	}
	if err := mw.Close(); err != nil {
		return nil, 0, fmt.Errorf("building multipart body: %w", err)
	}

	return rghttp.PostMultipart(ctx, endpoint, mw.FormDataContentType(), buf.Bytes(), auth)
}
