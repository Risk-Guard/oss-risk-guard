package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Risk-Guard/oss-risk-guard/src/policy"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

// errBlockingFindings is returned by runAll when SARIF results contain at least
// one error-level finding and the effective workflow mode is active. main()
// distinguishes this from operational errors so it can exit 1 without printing
// "Error: …" — the GitHub annotations already explained what failed.
var errBlockingFindings = errors.New("blocking findings detected")

// loadRepoPolicy reads and compiles .risk-guard.yml from the validated repo
// root. Returns (nil, nil, nil) when the file does not exist — callers should
// treat that as "use defaults" rather than an error. The raw bytes are returned
// alongside the LoadResult because policy_loader's Output carries both.
func loadRepoPolicy(repoPath string) (*policy.LoadResult, []byte, error) {
	if repoPath == "" {
		return nil, nil, nil
	}
	raw, err := os.ReadFile(filepath.Join(repoPath, policy.PolicyFileName)) //nolint:gosec // repoPath is the validated git repo
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("reading %s: %w", policy.PolicyFileName, err)
	}
	res, err := policy.LoadFullFromBytes(raw, policy.PolicyFileName)
	if err != nil {
		return nil, nil, err
	}
	return res, raw, nil
}

// resolveWorkflowMode picks the effective mode using the precedence:
// CLI --mode flag > .risk-guard.yml workflow.mode > default "active".
// repoPath is the validated git repo root used for the second tier; an
// unreadable or invalid policy file is reported as an error so we don't
// silently fall back when the user expects their config to apply.
func resolveWorkflowMode(modeOverride, repoPath string) (policy.WorkflowMode, error) {
	if modeOverride != "" {
		m := policy.WorkflowMode(modeOverride)
		if !policy.IsValidWorkflowMode(m) {
			return "", fmt.Errorf("invalid --mode %q: want active, no-fail, silent, or disabled", modeOverride)
		}
		return m, nil
	}
	res, _, err := loadRepoPolicy(repoPath)
	if err != nil {
		return "", err
	}
	if res == nil || res.Policy == nil || res.Policy.Workflow == nil || res.Policy.Workflow.Mode == "" {
		return policy.WorkflowModeActive, nil
	}
	m := res.Policy.Workflow.Mode
	if !policy.IsValidWorkflowMode(m) {
		// LoadFullFromBytes accepts any string for workflow.mode; reject typos
		// here so blocking findings still fail the build instead of silently
		// being treated as an unknown (effectively no-fail) mode.
		return "", fmt.Errorf("%s: invalid workflow.mode %q: want active, no-fail, silent, or disabled", policy.PolicyFileName, m)
	}
	return m, nil
}

// emitsAnnotations reports whether the effective mode should render GitHub
// Actions annotations to stdout. silent and disabled suppress annotations even
// when --github is set; active and no-fail emit them.
func emitsAnnotations(m policy.WorkflowMode) bool {
	return m == policy.WorkflowModeActive || m == policy.WorkflowModeNoFail
}

// failsOnBlocking reports whether the effective mode causes the CLI to exit
// non-zero when any SARIF result has level=error. Only active fails; no-fail,
// silent, and disabled never do.
func failsOnBlocking(m policy.WorkflowMode) bool {
	return m == policy.WorkflowModeActive
}

// reportHasErrorLevel returns true if any SARIF result is error-level. The
// audit pipeline already maps policy severity "blocking" to SARIF level
// "error", so this is the post-policy view of what should fail the run.
func reportHasErrorLevel(report *sarif.Report) bool {
	if report == nil {
		return false
	}
	for _, run := range report.Runs {
		for _, res := range run.Results {
			if res.Level != nil && *res.Level == "error" {
				return true
			}
		}
	}
	return false
}
