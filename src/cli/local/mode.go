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

// resolveWorkflowMode picks the effective mode using the precedence:
// CLI --mode flag > .risk-guard.yml workflow.mode > default "active".
// repoPath is the validated git repo root used for the second tier; an
// unreadable or invalid policy file is reported as an error so we don't
// silently fall back when the user expects their config to apply.
func resolveWorkflowMode(modeOverride, repoPath string) (policy.WorkflowMode, error) {
	if modeOverride != "" {
		m := policy.WorkflowMode(modeOverride)
		switch m {
		case policy.WorkflowModeActive, policy.WorkflowModeSilent, policy.WorkflowModeDisabled:
			return m, nil
		default:
			return "", fmt.Errorf("invalid --mode %q: want active, silent, or disabled", modeOverride)
		}
	}
	if repoPath == "" {
		return policy.WorkflowModeActive, nil
	}
	raw, err := os.ReadFile(filepath.Join(repoPath, policy.PolicyFileName)) //nolint:gosec // repoPath is the validated git repo
	if err != nil {
		if os.IsNotExist(err) {
			return policy.WorkflowModeActive, nil
		}
		return "", fmt.Errorf("reading %s: %w", policy.PolicyFileName, err)
	}
	res, err := policy.LoadFullFromBytes(raw, policy.PolicyFileName)
	if err != nil {
		return "", err
	}
	if res.Policy != nil && res.Policy.Workflow != nil && res.Policy.Workflow.Mode != "" {
		return res.Policy.Workflow.Mode, nil
	}
	return policy.WorkflowModeActive, nil
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
