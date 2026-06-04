package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/git"

	"github.com/charmbracelet/huh"
	"github.com/fatih/color"
)

// CI snippets Risk Guard knows how to wire in. The GitHub one is a complete
// workflow (name + on + jobs) — the bare jobs: block won't run on its own. The
// GitLab one is a component include that merges into an existing .gitlab-ci.yml.
const (
	githubCIWorkflow = `name: Risk Guard
on:
  pull_request:
  push:
    branches: [main]
jobs:
  risk-guard:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v6
      - uses: Risk-Guard/action@v1
`

	gitlabCISnippet = `include:
  - component: $CI_SERVER_FQDN/risk-guard/components/scan@1.0.3
`
)

// Substrings that mark a CI file as already wired to Risk Guard, so init doesn't
// re-print a snippet the user already has.
const (
	githubCIMarker = "Risk-Guard/action"
	gitlabCIMarker = "risk-guard/components/scan"
)

// offerCIIntegration detects the repo's CI and prints a ready-to-paste Risk Guard
// snippet for it. It never writes files — wiring CI is the user's call, and
// merging into an existing pipeline safely is theirs to do. When no CI is
// detected it asks which platform they use and prints that snippet. Callers gate
// this on isInteractive() (the no-CI path prompts).
func offerCIIntegration(repoPath string) error {
	ghPath := firstExisting(repoPath, git.CIProviders["GitHub Actions"].Paths)
	glPath := firstExisting(repoPath, git.CIProviders["GitLab CI"].Paths)

	if ghPath == "" && glPath == "" {
		return promptNoCIPlatform()
	}

	fmt.Fprintln(os.Stderr)
	if ghPath != "" {
		if ciAlreadyIntegrated(repoPath, ghPath, githubCIMarker) {
			echoGroupDone("Risk Guard is already wired into your GitHub Actions")
		} else {
			printCISnippet("Add Risk Guard to GitHub Actions — save as .github/workflows/risk-guard.yml:", githubCIWorkflow)
		}
	}
	if glPath != "" {
		if ciAlreadyIntegrated(repoPath, glPath, gitlabCIMarker) {
			echoGroupDone("Risk Guard is already wired into your GitLab CI")
		} else {
			printCISnippet("Add Risk Guard to GitLab CI — add to your .gitlab-ci.yml:", gitlabCISnippet)
		}
	}
	return nil
}

// promptNoCIPlatform asks which CI the user runs when none is detected, then
// prints that platform's snippet. Skipping prints nothing actionable.
func promptNoCIPlatform() error {
	var choice string
	if err := huh.NewSelect[string]().
		Title("No CI detected. Want to run Risk Guard in CI?").
		Description("Pick your platform to print a ready-to-paste snippet.\n↑/↓ to move · enter to confirm").
		Options(
			huh.NewOption("GitHub Actions", "github"),
			huh.NewOption("GitLab CI", "gitlab"),
			huh.NewOption("Skip — I'll set it up later", "skip"),
		).
		Value(&choice).
		Run(); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr)
	switch choice {
	case "github":
		printCISnippet("Add Risk Guard to GitHub Actions — save as .github/workflows/risk-guard.yml:", githubCIWorkflow)
	case "gitlab":
		printCISnippet("Add Risk Guard to GitLab CI — create .gitlab-ci.yml with:", gitlabCISnippet)
	default:
		echoGroupDone("Skipped CI setup")
	}
	return nil
}

// printCISnippet prints a bold instruction line followed by the indented, cyan
// snippet body, so it stands out as copy-paste-ready text in the scrollback.
func printCISnippet(title, body string) {
	fmt.Fprintln(os.Stderr, color.New(color.Bold).Sprint(title))
	fmt.Fprintln(os.Stderr)
	for line := range strings.SplitSeq(strings.TrimRight(body, "\n"), "\n") {
		if line == "" {
			fmt.Fprintln(os.Stderr)
			continue
		}
		fmt.Fprintf(os.Stderr, "  %s\n", color.CyanString("%s", line))
	}
	fmt.Fprintln(os.Stderr)
}

// firstExisting returns the first repo-relative candidate that exists on disk,
// or "" when none do.
func firstExisting(repoPath string, candidates []string) string {
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(repoPath, c)); err == nil {
			return c
		}
	}
	return ""
}

// ciAlreadyIntegrated reports whether the CI config at relPath (a file, or a
// directory of workflow YAML) already references Risk Guard via marker.
func ciAlreadyIntegrated(repoPath, relPath, marker string) bool {
	full := filepath.Join(repoPath, relPath)
	info, err := os.Stat(full)
	if err != nil {
		return false
	}
	if !info.IsDir() {
		return fileContains(full, marker)
	}
	entries, err := os.ReadDir(full)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		if fileContains(filepath.Join(full, e.Name()), marker) {
			return true
		}
	}
	return false
}

func fileContains(path, marker string) bool {
	//nolint:gosec // path is built from git.CIProviders entries and dir listings, not user input.
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), marker)
}
