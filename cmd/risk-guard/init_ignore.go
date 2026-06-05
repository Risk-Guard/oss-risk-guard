package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"github.com/Risk-Guard/oss-risk-guard/src/riskguardignore"

	"github.com/charmbracelet/huh"
)

// ignoreOtherOption is the sentinel value for the "Other…" entry in the ignore
// multiselect. It is filtered out of the selection and instead triggers the
// free-text custom-pattern prompt, so it must never be written to the file.
const ignoreOtherOption = "\x00other"

// ignorableDirsFromManifests returns the distinct TOP-LEVEL directories that
// contain detected manifests, sorted, with repo-root manifests excluded. The
// top-level dir is the natural unit to offer: picking "benchmarks/" excludes the
// whole tree under it (Matcher.Match appends "/**"), so a handful of choices
// covers a repo like pytorch instead of one row per nested manifest. Custom or
// finer-grained globs are handled by the "Other…" free-text prompt.
func ignorableDirsFromManifests(manifests []models.DetectedManifest) []string {
	seen := map[string]struct{}{}
	var dirs []string
	for _, m := range manifests {
		for _, p := range m.Paths {
			slash := filepath.ToSlash(p)
			idx := strings.Index(slash, "/")
			if idx <= 0 {
				continue // repo-root manifest, nothing to exclude
			}
			top := slash[:idx]
			if _, ok := seen[top]; ok {
				continue
			}
			seen[top] = struct{}{}
			dirs = append(dirs, top)
		}
	}
	sort.Strings(dirs)
	return dirs
}

// promptIgnoreDirs shows the top-level dirs as a checklist plus an "Other…" row.
// It returns the chosen dir patterns (with a trailing slash) and whether the user
// asked to enter custom patterns. Callers must gate on isInteractive().
func promptIgnoreDirs(dirs []string) (selected []string, wantOther bool, err error) {
	opts := make([]huh.Option[string], 0, len(dirs)+1)
	for _, d := range dirs {
		opts = append(opts, huh.NewOption(d+"/", d+"/"))
	}
	opts = append(opts, huh.NewOption("Other (enter custom patterns)…", ignoreOtherOption))

	var chosen []string
	if err := huh.NewMultiSelect[string]().
		Title("Exclude any directories from the dependency audit?").
		Description(fmt.Sprintf(
			"Selected directories are added to %s.\n↑/↓ to move · space to select · enter to confirm",
			riskguardignore.IgnoreFileName,
		)).
		Options(opts...).
		Value(&chosen).
		Run(); err != nil {
		return nil, false, err
	}

	for _, c := range chosen {
		if c == ignoreOtherOption {
			wantOther = true
			continue
		}
		selected = append(selected, c)
	}
	return selected, wantOther, nil
}

// promptCustomPatterns collects free-form gitignore-style patterns, one per line.
// Blank lines and #-comments are dropped. Returns nil when nothing usable is entered.
func promptCustomPatterns() ([]string, error) {
	var text string
	if err := huh.NewText().
		Title("Custom ignore patterns").
		Description("gitignore-style globs, one per line (e.g. **/test/, vendor/*). Blank to skip.").
		Value(&text).
		Run(); err != nil {
		return nil, err
	}

	var out []string
	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

// promptAndApplyIgnore offers the top-level manifest directories (and an "Other…"
// escape hatch for custom globs) for exclusion, appends the picks to
// <repoPath>/.riskguardignore, and reports whether the file changed so the caller
// can re-create the SBOM. Returns false when there is nothing to offer, the user
// picks nothing, or nothing new was written.
func promptAndApplyIgnore(repoPath string, manifests []models.DetectedManifest) (bool, error) {
	dirs := ignorableDirsFromManifests(manifests)
	if len(dirs) == 0 {
		return false, nil
	}

	selected, wantOther, err := promptIgnoreDirs(dirs)
	if err != nil {
		return false, err
	}

	entries := selected
	if wantOther {
		custom, cerr := promptCustomPatterns()
		if cerr != nil {
			return false, cerr
		}
		entries = append(entries, custom...)
	}
	// The prompt was shown, so the group always ends with a ✅ marker — even
	// when nothing was excluded — so the user knows the step finished.
	if len(entries) == 0 {
		echoGroupDone("No directories excluded")
		return false, nil
	}

	written, err := riskguardignore.AppendIgnorePatterns(repoPath, entries)
	if err != nil {
		return false, fmt.Errorf("updating %s: %w", riskguardignore.IgnoreFileName, err)
	}
	if len(written) == 0 {
		echoGroupDone("No new directories excluded (selection already in %s)", riskguardignore.IgnoreFileName)
		return false, nil
	}

	noun := "entries"
	if len(written) == 1 {
		noun = "entry"
	}
	// huh clears the prompt on submit, so the marker doubles as a durable record
	// of exactly what was excluded.
	echoGroupDone("Added %d %s to %s:", len(written), noun, riskguardignore.IgnoreFileName)
	for _, w := range written {
		fmt.Fprintf(os.Stderr, "  + %s\n", w)
	}
	return true, nil
}
