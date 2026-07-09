package checks

import (
	"fmt"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

func AppendTruncatedEvidence(out *Output, items []string, prefix, overflowLabel string) {
	displayItems := items
	if len(displayItems) > MaxEvidenceItems {
		displayItems = displayItems[:MaxEvidenceItems]
	}
	for _, item := range displayItems {
		out.WithEvidencef("%s%s", prefix, item)
	}
	if len(items) > MaxEvidenceItems {
		out.WithEvidencef("%s... and %d more %s", prefix, len(items)-MaxEvidenceItems, overflowLabel)
	}
}

// SourceProvenance formats the one-line clause disclosing which source tree a
// provenance check compared against. gitHeadUsed is true when the manifests came
// from the tree cloned at the published version's gitHead (commit is that SHA,
// rendered short); false means the check fell back to the repository's current
// HEAD, in which case the source may have diverged from the published artifact.
// pkgRef is "eco/name@version" (or "eco/name" when the version is unknown).
func SourceProvenance(gitHeadUsed bool, commit, pkgRef string) string {
	if gitHeadUsed {
		return fmt.Sprintf("source as published (gitHead %s)", shortSHA(commit))
	}
	return fmt.Sprintf("repository HEAD — no gitHead recorded for %s, so source may differ from the published artifact", pkgRef)
}

// ScannedProvenance renders SourceProvenance as a standalone evidence line, the
// form every provenance check emits it in.
func ScannedProvenance(gitHeadUsed bool, commit, pkgRef string) string {
	return "Scanned " + SourceProvenance(gitHeadUsed, commit, pkgRef)
}

// PackagesRef renders the analyzed packages as "eco/name@version" (comma-joined,
// truncated), for use as the pkgRef in SourceProvenance. Falls back to a generic
// phrase when no packages are present.
func PackagesRef(pkgs []models.PackageInfo) string {
	var refs []string
	for _, p := range pkgs {
		r := p.Ecosystem + "/" + p.Name
		if p.Version != "" {
			r += "@" + p.Version
		}
		refs = append(refs, r)
	}
	if len(refs) == 0 {
		return "this package"
	}
	if len(refs) > MaxEvidenceItems {
		refs = append(refs[:MaxEvidenceItems:MaxEvidenceItems], "...")
	}
	return strings.Join(refs, ", ")
}

func shortSHA(commit string) string {
	if len(commit) > 7 {
		return commit[:7]
	}
	return commit
}

func TruncateEvidence(evidence []string) []string {
	if len(evidence) > MaxEvidenceItems {
		overflow := len(evidence) - MaxEvidenceItems
		result := evidence[:MaxEvidenceItems]
		return append(result, fmt.Sprintf("... and %d more", overflow))
	}
	return evidence
}
