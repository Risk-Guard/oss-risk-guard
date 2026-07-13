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

// Source-provenance kinds, mirroring package_detector_published.SourceRef* so a
// detector's raw SourceRef string maps straight onto SourceRef.Kind. They form an
// assurance ladder: an attested gitHead is strongest, a version-matched release
// tag is inferred (the tag could have been moved after release), and current HEAD
// is weakest (the source may have diverged from the published artifact entirely).
const (
	ProvenanceVerified = "provenance" // cryptographically verified build-provenance attestation (strongest)
	ProvenanceGitHead  = "gitHead"    // registry-attested commit the version was published from
	ProvenanceTag      = "tag"        // release tag matching the version, resolved on the remote
	ProvenanceHead     = "head"       // fell back to current HEAD
)

// SourceRef records which source tree a provenance check scanned, so findings can
// disclose that assurance level honestly.
type SourceRef struct {
	Kind   string // ProvenanceGitHead | ProvenanceTag | ProvenanceHead
	Commit string // resolved SHA for the gitHead/tag kinds; empty for head
	Name   string // tag ref name (e.g. "@dnd-kit/core@6.3.1") for the tag kind; empty otherwise
}

// Published reports whether the scan compared against the source as-published —
// either the attested gitHead or a version-matched release tag — rather than
// current HEAD.
func (r SourceRef) Published() bool {
	return r.Kind == ProvenanceVerified || r.Kind == ProvenanceGitHead || r.Kind == ProvenanceTag
}

// Describe formats the one-line clause naming the compared source tree. pkgRef is
// "eco/name@version" (or "eco/name" when the version is unknown) and is used only
// in the HEAD wording.
func (r SourceRef) Describe(pkgRef string) string {
	switch r.Kind {
	case ProvenanceVerified:
		return fmt.Sprintf("source with verified build provenance (%s)", shortSHA(r.Commit))
	case ProvenanceGitHead:
		return fmt.Sprintf("source as published (gitHead %s)", shortSHA(r.Commit))
	case ProvenanceTag:
		return fmt.Sprintf("source at tag %s (%s)", r.Name, shortSHA(r.Commit))
	default:
		return fmt.Sprintf("repository HEAD — no gitHead recorded for %s, so source may differ from the published artifact", pkgRef)
	}
}

// Scanned renders Describe as the standalone evidence line every provenance check emits.
func (r SourceRef) Scanned(pkgRef string) string {
	return "Scanned " + r.Describe(pkgRef)
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
