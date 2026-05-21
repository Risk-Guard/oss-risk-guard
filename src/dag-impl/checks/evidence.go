package checks

import "fmt"

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

func TruncateEvidence(evidence []string) []string {
	if len(evidence) > MaxEvidenceItems {
		overflow := len(evidence) - MaxEvidenceItems
		result := evidence[:MaxEvidenceItems]
		return append(result, fmt.Sprintf("... and %d more", overflow))
	}
	return evidence
}
