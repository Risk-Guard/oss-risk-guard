package checkutil

import "fmt"

const MaxEvidenceItems = 5

func TruncateEvidence(evidence []string) []string {
	if len(evidence) > MaxEvidenceItems {
		overflow := len(evidence) - MaxEvidenceItems
		result := evidence[:MaxEvidenceItems]
		return append(result, fmt.Sprintf("... and %d more", overflow))
	}
	return evidence
}
