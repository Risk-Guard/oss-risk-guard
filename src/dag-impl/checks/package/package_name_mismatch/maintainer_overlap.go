package package_name_mismatch

import (
	"fmt"
	"risk-guard/src/models"
	"strings"
)

// MaintainerOverlap represents the comparison result between two packages' maintainers
type MaintainerOverlap struct {
	ComparedTo       string
	SharedCount      int
	TotalMaintainers int
	OverlapPercent   int
}

// ComputeMaintainerOverlap compares maintainers between two packages.
// Uses email as the canonical identifier since usernames can differ across systems.
func ComputeMaintainerOverlap(mismatchedMaintainers, comparisonMaintainers []models.Maintainer) MaintainerOverlap {
	if len(mismatchedMaintainers) == 0 {
		return MaintainerOverlap{
			TotalMaintainers: 0,
			OverlapPercent:   0,
		}
	}

	comparisonEmails := make(map[string]bool)
	for _, m := range comparisonMaintainers {
		email := strings.ToLower(strings.TrimSpace(m.Email))
		if email != "" {
			comparisonEmails[email] = true
		}
	}

	sharedCount := 0
	for _, m := range mismatchedMaintainers {
		email := strings.ToLower(strings.TrimSpace(m.Email))
		if email != "" && comparisonEmails[email] {
			sharedCount++
		}
	}

	total := len(mismatchedMaintainers)
	percent := 0
	if total > 0 {
		percent = (sharedCount * 100) / total
	}

	return MaintainerOverlap{
		SharedCount:      sharedCount,
		TotalMaintainers: total,
		OverlapPercent:   percent,
	}
}

// FormatMaintainerOverlapEvidence formats the overlap as an evidence string.
func FormatMaintainerOverlapEvidence(overlap MaintainerOverlap) string {
	if overlap.TotalMaintainers == 0 {
		return fmt.Sprintf("Maintainer overlap with %s: Unknown (no maintainers listed)",
			overlap.ComparedTo)
	}

	result := fmt.Sprintf("Maintainer overlap with %s: %d%% (%d/%d shared)",
		overlap.ComparedTo,
		overlap.OverlapPercent,
		overlap.SharedCount,
		overlap.TotalMaintainers,
	)

	if overlap.SharedCount == 0 {
		result += " - DIFFERENT MAINTAINERS"
	}

	return result
}
