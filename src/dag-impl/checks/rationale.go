package checks

import (
	"fmt"
)

func BuildCompliantRationale(items []string, emptyMessage, description string) string {
	if len(items) == 0 {
		return emptyMessage
	}
	if len(items) == 1 {
		return items[0]
	}
	return fmt.Sprintf("All %d %s", len(items), description)
}

func BuildViolationRationale(items []string, singular, plural string) string {
	if len(items) == 0 {
		return ""
	}
	if len(items) == 1 {
		if singular == "" {
			return items[0]
		}
		return fmt.Sprintf("%s %s", items[0], singular)
	}
	if plural == "" {
		return fmt.Sprintf("%s and %d other(s)", items[0], len(items)-1)
	}
	return fmt.Sprintf("%s and %d other(s) %s", items[0], len(items)-1, plural)
}

// UnknownReleaseDateSuffix names the packages a date-based check could not
// evaluate. Every rationale that reports a partial result carries it, so a
// result computed from some of the packages never reads as a verdict on all of
// them — including violation rationales, whose evidence list may be truncated
// past the unknowns.
func UnknownReleaseDateSuffix(unknownCount int) string {
	if unknownCount == 0 {
		return ""
	}
	return fmt.Sprintf("; %d package(s) had no release date and were not evaluated", unknownCount)
}

func FormatScannedItems(items []string) string {
	if len(items) == 0 {
		return ""
	}
	if len(items) == 1 {
		return fmt.Sprintf(" (%s)", items[0])
	}
	return fmt.Sprintf(" (%s and %d others)", items[0], len(items)-1)
}
