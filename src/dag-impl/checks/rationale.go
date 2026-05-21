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

func FormatScannedItems(items []string) string {
	if len(items) == 0 {
		return ""
	}
	if len(items) == 1 {
		return fmt.Sprintf(" (%s)", items[0])
	}
	return fmt.Sprintf(" (%s and %d others)", items[0], len(items)-1)
}
