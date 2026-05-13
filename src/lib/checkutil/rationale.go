package checkutil

import (
	"fmt"

	"github.com/Risk-Guard/oss-risk-guard/src/lib/models"
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

func FormatLicenseWithPath(license models.LicenseInfo) string {
	if license.SPDXID != nil && *license.SPDXID != "" {
		return fmt.Sprintf("%s (%s)", *license.SPDXID, license.Path)
	}
	return fmt.Sprintf("unknown (%s)", license.Path)
}

func FormatScannedFiles(licenses []models.LicenseInfo) string {
	if len(licenses) == 0 {
		return ""
	}
	first := licenses[0].Path
	if len(licenses) == 1 {
		return fmt.Sprintf(" in %s", first)
	}
	return fmt.Sprintf(" in %s (and %d others)", first, len(licenses)-1)
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

func FormatLicenseEvidence(license models.LicenseInfo) string {
	base := FormatLicenseWithPath(license)
	if license.TextURL != nil && *license.TextURL != "" && *license.TextURL != "<unsupported>" {
		return fmt.Sprintf("%s (URL: %s)", base, *license.TextURL)
	}
	return base
}
