package licenseutil

import (
	"strings"
)

// NormalizeLicense converts a license string to SPDX identifier
// Handles PyPI classifiers and returns normalized SPDX identifiers
func NormalizeLicense(license string) string {
	// Trim whitespace
	license = strings.TrimSpace(license)

	// Check if it looks like a PyPI classifier (contains "::" or common PyPI patterns)
	if strings.Contains(license, " :: ") || isPyPILicensePattern(license) {
		return NormalizePyPIClassifier(license)
	}

	// Return as-is if already looks like SPDX ID (contains hyphen or is short)
	if strings.Contains(license, "-") || len(license) <= 10 {
		return license
	}

	// Otherwise return original
	return license
}

// isPyPILicensePattern checks if a license string looks like a PyPI classifier
func isPyPILicensePattern(license string) bool {
	// Common PyPI license patterns (without "OSI Approved :: " prefix)
	pypiPatterns := []string{
		"BSD License",
		"MIT License",
		"Apache",
		"GNU ",
		"ISC License",
		"Mozilla Public License",
		"Public Domain",
	}

	for _, pattern := range pypiPatterns {
		if strings.Contains(license, pattern) {
			return true
		}
	}

	return false
}
