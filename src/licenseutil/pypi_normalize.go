package licenseutil

import (
	"strings"
)

// PyPI Classifier to SPDX ID mapping
// These mappings handle PyPI license classifiers that are extracted from package metadata.
// The Python transformer extracts classifiers in the format "License :: OSI Approved :: X"
// and strips the "License :: " prefix, leaving "OSI Approved :: X" or just "X".
var pypiClassifierToSPDX = map[string]string{
	// BSD Family
	"BSD License":          "BSD", // Generic - matches any BSD variant
	"BSD-1-Clause License": "BSD-1-Clause",
	"BSD 1-Clause License": "BSD-1-Clause",
	"BSD-2-Clause License": "BSD-2-Clause",
	"BSD 2-Clause License": "BSD-2-Clause",
	"BSD-3-Clause License": "BSD-3-Clause",
	"BSD 3-Clause License": "BSD-3-Clause",

	// MIT Family
	"MIT License": "MIT",
	"MIT":         "MIT",
	"MIT-0":       "MIT-0",

	// Apache Family
	"Apache License 2.0":          "Apache-2.0",
	"Apache License, Version 2.0": "Apache-2.0",
	"Apache-2.0":                  "Apache-2.0",
	"Apache Software License":     "Apache", // Generic

	// GPL Family
	"GNU General Public License v2":          "GPL-2.0",
	"GNU General Public License v2 (GPLv2)":  "GPL-2.0-only",
	"GNU General Public License v2 or later": "GPL-2.0-or-later",
	"GNU General Public License v3":          "GPL-3.0",
	"GNU General Public License v3 (GPLv3)":  "GPL-3.0-only",
	"GNU General Public License v3 or later": "GPL-3.0-or-later",
	"GPL-2.0":                                "GPL-2.0",
	"GPL-2.0-only":                           "GPL-2.0-only",
	"GPL-2.0-or-later":                       "GPL-2.0-or-later",
	"GPL-3.0":                                "GPL-3.0",
	"GPL-3.0-only":                           "GPL-3.0-only",
	"GPL-3.0-or-later":                       "GPL-3.0-or-later",

	// LGPL Family
	"GNU Lesser General Public License v2":   "LGPL-2.0",
	"GNU Lesser General Public License v2.1": "LGPL-2.1",
	"GNU Lesser General Public License v3":   "LGPL-3.0",
	"LGPL-2.0":                               "LGPL-2.0",
	"LGPL-2.1":                               "LGPL-2.1",
	"LGPL-3.0":                               "LGPL-3.0",

	// Other Common
	"ISC License":                          "ISC",
	"ISC License (ISCL)":                   "ISC",
	"Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
	"MPL-2.0":                              "MPL-2.0",
	"Public Domain":                        "Unlicense",
}

// NormalizePyPIClassifier normalizes PyPI license classifiers to SPDX identifiers.
// It handles both direct classifiers (e.g., "BSD License") and "OSI Approved" variants
// (e.g., "OSI Approved :: BSD License") by stripping the prefix and normalizing the base name.
//
// Examples:
//   - "OSI Approved :: BSD License" → "BSD"
//   - "BSD License" → "BSD"
//   - "OSI Approved :: MIT License" → "MIT"
//   - "MIT License" → "MIT"
func NormalizePyPIClassifier(classifier string) string {
	// Trim whitespace
	classifier = strings.TrimSpace(classifier)

	// Strip "OSI Approved :: " prefix if present
	// This allows us to reuse the same mappings for both formats:
	//   "BSD License" and "OSI Approved :: BSD License" both normalize to "BSD"
	stripped := strings.TrimPrefix(classifier, "OSI Approved :: ")

	// Use existing mapping for the base license name
	if spdx, exists := pypiClassifierToSPDX[stripped]; exists {
		return spdx
	}

	// Return stripped version if no mapping (allows downstream logic to handle it)
	return stripped
}
