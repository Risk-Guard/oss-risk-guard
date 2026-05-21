package licenseutil

import (
	"testing"
)

func TestNormalizeLicense(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// PyPI classifiers
		{"BSD License", "BSD"},
		{"MIT License", "MIT"},
		{"Apache License 2.0", "Apache-2.0"},
		{"Apache License, Version 2.0", "Apache-2.0"},
		{"GNU General Public License v3", "GPL-3.0"},
		{"GNU General Public License v3 or later", "GPL-3.0-or-later"},

		// Already SPDX
		{"BSD-2-Clause", "BSD-2-Clause"},
		{"BSD-3-Clause", "BSD-3-Clause"},
		{"MIT", "MIT"},
		{"Apache-2.0", "Apache-2.0"},
		{"GPL-3.0-only", "GPL-3.0-only"},

		// Edge cases
		{"  MIT License  ", "MIT"},
		{"", ""},
		{"ISC License", "ISC"},
		{"MPL-2.0", "MPL-2.0"},

		// PyPI "OSI Approved ::" classifiers (sphinxcontrib-htmlhelp case)
		{"OSI Approved :: BSD License", "BSD"},
		{"OSI Approved :: MIT License", "MIT"},
		{"OSI Approved :: Apache Software License", "Apache"},
		{"OSI Approved :: GNU General Public License v3 (GPLv3)", "GPL-3.0-only"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizeLicense(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizeLicense(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
