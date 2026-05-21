package licenseutil

import (
	"testing"
)

func TestNormalizePyPIClassifier_OSIApprovedPrefix(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		desc     string
	}{
		// OSI Approved variants (the sphinxcontrib-htmlhelp case)
		{"OSI Approved :: BSD License", "BSD", "OSI Approved BSD classifier"},
		{"OSI Approved :: MIT License", "MIT", "OSI Approved MIT classifier"},
		{"OSI Approved :: Apache Software License", "Apache", "OSI Approved Apache classifier"},
		{"OSI Approved :: GNU General Public License v3 (GPLv3)", "GPL-3.0-only", "OSI Approved GPL-3.0 classifier"},
		{"OSI Approved :: ISC License (ISCL)", "ISC", "OSI Approved ISC classifier"},
		{"OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)", "MPL-2.0", "OSI Approved MPL-2.0 classifier"},

		// Direct classifiers (without OSI Approved prefix)
		{"BSD License", "BSD", "Direct BSD classifier"},
		{"MIT License", "MIT", "Direct MIT classifier"},
		{"Apache Software License", "Apache", "Direct Apache classifier"},
		{"GNU General Public License v3 (GPLv3)", "GPL-3.0-only", "Direct GPL-3.0 classifier"},
		{"ISC License (ISCL)", "ISC", "Direct ISC classifier"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			result := NormalizePyPIClassifier(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizePyPIClassifier(%q) = %q, want %q",
					tt.input, result, tt.expected)
			}
		})
	}
}

func TestNormalizePyPIClassifier_BSDFamily(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"BSD License", "BSD"},
		{"BSD-2-Clause License", "BSD-2-Clause"},
		{"BSD 2-Clause License", "BSD-2-Clause"},
		{"BSD-3-Clause License", "BSD-3-Clause"},
		{"BSD 3-Clause License", "BSD-3-Clause"},
		{"OSI Approved :: BSD License", "BSD"},
		{"OSI Approved :: BSD-2-Clause License", "BSD-2-Clause"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizePyPIClassifier(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizePyPIClassifier(%q) = %q, want %q",
					tt.input, result, tt.expected)
			}
		})
	}
}

func TestNormalizePyPIClassifier_GPLFamily(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"GNU General Public License v2", "GPL-2.0"},
		{"GNU General Public License v2 (GPLv2)", "GPL-2.0-only"},
		{"GNU General Public License v2 or later", "GPL-2.0-or-later"},
		{"GNU General Public License v3", "GPL-3.0"},
		{"GNU General Public License v3 (GPLv3)", "GPL-3.0-only"},
		{"GNU General Public License v3 or later", "GPL-3.0-or-later"},
		{"OSI Approved :: GNU General Public License v3 (GPLv3)", "GPL-3.0-only"},
		{"GPL-2.0", "GPL-2.0"},
		{"GPL-3.0-only", "GPL-3.0-only"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizePyPIClassifier(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizePyPIClassifier(%q) = %q, want %q",
					tt.input, result, tt.expected)
			}
		})
	}
}

func TestNormalizePyPIClassifier_UnmappedClassifier(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		desc     string
	}{
		{"Some Unknown License", "Some Unknown License", "Unmapped license returns as-is"},
		{"OSI Approved :: Future License Name", "Future License Name", "OSI prefix stripped but no mapping"},
		{"Custom License v1.0", "Custom License v1.0", "Custom license returns as-is"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			result := NormalizePyPIClassifier(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizePyPIClassifier(%q) = %q, want %q",
					tt.input, result, tt.expected)
			}
		})
	}
}

func TestNormalizePyPIClassifier_Whitespace(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"  BSD License  ", "BSD"},
		{" OSI Approved :: MIT License ", "MIT"},
		{"\tGNU General Public License v3\n", "GPL-3.0"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizePyPIClassifier(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizePyPIClassifier(%q) = %q, want %q",
					tt.input, result, tt.expected)
			}
		})
	}
}
