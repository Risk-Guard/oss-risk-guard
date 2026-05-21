package patterns

import (
	"slices"
	"testing"

	"github.com/bmatcuk/doublestar/v4"
)

func TestGlobPatternsContainsExpected(t *testing.T) {
	pats := GlobPatterns()

	expected := []string{
		"**/LICENSE", "**/LICENSE.*", "**/LICENSE-*", "**/*-LICENSE", "**/*-LICENSE.*",
		"**/license", "**/license.*", "**/license-*", "**/*-license", "**/*-license.*",
		"**/LICENCE", "**/LICENCE.*", "**/LICENCE-*", "**/*-LICENCE", "**/*-LICENCE.*",
		"**/licence", "**/licence.*", "**/licence-*", "**/*-licence", "**/*-licence.*",
		"**/UNLICENSE", "**/UNLICENSE.*",
		"**/unlicense", "**/unlicense.*",
		"**/UNLICENCE", "**/UNLICENCE.*",
		"**/unlicence", "**/unlicence.*",
		"**/COPYING", "**/COPYING.*", "**/COPYING-*", "**/*-COPYING", "**/*-COPYING.*",
		"**/copying", "**/copying.*", "**/copying-*", "**/*-copying", "**/*-copying.*",
		"**/BSDL", "**/BSDL.*", "**/bsdl", "**/bsdl.*",
	}

	for _, e := range expected {
		if !slices.Contains(pats, e) {
			t.Errorf("GlobPatterns() missing %q", e)
		}
	}
}

func TestGlobPatternsNoUnlicenseSuffix(t *testing.T) {
	pats := GlobPatterns()
	forbidden := []string{
		"**/UNLICENSE-*", "**/unlicense-*",
		"**/*-UNLICENSE", "**/*-UNLICENSE.*",
		"**/*-unlicense", "**/*-unlicense.*",
		"**/UNLICENCE-*", "**/unlicence-*",
		"**/*-UNLICENCE", "**/*-UNLICENCE.*",
		"**/*-unlicence", "**/*-unlicence.*",
	}
	for _, f := range forbidden {
		if slices.Contains(pats, f) {
			t.Errorf("GlobPatterns() should not contain %q", f)
		}
	}
}

func TestGitSparseCheckoutPatternsContainsExpected(t *testing.T) {
	pats := GitSparseCheckoutPatterns()

	expected := []string{
		"**/LICENSE*", "**/license*",
		"**/*-LICENSE", "**/*-LICENSE.*",
		"**/*-license", "**/*-license.*",
		"**/LICENCE*", "**/licence*",
		"**/*-LICENCE", "**/*-LICENCE.*",
		"**/*-licence", "**/*-licence.*",
		"**/UNLICENSE*", "**/unlicense*",
		"**/UNLICENCE*", "**/unlicence*",
		"**/COPYING*", "**/copying*",
		"**/*-COPYING", "**/*-COPYING.*",
		"**/*-copying", "**/*-copying.*",
		"**/BSDL*", "**/bsdl*",
	}

	for _, e := range expected {
		if !slices.Contains(pats, e) {
			t.Errorf("GitSparseCheckoutPatterns() missing %q", e)
		}
	}
}

func TestGlobPatternsMatchKnownFiles(t *testing.T) {
	pats := GlobPatterns()

	files := []string{
		"LICENSE", "LICENSE.txt", "LICENSE-MIT", "MIT-LICENSE", "MIT-LICENSE.txt",
		"LICENCE", "LICENCE.md", "LICENCE-Apache", "Apache-LICENCE",
		"license", "license.txt", "license-mit", "bsd-license", "bsd-license.txt",
		"UNLICENSE", "UNLICENSE.txt", "unlicense", "unlicense.md",
		"UNLICENCE", "UNLICENCE.txt",
		"COPYING", "COPYING.txt", "COPYING-BSD", "GPL-COPYING", "GPL-COPYING.txt",
		"copying", "copying.txt", "copying-lgpl", "lgpl-copying",
		"BSDL", "BSDL.txt", "bsdl",
		"src/LICENSE", "vendor/lib/MIT-LICENSE.txt",
	}

	for _, file := range files {
		matched := false
		for _, pat := range pats {
			ok, err := doublestar.Match(pat, file)
			if err != nil {
				t.Fatalf("doublestar.Match(%q, %q) error: %v", pat, file, err)
			}
			if ok {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("no glob pattern matched %q", file)
		}
	}
}
