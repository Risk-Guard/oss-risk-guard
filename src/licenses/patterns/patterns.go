package patterns

import (
	"fmt"
	"strings"
)

type licenseFamily struct {
	names     []string
	hasPrefix bool
	hasSuffix bool
}

var families = []licenseFamily{
	{names: []string{"LICENSE", "LICENCE"}, hasPrefix: true, hasSuffix: true},
	{names: []string{"UNLICENSE", "UNLICENCE"}, hasPrefix: false, hasSuffix: false},
	{names: []string{"COPYING"}, hasPrefix: true, hasSuffix: true},
	{names: []string{"BSDL"}, hasPrefix: false, hasSuffix: false},
}

func caseForms(name string) [2]string {
	return [2]string{name, strings.ToLower(name)}
}

// GlobPatterns returns patterns for doublestar.FilepathGlob license detection.
func GlobPatterns() []string {
	var out []string
	for _, fam := range families {
		for _, name := range fam.names {
			for _, n := range caseForms(name) {
				out = append(out,
					fmt.Sprintf("**/%s", n),
					fmt.Sprintf("**/%s.*", n),
				)
				if fam.hasSuffix {
					out = append(out, fmt.Sprintf("**/%s-*", n))
				}
				if fam.hasPrefix {
					out = append(out,
						fmt.Sprintf("**/*-%s", n),
						fmt.Sprintf("**/*-%s.*", n),
					)
				}
			}
		}
	}
	return out
}

// GitSparseCheckoutPatterns returns broader patterns for git sparse checkout.
func GitSparseCheckoutPatterns() []string {
	var out []string
	for _, fam := range families {
		for _, name := range fam.names {
			for _, n := range caseForms(name) {
				out = append(out, fmt.Sprintf("**/%s*", n))
				if fam.hasPrefix {
					out = append(out,
						fmt.Sprintf("**/*-%s", n),
						fmt.Sprintf("**/*-%s.*", n),
					)
				}
			}
		}
	}
	return out
}
