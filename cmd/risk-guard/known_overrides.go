package main

import "github.com/Risk-Guard/oss-risk-guard/src/policy"

// knownOverrides is a built-in, reviewable table of source-URL gap-fillers for
// packages whose registry metadata declares no repository even though their
// source is well-known. Entries use precedence "fallback", so they apply only
// when metadata resolved no source and never clobber a package's own
// declaration. Keys support the same `*` wildcard matching as user overrides.
//
// These bypass policy.validateOverrides (they are code-defined, not loaded from
// a .risk-guard.yml), so keep paths/reasons populated and precedence valid here.
var knownOverrides = map[string][]policy.PolicyOverride{
	// The @types/* scope is registry-locked on npm (only DefinitelyTyped
	// automation can publish) and every package is published from the
	// DefinitelyTyped monorepo. Graduated/deprecated stub versions ship
	// repository: null, which otherwise triggers SOURCE_REPO_NOT_FOUND.
	"package/npm/@types/*": {
		{
			Path:       "output.source_url",
			Value:      "https://github.com/DefinitelyTyped/DefinitelyTyped",
			Precedence: "fallback",
			Reason:     "@types scope is registry-locked; published from the DefinitelyTyped monorepo",
		},
	},
}
