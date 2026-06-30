package main

import (
	_ "embed"
	"fmt"

	"github.com/Risk-Guard/oss-risk-guard/src/policy"

	"sigs.k8s.io/yaml"
)

//go:embed known_overrides.yml
var knownOverridesYAML []byte

// knownOverrides is the built-in, reviewable table of source-URL gap-fillers,
// loaded from the embedded known_overrides.yml. See that file for what the
// entries mean and the invariants they must hold.
var knownOverrides map[string][]policy.PolicyOverride

func init() {
	if err := yaml.Unmarshal(knownOverridesYAML, &knownOverrides); err != nil {
		panic(fmt.Sprintf("parsing known_overrides.yml: %v", err))
	}
	// These bypass the .risk-guard.yml load path, so validate them here against
	// the same rules to catch a malformed built-in entry at startup rather than
	// silently dropping it during an audit.
	if err := policy.ValidateOverrides(knownOverrides, "known_overrides.yml"); err != nil {
		panic(fmt.Sprintf("invalid known_overrides.yml: %v", err))
	}
}
