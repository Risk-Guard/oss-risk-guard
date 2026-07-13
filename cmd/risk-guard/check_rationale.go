package main

import "fmt"

// checkRationale is the "why you should care" copy for a check, shown when tuning
// its severity during `init`. why is a benefit-led, verb-varied headline (what
// keeping the check on does for you); stat is an optional one-line, sourced fact
// shown as a subtitle beneath it. The verb is matched to the check: preventive
// checks "Block"/"Catch", probabilistic ones "Reduce exposure to", and
// detective/legal/coverage ones "Flag"/"Surface" — so the line never overclaims.
type checkRationale struct {
	why  string
	stat string // "" when no well-grounded, on-point number exists
}

// checkRationales maps a check code to its rationale. There is intentionally NO
// fallback: whyShouldICare errors when a fired check has no entry, so every check
// that can surface a finding must carry curated wording. Add an entry here when
// you add a check. Stats are sourced from the project's own research where one
// fits the check, and from verified public data otherwise.
var checkRationales = map[string]checkRationale{
	// Source checks
	"SOURCE_NO_CI": {
		why: "Flags dependencies with no automated test, lint, or security gates — nothing stops a bad commit from shipping.",
	},
	"SOURCE_NO_LICENSE": {
		why:  "Flags code that's legally unsafe to use, vendor, or redistribute — a license can't be assumed from the README.",
		stat: "31–33% of audited codebases ship OSS with no discernible license — Black Duck OSSRA",
	},
	"SOURCE_NO_SECURITY_POLICY": {
		why: "Flags projects with no channel to report vulnerabilities, so issues get disclosed publicly or never fixed.",
	},
	"SOURCE_NO_HUMAN_COMMITS": {
		why: "Flags repos with no human commits — likely a bot mirror or fabricated project with no one behind the code.",
	},
	"SOURCE_REPO_ABANDONED": {
		why:  "Catches dependencies whose maintainers stopped years ago, so newly found vulnerabilities never get patched.",
		stat: "Polyfill.io: an abandoned project's domain was bought and used to backdoor 100,000+ sites",
	},
	"SOURCE_REPO_NEW": {
		why: "Reduces exposure to typosquats and throwaway malicious packages, which cluster in brand-new repos with no track record.",
	},
	"SOURCE_REPO_STALE": {
		why: "Flags projects where maintenance has slowed or stopped, so fixes arrive slowly if at all.",
	},
	"SOURCE_FEW_CONTRIBUTORS": {
		why:  "Surfaces a small bus factor — a handful of people, or one compromised account, can stall or subvert the project.",
		stat: "OpenSSL secured ~66% of web servers on ~4 volunteers when Heartbleed hit",
	},
	"SOURCE_SINGLE_CONTRIBUTOR": {
		why:  "Surfaces a small bus factor, one compromised account, can stall or subvert the project.",
		stat: "xz-utils: ~3 years of trust-building by one co-maintainer ended in a CVSS 10.0 SSH backdoor",
	},
	"SOURCE_REPO_NOT_FOUND": {
		why: "Flags packages whose source can't be located, so none of the source-based checks can verify what you're installing.",
	},
	"SOURCE_MANIFEST_WITHOUT_LOCKFILE": {
		why: "Reduces exposure to version-drift and dependency confusion by flagging builds that aren't pinned.",
	},
	"SOURCE_MALFORMED_METADATA": {
		why: "Flags dependency files that can't be parsed, so the audit may miss packages you actually ship.",
	},
	"SOURCE_UNSUPPORTED_MANIFEST_FILE": {
		why: "Flags ecosystems the audit can't scan yet — a coverage gap, not a clean bill of health.",
	},
	"SOURCE_PACKAGE_NAME_UNEXPORTED": {
		why: "Flags manifests where no package name was detected, so published-package checks can't confirm what ships.",
	},
	"PACKAGE_DYNAMIC_NAME": {
		why: "Catches package names computed at build time — a trick used to disguise what actually gets published.",
	},
	"PACKAGE_INSTALL_SCRIPTS": {
		why:  "Blocks packages that run code at install time — the primary vector for turning a bad dependency into a compromised machine.",
		stat: "Install scripts drove event-stream, ua-parser-js (8M weekly downloads), and the Shai-Hulud worm",
	},

	// Package checks
	"PACKAGE_NO_LICENSE": {
		why:  "Flags packages with no declared license — unresolved legal risk for everything that depends on them.",
		stat: "89% of M&A deals carry OSS license-compliance risk — Black Duck OSSRA",
	},
	"PACKAGE_STALE_RELEASE": {
		why:  "Flags packages with no release in years — likely unmaintained, with no fixes coming for new vulnerabilities.",
		stat: "coa and rc had no legitimate release in 3+ years before they were hijacked",
	},
	"PACKAGE_RELEASE_COOLDOWN": {
		why:  "Holds back just-published versions until the ecosystem can catch a hijacked or malicious release — most are caught within days.",
		stat: "A ~3-day cooldown cuts ~80–90% of exposure; Nx and LiteLLM were pulled within hours — cooldowns.dev",
	},
	"PACKAGE_NAME_MISMATCH": {
		why:  "Catches packages whose published name doesn't match their source repo — a hallmark of impersonation and typosquatting.",
		stat: "Sonatype found 63,000+ copycat packages after dependency confusion went public",
	},
	"PACKAGE_REGISTRY_MISMATCH": {
		why:  "Catches dependency confusion — a package missing from the registry it claims, or public while claiming to be private.",
		stat: "Dependency confusion hit 35+ firms (Apple, Microsoft, PayPal); 49% of orgs were vulnerable — Birsan/Orca",
	},
	"PACKAGE_REGISTRY_QUARANTINED": {
		why:  "Flags packages the registry has frozen — present but blocked from install pending a malware/abuse review — so an active takedown is treated as a security event, not mistaken for a typo'd or never-published name.",
		stat: "PyPI introduced project quarantine in 2024 (standardized as the PEP 792 project-status marker) to freeze suspected-malicious projects pending admin review",
	},
	"PACKAGE_UNSAFE_SOURCE_URL": {
		why: "Catches invalid or unsafe source URLs in metadata that can redirect tooling to attacker-controlled locations.",
	},
	"PACKAGE_SOURCE_URL_MISMATCH": {
		why: "Flags packages whose registry points at a different repo than the one analyzed — you may be reviewing code that isn't what ships.",
	},
	"PACKAGE_MALFORMED_DEPENDENCIES": {
		why: "Flags unparseable version constraints — the resolver's behavior is undefined, so you can't be sure what installs.",
	},
	"PACKAGE_UNRELEASED_CHANGES": {
		why: "Flags source with commits never published to the registry — what's installed may not match the code you reviewed.",
	},
	"PACKAGE_INVALID_ARTIFACT": {
		why: "Blocks packages whose artifact fails integrity or build-provenance verification — a mismatched hash, a bad signature, or an attested digest that doesn't match all signal tampering.",
	},
}

// whyShouldICare returns the curated rationale for a check code. It errors when
// the code is absent rather than falling back, so a check that can fire without
// curated wording fails loudly during init instead of showing a blank prompt.
func whyShouldICare(code string) (checkRationale, error) {
	if r, ok := checkRationales[code]; ok {
		return r, nil
	}
	return checkRationale{}, fmt.Errorf("no rationale defined for check %q in checkRationales (cmd/risk-guard/check_rationale.go)", code)
}
