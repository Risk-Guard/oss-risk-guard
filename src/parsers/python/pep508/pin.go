package pep508

import "strings"

// ExactPin returns the one version a specifier set pins to, or "" when the set
// still leaves the version open to resolution.
//
// Only "==" and "===" name a single version. "==1.*" is a prefix match, and
// every other operator (">=", "~=", "!=", ...) admits a range, so none of them
// pin. A set may legitimately pair a pin with looser bounds
// ("gunicorn>=20,==22.0.0"), which still installs exactly 22.0.0; two
// disagreeing pins are unsatisfiable, so we decline to guess rather than pick
// one and report on a version nobody installs.
func ExactPin(specifiers []string) string {
	pin := ""
	for _, spec := range specifiers {
		version, ok := exactVersion(spec)
		if !ok {
			continue
		}
		if pin != "" && pin != version {
			return ""
		}
		pin = version
	}
	return pin
}

// exactVersion pulls the version out of a single "=="/"===" specifier.
func exactVersion(spec string) (string, bool) {
	spec = strings.TrimSpace(spec)

	// "===" must be tested first: CutPrefix(spec, "==") would leave a stray "=".
	if version, found := strings.CutPrefix(spec, "==="); found {
		// Arbitrary equality matches the literal string and is explicitly not
		// normalized, so the version is taken exactly as written.
		return validVersion(strings.TrimSpace(version))
	}
	if version, found := strings.CutPrefix(spec, "=="); found {
		version, ok := validVersion(strings.TrimSpace(version))
		if !ok {
			return "", false
		}
		return normalizeVersion(version), true
	}
	return "", false
}

func validVersion(version string) (string, bool) {
	// A wildcard is a prefix match over many releases, not a pin.
	if version == "" || strings.Contains(version, "*") {
		return "", false
	}
	return version, true
}

// normalizeVersion drops the leading "v" that PEP 440 permits but requires be
// removed during normalization ("v1.0" -> "1.0"), so the key matches the
// version string registries actually publish.
func normalizeVersion(version string) string {
	if len(version) > 1 && (version[0] == 'v' || version[0] == 'V') && version[1] >= '0' && version[1] <= '9' {
		return version[1:]
	}
	return version
}
