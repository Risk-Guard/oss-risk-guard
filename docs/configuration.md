# Configuration

Risk Guard reads `.risk-guard.yml` from the repository root. The file selects which findings block the build, which are warnings, and which are acknowledged exceptions.

The schema is defined by the `Policy` type in [`src/policy/types.go`](../src/policy/types.go); that file is the precise source of truth. The shipped default is [`src/policy/default_policy.yml`](../src/policy/default_policy.yml).

## Annotated example

```yaml
# .risk-guard.yml

# Schema version. Required. Currently only 2 is supported.
version: 2

# How the scan participates in your build.
workflow:
  # active   — run the scan, fail the build on blocking findings (default)
  # no-fail  — run the scan, emit annotations, never fail the build
  # silent   — run the scan, skip annotations, never fail
  # disabled — skip the scan entirely
  mode: active

# Map of selectors → severity.
#
# Severity values: blocking | warning | ignore
#
# Selector grammar (each segment is optional except the terminal one):
#
#   [source/<pattern>/][ecosystem/<name>/][depth/<range>/][env/dev|prod/](category/<name> | check/<CODE>)
#
# - `*` matches within a single path segment.
# - Source patterns must be quoted (they contain slashes).
# - `depth/0` is the repo itself; `depth/1` is a direct dep; `depth/2+` is transitive.
# - More specific selectors win over less specific ones.
severity:
  # Whole categories
  category/critical: blocking
  category/license-compliance: warning
  category/security-vulnerability: warning

  # A single check code
  check/SOURCE_NO_LICENSE: warning

  # Depth-scoped: ignore continuity risk on your own code, block it on
  # direct deps, downgrade it on transitive ones.
  depth/0/category/continuity-assurance: ignore
  depth/1/category/continuity-assurance: blocking
  depth/2+/category/continuity-assurance: warning

  # Scope to a source pattern (the repo a dependency comes from)
  source/"github.com/your-org/*"/category/critical: ignore

  # Long form with a reason and a future escalation date
  check/PACKAGE_STALE_RELEASE:
    severity: warning
    reason: "Triaged 2026-04-01; tracking in JIRA-123"
    blocking_after: 2026-07-01T00:00:00Z

# Acknowledged failures. The scan still reports them, but they do not
# fail the build. Keys are entity identifiers; values list the check
# codes you are accepting on that entity.
#
# Keys:
#   package/<ecosystem>/<name>[?version=X.Y.Z]
#   source/<host>/<org>/<repo>
#   root                              (this repository)
#
# `*` wildcards are allowed in the key.
expected_failures:
  package/npm/lodash:
    checks: [PACKAGE_STALE_RELEASE]
    reason: "Pinned to last patched release; upgrade tracked in #482"
    approved_by: "security@example.com"
    expires: 2026-09-01T00:00:00Z

  root:
    checks: [SOURCE_NO_LICENSE]
    reason: "Internal repo; license intentionally omitted"

# Acknowledged warnings — a noise baseline. Same key/value grammar as
# expected_failures, but this section applies only to warning-level findings:
# matched warnings are recorded as acknowledged so they stop adding annotation
# noise. It can never silence a blocking finding (if a check resolves to
# blocking, expected_warnings is ignored and the build still fails).
#
# Use it to baseline an existing repo's current warnings — `risk-guard init`
# seeds this for you — so the noise from your code history clears while new
# pull requests still surface fresh warnings. An expired entry simply reverts
# to a normal warning (it does not escalate to blocking).
expected_warnings:
  package/npm/left-pad:
    checks: [PACKAGE_STALE_RELEASE]
    reason: "Known stale; baselined at adoption"
    approved_by: "security@example.com"
    expires: 2026-12-01T00:00:00Z

# Per-entity output overrides. Use sparingly — every override requires
# a `reason` for audit trail.
overrides:
  package/npm/some-pkg:
    - path: output.source_url
      value: "https://github.com/actual-org/actual-repo"
      reason: "npm metadata points at a stale fork"
```

## `.riskguardignore`

A sibling file using gitignore syntax. Paths matching its patterns are excluded from scanning (e.g. vendored or generated code).

```
tests/
vendor/
**/*.generated.go
```

## Default policy

If no `.risk-guard.yml` is present, Risk Guard uses the embedded default — see [`src/policy/default_policy.yml`](../src/policy/default_policy.yml).
