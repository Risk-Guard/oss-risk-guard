# Risk Guard

Open source risk analysis and scoring for software dependencies. Runs a scoring DAG against a local git repository and emits SARIF results.

## Quick Start

```bash
# Full pipeline: score the local source, build an SBOM, audit direct deps
# Emits one merged SARIF (default ./risk-guard-report.sarif)
go run src/cli/local .

# Source-only scoring (no dependency audit)
go run src/cli/local scan .

# Generate an SBOM (SPDX or CycloneDX) for a local repository
go run src/cli/local sbom .

# Audit direct dependencies from an existing SBOM
go run src/cli/local audit --sbom sbom.spdx --sarif audit.sarif

# Score a single package by its analysis-identifier key
go run src/cli/local audit-package 'package/npm/express' --sarif out.sarif

# Render a human-readable summary of a SARIF report
go run src/cli/local view-audit risk-guard-report.sarif
```

Cache outputs (DAG results, clones, audit cache, network cache) resolve in this
order: `--cache-dir` flag → `RISK_GUARD_CACHE_DIR` env → `os.UserCacheDir()/risk-guard`.

## Supported Ecosystems

- `npm` - JavaScript / Node.js
- `pypi` - Python
- `rubygems` - Ruby

## Flags

Persistent (all commands):

- `--cache-dir` - cache root for DAG results, clones, audit cache, network cache
- `--log-level` - `debug`, `info`, `warn` (default), `error`
- `--logfile` - write debug logs to a file in addition to console
- `--secure-git` - isolate git from local config/credentials (blocks SSH keys, credential helpers)
- `--no-color` - disable colored output (also honors `NO_COLOR`)

Root pipeline (`risk-guard-local <path>`):

- `--sarif` - merged SARIF output path (default `./risk-guard-report.sarif`)
- `--sbom-format` - `spdx` (default) or `cyclonedx`
- `--sbom-out` - also persist the in-memory SBOM to this path
- `--jobs` - parallel audit workers (default 4)
- `--max-age` - audit cache max age, e.g. `48h` (default); `0` disables caching
- `--no-cache` - force fresh audit scoring
- `--continue-on-error` - emit a partial SARIF when SBOM/audit steps fail (default true)
- `--overrides`, `--policy-override`, `--policy-default`

## License

MIT - see [LICENSE](LICENSE).
