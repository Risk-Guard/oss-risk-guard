# Risk Guard

Open source risk analysis and scoring for software dependencies. Runs a scoring DAG against a local git repository and emits SARIF results.

## Quick Start

```bash
# Score the current repository
go run src/cli/local . 

# Audit direct dependencies from an SBOM
go run src/cli/local audit <path>

# Score a single package by its analysis-identifier key
go run src/cli/local audit-package <package-key>

# Generate an SBOM (SPDX or CycloneDX) for a local repository
go run src/cli/local sbom <path>

# Render a human-readable summary of an audit SARIF file
go run src/cli/local view-audit <sarif-file>
```

Results are written to `<path>/.risk-guard/cache/`.

## Supported Ecosystems

- `npm` - JavaScript / Node.js
- `pypi` - Python
- `rubygems` - Ruby

## Flags

- `--log-level` - `debug`, `info`, `warn` (default), `error`
- `--logfile` - write debug logs to a file in addition to console
- `--secure-git` - isolate git from local config/credentials (blocks SSH keys, credential helpers)
- `--no-color` - disable colored output (also honors `NO_COLOR`)

## License

MIT - see [LICENSE](LICENSE).
