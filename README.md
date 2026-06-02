# Risk Guard

Open source risk analysis and scoring for software dependencies.

Risk Guard walks a local git repository, builds an SBOM (software bill of
materials), runs a graph of scoring checks — rules that flag supply-chain risk
such as missing licenses, install scripts, or abandoned upstreams — against the
source and its direct dependencies, and emits a single SARIF report (the
code-scanning format GitHub and GitLab render inline). Use it locally to spot
risky dependencies before you adopt them, or in CI to gate pull requests.

Supported ecosystems: `npm`, `pypi`, `rubygems`.

Risk Guard runs entirely on your machine. It fetches only public package
metadata, artifacts, and source repositories from the registries and forges it
analyzes — it never uploads your code or dependency list to any Risk Guard server.

## Install

Pick whichever fits your machine. Each gives you a `risk-guard` binary.

### Install script (Linux / macOS)

Download the latest prebuilt binary in one command:

```bash
curl -fsSL https://raw.githubusercontent.com/Risk-Guard/oss-risk-guard/main/getRiskGuard.sh | sh
```

It detects your OS/arch, downloads the matching release archive, verifies its
checksum, and installs to `/usr/local/bin` (or `~/.local/bin` if that isn't
writable). Customize with:

```bash
# Pin a version
curl -fsSL https://raw.githubusercontent.com/Risk-Guard/oss-risk-guard/main/getRiskGuard.sh | sh -s -- v0.0.2

# Install somewhere else
curl -fsSL https://raw.githubusercontent.com/Risk-Guard/oss-risk-guard/main/getRiskGuard.sh | RISK_GUARD_INSTALL_DIR="$HOME/bin" sh
```

On an architecture without a prebuilt binary, the script points you at the
`go install` method below.

### Prebuilt binary

Download an archive for your platform from the
[GitHub Releases page](https://github.com/Risk-Guard/oss-risk-guard/releases),
unpack it, and put `risk-guard` on your `PATH`. Builds are published for Linux
(amd64, arm64, armv7), macOS (amd64, arm64), and Windows (amd64, arm64), each with
a `checksums-*.txt` for verification.

```bash
tar xzf risk-guard-<version>-linux-amd64.tar.gz
sudo mv risk-guard /usr/local/bin/
risk-guard --version
```

### Go install

If you have Go 1.25.1+ installed, install straight from source — no clone needed:

```bash
go install github.com/Risk-Guard/oss-risk-guard/cmd/risk-guard@latest
```

This drops a `risk-guard` binary in `$(go env GOPATH)/bin` (usually `~/go/bin`).
Make sure that directory is on your `PATH`.

### Build from source

```bash
git clone https://github.com/Risk-Guard/oss-risk-guard.git
cd oss-risk-guard
go build -o risk-guard ./cmd/risk-guard
```

## Usage

Run the full pipeline against an on-disk git repository — score the local source,
build an SBOM, audit each direct dependency, and write one merged SARIF report:

```bash
risk-guard .
```

The single argument is a path to an existing git repository. By default the report
is written to `./risk-guard-report.sarif`.

```bash
risk-guard /path/to/repo --sarif report.sarif      # choose the output file
risk-guard . --sbom-format cyclonedx --sbom-out sbom.cdx.json
risk-guard . --jobs 8                               # audit more packages in parallel
risk-guard . --continue-on-error=false              # fail instead of emitting partial SARIF
```

Run `risk-guard --help` (or `risk-guard <command> --help`) for the full flag list.

### Example output

The SARIF report renders inline in GitHub/GitLab. Locally,
`risk-guard view-audit risk-guard-report.sarif` prints a summary like:

> **⚠️ 20 warning · 🔵 4 acknowledged · ⬜ 9 ignored**

| Severity | Subject | Finding | Rule |
| --- | --- | --- | --- |
| ⚠️ warning | requests (pypi) | artifact has install-time scripts | `PACKAGE_INSTALL_SCRIPTS` |
| ⚠️ warning | is-even@1.0.0 (npm) | No security policy file found | `SOURCE_NO_SECURITY_POLICY` |
| ⚠️ warning | your repository | package does not declare a license | `PACKAGE_NO_LICENSE` |
| ⚠️ warning | f-ask (pypi) | source is 2632 days ahead of last release | `PACKAGE_UNRELEASED_CHANGES` |
| ⬜ info | is-even@1.0.0 (npm) | last repository commit was 2981 days ago | `SOURCE_REPO_ABANDONED` |

### Subcommands

The root command runs the complete pipeline. These subcommands expose individual
stages:

| Command | What it does |
| --- | --- |
| `scan <path>` | Score the local source repo only — no dependency audit. |
| `audit` | Audit direct dependencies from an SBOM. |
| `audit-package <key>` | Score a single package by key, e.g. `package/npm/express` or `package/npm/lodash?version=4.17.20`. |
| `sbom <path>` | Generate an SBOM (SPDX or CycloneDX) for a local repo. |
| `init [path]` | Run an initial scan and write a `.risk-guard.yml` seeded from the findings. |
| `view-audit <sarif>` | Render a human-readable summary of an audit SARIF file. |
| `policy show [path]` | Print the effective policy (built-in default overlaid with the repo's `.risk-guard.yml`). |
| `policy add-expected-failures [path]` | Acknowledge findings by merging a SARIF report's blocking findings into `expected_failures` in `.risk-guard.yml`. |

### Common flags

These persistent flags apply to every command:

| Flag | Default | Purpose |
| --- | --- | --- |
| `--cache-dir` | `os.UserCacheDir()/risk-guard` | Cache root for DAG outputs, clones, and network/audit caches. Also set via `RISK_GUARD_CACHE_DIR`. |
| `--log-level` | `warn` | `debug`, `info`, `warn`, or `error`. |
| `--logfile` | — | Also write debug logs to a file. |
| `--secure-git` | `false` | Isolate git from local config/credentials (blocks SSH keys and credential helpers). |
| `--color` | `auto` | Colored output: `auto` (honors TTY + `NO_COLOR`), `always`, or `never`. |
| `--no-color` | `false` | Deprecated alias for `--color=never`. |

## Use in CI

### GitHub Actions

Use the [Risk Guard Action](https://github.com/Risk-Guard/action). Findings appear
in the **Security** tab and inline on pull requests.

```yaml
jobs:
  risk-guard:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v6
      - uses: Risk-Guard/action@v1
```

### GitLab CI/CD

Use the [Risk Guard component](https://gitlab.com/risk-guard/components). Findings
show in the merge request widget (all tiers) and the Security tab (Ultimate).

```yaml
include:
  - component: $CI_SERVER_FQDN/risk-guard/components/scan@1.0.3
```

### Other CI, or running the CLI directly

Run the pipeline and let the exit code gate the build:

```bash
risk-guard . --github                              # GitHub Actions annotations + SARIF
risk-guard . --gitlab gl-code-quality-report.json  # GitLab Code Quality report + SARIF
```

- The exit code is non-zero when there are blocking findings and the effective
  workflow mode is `active`. Modes `no-fail`, `silent`, and `disabled` never fail
  the build.
- `--mode` overrides `workflow.mode` from `.risk-guard.yml` for a single run, e.g.
  `--mode no-fail` to observe findings without breaking the build.

Upload `risk-guard-report.sarif` to GitHub code scanning, or expose the GitLab
Code Quality report as an artifact, to render findings inline:

```yaml
risk-guard:
  script:
    - risk-guard . --gitlab gl-code-quality-report.json
  artifacts:
    reports:
      codequality: gl-code-quality-report.json
```

## Configuration

Risk Guard reads two optional files from the repository root:

- **`.risk-guard.yml`** — workflow config: scoring mode, the policy that decides
  which findings block vs. warn vs. ignore, acknowledged exceptions, and overrides.
- **`.riskguardignore`** — gitignore-style patterns excluding paths from scanning.

`risk-guard init` generates a starter `.risk-guard.yml` from a first scan. See
[docs/configuration.md](docs/configuration.md) for the annotated schema.

## Development

Requires Go 1.25.1+. Run the CLI without building a binary:

```bash
go run ./cmd/risk-guard .                    # full pipeline against the current repo
go run ./cmd/risk-guard scan .               # source-only scan
go run ./cmd/risk-guard --help
```

Tests and the build:

```bash
go test ./...
go build ./...
```

Linting uses [golangci-lint](https://golangci-lint.run/) with the config in
[`.golangci.yml`](.golangci.yml):

```bash
golangci-lint fmt    # apply gofumpt + goimports formatting
golangci-lint run    # lint
```

## License

MIT — see [LICENSE](LICENSE).
