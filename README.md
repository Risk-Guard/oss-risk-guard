# Risk Guard

Open source risk analysis and scoring for software dependencies.

**Website:** [risk-guard.github.io/oss-risk-guard](https://risk-guard.github.io/oss-risk-guard/)

Risk Guard walks a local git repository, builds an SBOM, scores the source and
its direct dependencies against supply-chain risk checks — missing licenses,
install scripts, abandoned upstreams — and emits a single SARIF report. Use it
locally before adopting a dependency, or in CI to gate pull requests.

Ecosystems: `npm`, `pypi`, `rubygems`.

Everything runs on your machine by default. Risk Guard fetches only public
package metadata and source repositories; it never uploads your code. (The
opt-in `--risk-guard` flag offloads dependency scoring to the Risk Guard
server, which does upload your SBOM and source findings.)

## Install

```bash
# Linux / macOS — detects OS/arch, verifies checksum, installs to /usr/local/bin
curl -fsSL https://risk-guard.github.io/oss-risk-guard/get.sh | sh

# Go 1.25.8+
go install github.com/Risk-Guard/oss-risk-guard/cmd/risk-guard@latest
```

Prebuilt archives for Linux, macOS, and Windows are on the
[Releases page](https://github.com/Risk-Guard/oss-risk-guard/releases).

## Usage

```bash
risk-guard .
```

The argument is a path to a git repository. The report is written to
`./risk-guard-report.sarif`. Run `risk-guard --help` for the full flag list.

Subcommands expose individual stages:

| Command | What it does |
| --- | --- |
| `audit source <path>` | Score the local source repo only. |
| `audit deps` | Audit direct dependencies from an SBOM. |
| `audit package <key>` | Score one package, e.g. `package/npm/express`. |
| `audit view <sarif>` | Render a human-readable summary of a SARIF file. |
| `sbom <path>` | Generate an SBOM (SPDX or CycloneDX). |
| `init [path]` | Scan and write a `.risk-guard.yml` seeded from the findings. |
| `policy show [path]` | Print the effective policy. |
| `policy checks` | List all available checks and their risk categories. |
| `policy override [path]` | Set a package/source output override in `.risk-guard.yml`. |
| `policy add-expected-failures [path]` | Merge a report's blocking findings into `expected_failures`. |

`risk-guard audit view risk-guard-report.sarif` re-renders a saved report:

```
Policy result:
  2 blocking  3 warning  0 acknowledged  2 ignored

your repository — 4 finding(s): 1 error, 3 warning

  ERROR    No license file found in source repository
           SOURCE_NO_LICENSE
```

## CI

GitHub Actions — findings appear in the **Security** tab and inline on PRs:

```yaml
- uses: actions/checkout@v6
- uses: Risk-Guard/action@v1   # needs security-events: write
```

GitLab CI/CD — findings show in the merge request widget:

```yaml
include:
  - component: $CI_SERVER_FQDN/risk-guard/components/scan@1.0.3
```

Anywhere else, let the exit code gate the build:

```bash
risk-guard . --github                              # Actions annotations + SARIF
risk-guard . --gitlab gl-code-quality-report.json  # GitLab Code Quality + SARIF
```

The exit code is non-zero when there are blocking findings and the workflow
mode is `active`. `--mode no-fail` observes findings without failing the build.

## Configuration

Two optional files in the repository root:

- **`.risk-guard.yml`** — scoring mode, the policy deciding which findings
  block vs. warn vs. ignore, and acknowledged exceptions.
- **`.riskguardignore`** — gitignore-style patterns excluding paths.

`risk-guard init` writes a starter config. See
[docs/configuration.md](docs/configuration.md) for the annotated schema.

## Development

Requires Go 1.25.8+.

```bash
go run ./cmd/risk-guard .
go test ./...
golangci-lint fmt && golangci-lint run
```
