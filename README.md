# Risk Guard

Open source risk analysis and scoring for software dependencies.

Risk Guard walks a local git repository, builds an SBOM, runs a graph of scoring checks against the source and its direct dependencies, and emits a single SARIF report. Use it locally to spot risky dependencies before you adopt them, or in CI to gate pull requests.

Supported ecosystems: `npm`, `pypi`, `rubygems`.

## Install

Download a prebuilt binary from the [GitHub Releases page](https://github.com/Risk-Guard/oss-risk-guard/releases), or build from source (requires Go 1.25.1+):

```bash
git clone https://github.com/Risk-Guard/oss-risk-guard.git
cd oss-risk-guard
go build -o risk-guard ./src/cli/local
```

## Usage

Score the current repository and emit a SARIF report:

```bash
risk-guard .
```

Run `risk-guard --help` to see all subcommands and flags.

## Configuration

Risk Guard reads two optional files from the repository root:

- **`.risk-guard.yml`** — workflow config (scoring mode, policy, overrides).
- **`.riskguardignore`** — gitignore-style patterns excluding paths from scanning.

See [docs/configuration.md](docs/configuration.md) for an annotated example.

## License

MIT — see [LICENSE](LICENSE).
