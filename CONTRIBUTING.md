# Contributing

Thanks for your interest in improving Risk Guard.

## Development

Requires Go 1.25.1+.

```bash
go run ./cmd/risk-guard .    # run the full pipeline against the current repo
go test ./...                # tests
go build -o ./risk-guard ./cmd/risk-guard # build 
```

Formatting and linting use [golangci-lint](https://golangci-lint.run/) v2
(config in [`.golangci.yml`](.golangci.yml)):

```bash
golangci-lint fmt           # apply gofumpt + goimports formatting
golangci-lint run           # lint
```

## Pull requests

- Keep changes focused; one logical change per PR.
- Add or update tests for behavior changes.
- Make sure `golangci-lint fmt`, `golangci-lint run`, `go test ./...`, and
  `go build ./...` all pass before opening the PR.
- For security issues, see [SECURITY.md](SECURITY.md) — do not open a public issue.
