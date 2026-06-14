# Contributing to ironrun

## Getting Started

```bash
git clone https://github.com/generalized-labs/ironrun.git
cd ironrun
go build ./cmd/ironrun
go test ./...
```

## Pull Requests

1. Open an issue first describing what you want to change
2. Fork and branch from `main`
3. Write tests for new functionality
4. Run `go vet ./...` and ensure tests pass
5. Submit a PR referencing the issue

## Code Style

- `gofmt` everything
- Small, focused packages in `internal/`
- Minimal external dependencies
- Table-driven tests

## Adding a Provider

Providers live in `internal/provider/`. Implement the `Provider` interface:

```go
type Provider interface {
    Name() string
    Resolve(ref string) (string, error)
}
```

Register it in `internal/provider/registry.go`.

## Security

Report vulnerabilities per [SECURITY.md](SECURITY.md). Do not open public issues for security bugs.
