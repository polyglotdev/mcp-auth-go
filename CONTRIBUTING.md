# Contributing

Thanks for your interest in `mcp-auth-go`. This is a small, focused security
library, so the bar for changes is high and the setup is short.

## Prerequisites

- Go 1.26 or newer (`go version`)
- [golangci-lint](https://golangci-lint.run/) v2 (`golangci-lint version`)

## Build, lint, test

One command runs the whole gate — formatting, `go vet`, the linter, and the
race-enabled test suite:

```sh
make check
```

It must pass before a change is ready. The individual targets (`make fmt`,
`vet`, `lint`, `race`, `tidy`) are there if you want to run them piecemeal.

## What we expect from a change

- **Idiomatic Go.** Follow the [Google Go Style Guide](https://google.github.io/styleguide/go/).
  The linter config in `.golangci.yml` enforces the bulk of it.
- **No panics in library code** except the documented exceptions: construction-time
  guards for missing required config, `Must*` helpers, and unrecoverable failures
  (e.g. `crypto/rand`). Everything else returns a typed `*Error`.
- **The core stays transport-neutral.** `transport/http` may import the root
  package; the root package must never import a transport.
- **Tests are part of the change.** Cover new behavior with table-driven tests,
  and add a runnable `ExampleXxx` for new public API where it reads well — these
  double as documentation on pkg.go.dev. Bug fixes get a regression test.
- **Public API is documented.** Every exported identifier has a godoc comment
  that explains the non-obvious (constraints, errors returned, concurrency),
  not the obvious.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the package layout, the
authentication-versus-authorization split, and why authorization is injected
rather than hard-coded.

## Commits and pull requests

- Small, focused commits with imperative subject lines ("add", not "added").
- Keep history linear — rebase to integrate; don't merge or squash.
- A PR should say what changed, why, how it was tested, and the risk.
