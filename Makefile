# Makefile for github.com/polyglotdev/mcp-auth-go
#
# `make check` is the full local gate: formatting, vet, lint, and race tests.
# It covers the root module and every nested module (transport/mcpauth ships its
# own go.mod so the MCP Go SDK stays out of the core module's graph).

.PHONY: all help fmt fmt-check vet lint test race tidy check govulncheck actions-lint sbom

# Module directories: the root module plus each nested module. gofmt is
# path-based and already covers every file from the root, but vet/lint/test are
# module-scoped (./... stops at a nested go.mod) and must run in each module.
GO_MODULE_DIRS := . transport/mcpauth audit/otel dpop/redisreplay

all: check

## help: print this help message (targets are annotated with `## name: desc`).
help:
	@echo "Available targets:"
	@grep -E '^## [a-zA-Z0-9_-]+: ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ": "}; {sub(/^## /, ""); printf "  \033[36m%-20s\033[0m %s\n", $$1, substr($$0, index($$0, ": ")+2)}'

## fmt: format all first-party Go source in place (gofmt -s -w).
## Path-based, so it covers nested modules; vendored third-party code is
## excluded - we never reformat it.
fmt:
	@find . -name '*.go' -not -path '*/vendor/*' -print0 | xargs -0 gofmt -s -w

## fmt-check: fail if any first-party file is not gofmt-clean (CI gate).
## vendor/ is excluded: vendored deps are not ours to format and may not be
## gofmt-clean under our gofmt version.
fmt-check:
	@unformatted=$$(find . -name '*.go' -not -path '*/vendor/*' -print0 | xargs -0 gofmt -l); \
	  test -z "$$unformatted" || { echo "unformatted files:"; echo "$$unformatted"; exit 1; }

## vet: run go vet across all packages in every module.
vet:
	@for dir in $(GO_MODULE_DIRS); do echo "==> go vet ($$dir)"; (cd "$$dir" && go vet ./...) || exit 1; done

## lint: run golangci-lint (config in .golangci.yml) in every module.
lint:
	@for dir in $(GO_MODULE_DIRS); do echo "==> golangci-lint ($$dir)"; (cd "$$dir" && golangci-lint run ./...) || exit 1; done

## test: run the unit tests in every module.
test:
	@for dir in $(GO_MODULE_DIRS); do echo "==> go test ($$dir)"; (cd "$$dir" && go test -count=1 ./...) || exit 1; done

## race: run the unit tests with the race detector in every module.
race:
	@for dir in $(GO_MODULE_DIRS); do echo "==> go test -race ($$dir)"; (cd "$$dir" && go test -race -count=1 ./...) || exit 1; done

## tidy: tidy and verify the module graph in every module.
tidy:
	@for dir in $(GO_MODULE_DIRS); do echo "==> go mod tidy ($$dir)"; (cd "$$dir" && go mod tidy && go mod verify) || exit 1; done

## check: full local gate — formatting, vet, lint, race tests.
check: fmt-check vet lint race

## govulncheck: scan every module for known vulnerabilities (mirrors CI).
govulncheck:
	@command -v govulncheck >/dev/null 2>&1 || go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
	@for dir in $(GO_MODULE_DIRS); do echo "==> govulncheck ($$dir)"; (cd "$$dir" && govulncheck ./...) || exit 1; done

## actions-lint: lint and security-audit the GitHub Actions workflows (mirrors CI).
actions-lint:
	@command -v actionlint >/dev/null 2>&1 || go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
	actionlint .github/workflows/*.yml
	@command -v zizmor >/dev/null 2>&1 && zizmor .github/ || echo "zizmor not installed; see https://docs.zizmor.sh/installation/"

## sbom: generate a CycloneDX SBOM of the dependency tree (requires syft).
sbom:
	@command -v syft >/dev/null 2>&1 || { echo "syft not installed; see https://github.com/anchore/syft"; exit 1; }
	syft scan dir:. -o cyclonedx-json=sbom.cdx.json
	@echo "wrote sbom.cdx.json"
