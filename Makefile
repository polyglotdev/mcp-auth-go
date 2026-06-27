# Makefile for github.com/polyglotdev/mcp-auth-go
#
# `make check` is the full local gate: formatting, vet, lint, and race tests.
# It covers the root module and every nested module (transport/mcpauth ships its
# own go.mod so the MCP Go SDK stays out of the core module's graph).

.PHONY: all fmt fmt-check vet lint test race tidy check

# Module directories: the root module plus each nested module. gofmt is
# path-based and already covers every file from the root, but vet/lint/test are
# module-scoped (./... stops at a nested go.mod) and must run in each module.
GO_MODULE_DIRS := . transport/mcpauth audit/otel dpop/redisreplay

all: check

## fmt: format all Go source in place (path-based, covers nested modules).
fmt:
	gofmt -s -w .

## fmt-check: fail if any file is not gofmt-clean (CI gate).
fmt-check:
	@test -z "$$(gofmt -l .)" || { echo "unformatted files:"; gofmt -l .; exit 1; }

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
