# Security Policy

`mcp-auth-go` is an authentication and authorization library. Security is the
product, so we treat vulnerability reports seriously and aim to respond quickly.

## Supported versions

The library is pre-1.0. Security fixes are applied to the latest tagged minor
release. Pin a specific version and upgrade promptly when an advisory is
published.

| Version       | Supported   |
| ------------- | ----------- |
| latest `v0.x` | yes         |
| older `v0.x`  | best effort |

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Do not open a public issue,
pull request, or discussion for a security problem, and do not include exploit
details in any public channel.

Preferred channel: GitHub private vulnerability reporting.

1. Go to the repository's "Security" tab.
2. Choose "Report a vulnerability" under "Advisories".
3. Include affected version(s), a description, reproduction steps, and impact.

If private reporting is unavailable to you, contact the maintainer through the
profile listed at <https://github.com/polyglotdev> and request a private channel
before sharing any details.

## What to expect

- Acknowledgement of your report within 3 business days.
- An initial assessment (severity, affected versions) within 7 business days.
- Coordinated disclosure: we will agree on a timeline with you, prepare a fix
  and a GitHub Security Advisory, and credit you unless you prefer to remain
  anonymous.

## Scope

In scope:

- The Go module and its subpackages (token validation, claims, verifiers,
  session store, HTTP transport, DPoP, introspection, audit, exchange).
- The CI/CD workflows in this repository.

Out of scope:

- Vulnerabilities in your own integration or configuration (for example,
  misconfigured issuer, audience, or claim policy).
- Vulnerabilities in third-party dependencies that are already tracked by an
  upstream advisory; report those upstream. We will pick up the fix via
  Dependabot and govulncheck.

## How we secure this project

This repository runs a layered, defense-in-depth pipeline. All of it is visible
in `.github/workflows/` and the Security tab:

- CI gate (`make check` equivalent) across every module: gofmt, `go vet`,
  golangci-lint, and `-race` tests.
- CodeQL static analysis.
- govulncheck (Go vulnerability scanning) on every module, plus a weekly run so
  newly disclosed advisories in unchanged dependencies are still caught.
- gosec SAST.
- Dependency review on pull requests, blocking known-vulnerable dependencies.
- gitleaks secret scanning over full history.
- zizmor auditing of our own GitHub Actions workflows.
- OpenSSF Scorecard, published publicly.
- Dependabot across the `github-actions` ecosystem and all four Go modules.

Supply-chain hardening of the pipeline itself:

- Every third-party action is pinned to a full commit SHA, not a mutable tag.
- Every job is least-privilege (`contents: read` by default), runs on a pinned
  runner image, hardens the runner egress, checks out without persisting
  credentials, and sets an explicit timeout.
- No `pull_request_target`; privileged steps never run for fork pull requests.

## Maintainer runbook: repository settings to enable

These controls cannot be set by committed files alone. The maintainer should
enable them to complete the security posture and raise the Scorecard result:

1. Settings > Code security: enable private vulnerability reporting, secret
   scanning, and push protection.
2. Branch protection (or a ruleset) on `main`:
   - Require pull request review (with CODEOWNERS review).
   - Require the CI, govulncheck, dependency review, and zizmor checks to pass.
   - Require branches to be up to date before merging.
   - Disallow force pushes and deletions.
   - Require signed commits.
3. Code scanning: confirm the CodeQL, gosec, govulncheck, zizmor, and Scorecard
   SARIF uploads appear under Security > Code scanning.
4. Actions settings: restrict to SHA-pinned and trusted actions; require approval
   for fork pull request workflows.
