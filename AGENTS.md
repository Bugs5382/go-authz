# AGENTS.md - go-authz

Guide for AI agents working in this repository. Pair with `CLAUDE.md` (the working agreement and
hook-enforced rules). Keep this file current when the build, layout, or public API changes.

## What this is

A small, dependency-free, general-purpose authorization engine for Go. The consuming application
configures the model (rules, a default effect, a combining algorithm); the library provides the
decision types and evaluation. It is framework-agnostic: it returns decisions and ships no
HTTP/gRPC middleware.

## Using go-authz

The single entry point is `NewPolicy`, which returns a `*Policy` implementing the `Evaluator`
interface (`Decide(ctx, Request) Decision`). Applications compose behaviour from `Rule`s:

- functional rules (`NewRule`, `AllowWhen`, `DenyWhen`) plus matchers (`SubjectIs`, `ResourceIs`,
  `ActionIs`, `All`, `Any`);
- `RBAC` for role-based grants;
- `Matrix` for a responsibility (access) matrix: a subject x resource x action table.

Invariants that must not be bypassed: `Deny` is the zero value of `Effect` (fail-safe); the default
policy (no rules) denies everything; the public surface is a semver-stable v1 contract - additions
are fine, removals need a major bump.

## Layout

- `effect.go`, `request.go`, `decision.go`, `rule.go` - core types and the public contract.
- `combiner.go` - combining algorithms (`FirstApplicable`, `DenyOverrides`, `AllowOverrides`).
- `policy.go` - `Policy`, options, `Decide`.
- `match.go` - functional rules and matchers.
- `rbac.go`, `matrix.go` - the RBAC and responsibility-matrix rule types.
- `doc.go`, `example_test.go` - package doc and runnable examples.
- `authz_test.go` - unit tests.

## Build, test, lint

- Build: `task build` (`go build ./...`)
- Test: `task test` (`go test ./...`); no external services required.
- Full gate: `task ci` (build, vet, test, lint).
- Lint: `task lint` (gofmt check + golangci-lint + yamllint).
- License headers: `task license` (dry-run check) / `task license:fix` (inject).

## Conventions and gotchas

- See `CLAUDE.md` for branch/commit/PR rules; they are enforced by the git hooks in `.claude/hooks`
  (run `bash .claude/hooks/install.sh` once per clone).
- Open every PR as a draft. CI skips drafts, so run the full checks locally, push once they pass,
  and mark the PR ready when the work is finished; see CLAUDE.md "CI and Actions minutes".
- This is a PUBLIC library: no company, product, or internal names anywhere.
- `Wildcard` ("*") is the wildcard token in `RBAC` grants and `Matrix` entries; it collides with a
  literal "*" value, so do not use wildcards for a dimension that legitimately holds "*".
