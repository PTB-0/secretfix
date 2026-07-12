# VibeGuard CLI — v1 MVP Design

Date: 2026-07-13

## Context

VibeGuard is a security guardrail aimed at "vibe coders" — people shipping code with
AI assistance who don't have a security background. The overall product vision (see
vault `Projeler/VibeGuard/`) is a trio: pre-commit hook CLI, GitHub Action, and VS Code
extension. Council analysis (2026-06-25) put success probability at ~60%, with framing
as "deploy confidence" rather than "security tool" as the critical differentiator.

Build order agreed with the user: **1) CLI pre-commit hook → 2) GitHub Action →
3) demand validation → 4) VS Code extension.** This spec covers only #1.

## Goal

A zero-config-feeling npm CLI that scans staged changes at commit time for:
secret leaks, common OWASP-style code patterns, and vulnerable dependencies —
explains findings in plain English, and offers to auto-fix them.

## Package

- Name: `vibeguard` (npm)
- Install/setup: `npx vibeguard init`
  - Installs husky if not present
  - Adds a `vibeguard scan` invocation to `.husky/pre-commit`
  - Writes a default `.vibeguardrc.json`

## Architecture

Three independent scanner modules behind a common orchestrator interface
(`scan(stagedFiles) -> Finding[]`), so each can be developed, tested, and disabled
independently.

1. **Secrets scanner** — regex + entropy checks against staged file diffs. Ships with
   known-service signature patterns (AWS, Stripe, OpenAI, generic high-entropy
   strings) plus user-extensible patterns via config.
2. **OWASP pattern scanner** — static regex/AST checks for common vibe-coding
   mistakes: SQL string concatenation, `eval()`/`Function()` usage, hardcoded
   credentials, insecure randomness (`Math.random()` in security contexts), etc.
3. **Dependency CVE scanner** — runs `npm audit` (primary; fast, offline-capable,
   zero extra auth) and cross-references OSV.dev (supplementary; broader/fresher
   coverage), deduplicating overlapping advisories by package+version.

Each scanner returns a common `Finding` shape: `{ scanner, severity, file, line,
message, fix? }`, where `fix` is an optional structured description of an available
automated remediation (used by the interactive fixer).

## Flow

```
git commit
  → husky pre-commit hook
  → vibeguard scan (staged files only)
      → run all 3 scanners, collect Findings
  → no findings → commit proceeds
  → findings found → for each Finding, plain-English report, then prompt:
        "Fix this now? (y/n/skip)"
        y    → apply structured fix (move secret to .env + update .gitignore,
               bump dependency version in package.json, replace/comment out
               unsafe pattern), re-stage affected files
        n/skip → leave as-is
  → if any unresolved findings remain → block commit (non-zero exit)
  → if all resolved → re-run scan on updated staged files, then allow commit
```

## Config

`.vibeguardrc.json` in repo root:
- Per-rule enable/disable (e.g. `"owasp": false`)
- Line-level ignore markers (`// vibeguard-ignore-next-line`)
- CLI flags (`--no-owasp`, `--no-deps`, `--no-secrets`) override config for a single run

## Error Handling

Each scanner runs in isolation. If a scanner throws (e.g. OSV.dev API unreachable),
that scanner's results are dropped, a warning is printed, and the remaining scanners'
results still gate the commit. A single network failure must never silently pass
the commit through, nor must it hang the commit indefinitely — network calls run
with a short timeout and are skipped (with warning) past that timeout.

## Testing

- Unit tests per scanner using fixture files (known secret patterns, known
  vulnerable package versions, known unsafe code patterns) asserting expected
  Findings.
- E2E test driving the interactive fix flow against a scratch git repo (mocked
  stdin for y/n/skip prompts), asserting correct file mutations and correct
  commit block/allow behavior.

## Out of Scope (this spec)

- GitHub Action packaging (separate spec, next in build order)
- VS Code extension
- Non-npm ecosystems (Python, Go, etc.) for dependency scanning
- Paid/Snyk-based scanning
- Telemetry / usage analytics
