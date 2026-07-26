# Web Vulnerability Detection — Design

Date: 2026-07-26

## Context

`secretfix` (see `2026-07-13-cli-mvp-design.md`) ships three scanners behind a common
orchestrator: `secrets`, `owasp`, `deps`. The `owasp` scanner matches generic code
patterns — `eval`, SQL string concatenation, `innerHTML`, disabled TLS verification.
None of them are **web-application** vulnerabilities: an API route with no auth check,
a request body passed straight into an ORM write, a secret inlined into the browser
bundle, wide-open BaaS rules. Those are the holes that actually take vibe-coded sites
down, and the tool currently sees none of them.

This spec adds that coverage.

### Scope decomposition

The request ("catch well-known basic website vulnerabilities") covers two independent
systems. They are specced separately:

| Sub-project | What | Why separate |
|---|---|---|
| **A. Web SAST rules** *(this spec)* | A web-specific rule family in a new `web` scanner | Fits the existing pre-commit architecture; no network; `Finding`/fixer machinery already exists |
| **B. `check-site` DAST command** *(future spec)* | HTTP probing of a live URL | New command, network layer, rate limiting, "is this your site" authorisation, read-only (no fixes) |

A is specced first because B's findings route back into A's rules — a missing CSP header
is *observed* live but *fixed* in `next.config.js`. Knowing A's rule set is a
prerequisite for deciding where B's output points.

## Goal

Detect the common web-application vulnerability classes in staged changes, explain each
in plain English, auto-fix only where the correct fix is mechanically derivable, and
never block a commit on a finding that cannot be substantiated.

## Naming

The package is currently named `secretfix` (`package.json`), and the inline suppression
marker is `secretfix-ignore-next-line`. This spec uses those names. The directory and
the v1 spec still say "VibeGuard"; renaming is out of scope here.

---

## 1. Rule catalogue

26 rules in four groups. `C` = certain (blocks at its declared severity).
`H` = heuristic (subject to cross-file verification; see §5).

### Agnostic — any JS/TS file (11)

| # | Rule id | Sev | Conf |
|---|---|---|---|
| 1 | `agnostic/path-traversal` — `fs.*` called with a request-derived path | critical | C |
| 2 | `agnostic/ssrf` — `fetch`/`axios`/`got` with a request-derived URL | high | C |
| 3 | `agnostic/nosql-injection` — `req.body` used directly as a Mongo filter, or `$where` | critical | C |
| 4 | `agnostic/open-redirect` — `redirect(req.query.next)` with no validation | medium | C |
| 5 | `agnostic/mass-assignment` — `prisma`/`db` write with `data: req.body` | critical | C |
| 6 | `agnostic/plaintext-password-compare` — `password === user.password` | critical | C |
| 7 | `agnostic/jwt-unverified` — `jwt.decode()` in an auth decision, or `algorithms: ['none']` | critical | C |
| 8 | `agnostic/insecure-cookie` — cookie set without `httpOnly`/`secure`/`sameSite` | high | C |
| 9 | `agnostic/error-stack-to-client` — `err.stack` or a raw error object in a response | medium | C |
| 10 | `agnostic/cors-wildcard-credentials` — `origin: '*'` together with `credentials: true` | high | C |
| 11 | `agnostic/no-rate-limit-on-auth` — login/register handler with no rate-limit evidence | medium | H |

### Next.js (8)

| # | Rule id | Sev | Conf |
|---|---|---|---|
| 12 | `nextjs/public-env-secret` — `NEXT_PUBLIC_*` name containing SECRET/KEY/TOKEN/PASSWORD | critical | C |
| 13 | `nextjs/service-role-key-in-client` — service-role/admin key referenced in a `'use client'` file | critical | C |
| 14 | `nextjs/route-handler-no-auth` — route handler with no auth evidence | high/medium | H |
| 15 | `nextjs/server-action-no-auth` — `'use server'` function with no auth evidence | high/medium | H |
| 16 | `nextjs/missing-security-headers` — `next.config.*` staged, no `headers()` block | high | C |
| 17 | `nextjs/middleware-matcher-gap` — `middleware.ts` exists but its matcher misses `/admin` | high | H |
| 18 | `nextjs/images-wildcard` — `images.domains: ['*']` or a `**` remote pattern | medium | C |
| 19 | `nextjs/dangerous-rewrite` — `rewrites()` destination interpolates a request parameter | high | C |

### Express (4)

| # | Rule id | Sev | Conf |
|---|---|---|---|
| 20 | `express/static-serves-project-root` — `express.static(__dirname)`, exposing `.env` | critical | C |
| 21 | `express/no-helmet` — app entry staged, no `helmet()` (explain-only, no fix) | medium | C |
| 22 | `express/route-no-auth` — state-changing route with no auth-middleware evidence | high/medium | H |
| 23 | `express/csrf-missing` — cookie session plus state-changing POST, no CSRF protection | medium | H |

### BaaS config (3)

| # | Rule id | Sev | Conf |
|---|---|---|---|
| 24 | `baas/firebase-rules-open` — `allow read, write: if true` | critical | C |
| 25 | `baas/supabase-rls-disabled` — `DISABLE ROW LEVEL SECURITY` in a migration | critical | C |
| 26 | `baas/service-role-key-exposed` — `SUPABASE_SERVICE_ROLE_KEY` reachable from client code | critical | C |

Rule 26 excludes what rule 13 already covers: it does not evaluate files carrying a
`'use client'` directive, so a Next.js client component with a service-role key produces
one finding (13), not two.

### Deliberately excluded

- **XSS sinks** (`innerHTML`, `dangerouslySetInnerHTML`) and **`eval`** — already covered
  by the `owasp` scanner. Re-adding them would produce duplicate findings on one line.
- **Timing attacks, prototype pollution, ReDoS, XXE** — outside "well-known basic" and
  with false-positive rates that do not fit a commit-time gate.

---

## 2. Architecture

Three independent rule families behind one new scanner, `web`, registered alongside the
existing three. `owasp` is left untouched.

```
src/scanners/web/
  index.ts          webScanner: Scanner — runs rules, maps confidence to severity
  detect.ts         framework detection from package.json + file layout
  context.ts        ScanContext construction + per-run read cache
  block.ts          extractBlock() — brace-balanced body slicing
  verify.ts         auth-evidence and risk-signal heuristics
  types.ts          LineRule / BlockRule / FileRule
  rules/agnostic.ts
  rules/nextjs.ts
  rules/express.ts
  rules/baas.ts
src/fix/ai.ts       optional AI fix layer (§7, lazily imported)
src/report.ts       --json report for agent handoff (§7)
```

### 2.1 `ScanContext`

Web rules need to read outside the staged set (`package.json` for framework detection,
`middleware.ts` for auth verification). Rather than widen the shared `Scanner` interface,
the context is injected by **closure**: the web scanner is a factory.

```ts
export type Framework = 'agnostic' | 'nextjs' | 'express' | 'supabase' | 'firebase';

export interface ScanContext {
  cwd: string;
  frameworks: ReadonlySet<Framework>;
  /** Reads a repo file that may not be staged. Cached per run. */
  readRepoFile(path: string): string | undefined;
}

export function createWebScanner(context: ScanContext): Scanner;
```

`types.ts`'s `Scanner` interface, `orchestrator.ts`, and all three existing scanners are
therefore **completely untouched**, as are the 25 direct `.scan(files)` call sites in the
existing tests. Only `selectScanners` changes, gaining the context so it can build the
web scanner:

```ts
function selectScanners(config: SecretFixConfig, context: ScanContext): Scanner[]
```

An earlier draft of this spec widened `Scanner.scan` to take the context as a second
parameter. That was rejected during planning: it would have made every existing
one-argument `.scan(files)` test call a type error (25 of them), and it forces a
context-shaped parameter onto three scanners that have no use for it. Constructor
injection is the smaller and more honest change.

`readRepoFile` reads **the index first** (`git show :path`, the same path
`getStagedFiles` already uses), falling back to the working tree. The index is the
correct source for a verification read: the question is whether the *committed* code has
an auth check, not whether an unstaged edit does. `git.ts` gains a small
`readIndexFile(path, cwd)` helper.

### 2.2 Framework detection

`detect.ts` reads `package.json` through `readRepoFile` and inspects
`dependencies`/`devDependencies`:

| Dependency | Framework |
|---|---|
| `next` | `nextjs` |
| `express` | `express` |
| `@supabase/*` | `supabase` |
| `firebase`, `firebase-admin` | `firebase` |

`agnostic` is always present. A missing or unparseable `package.json` yields
`{ agnostic }` only — never an error. Detection runs once per scan and is cached on the
context. Rules whose `frameworks` do not intersect the detected set are skipped without
being evaluated.

### 2.3 Rule shapes

```ts
type Confidence = 'certain' | 'heuristic';

/** One match, anchored to the line the finding is reported against. */
interface Hit {
  line: number;
  /** Appended to the rule's message when the match needs naming (a route path, a field). */
  detail?: string;
  /** Present only when a deterministic rewrite exists for this match. */
  fix?: FixDescriptor;
  /** Set by a heuristic rule's own verification; see §5. */
  resolved?: { severity: Severity } | 'drop';
}

interface RuleBase {
  id: string;
  group: 'injection' | 'auth' | 'exposure' | 'hardening';
  frameworks: readonly Framework[];
  severity: Severity;
  confidence: Confidence;
  message: string;
}

interface LineRule  extends RuleBase { kind: 'line';  regex: RegExp; fix?: (line: string) => FixDescriptor | undefined }
interface BlockRule extends RuleBase { kind: 'block'; find: (file: StagedFile, ctx: ScanContext) => Hit[] }
interface FileRule  extends RuleBase { kind: 'file';  appliesTo: RegExp; check: (file: StagedFile, ctx: ScanContext) => Hit[] }
```

The 26 rules split as:

- **`BlockRule` (7)** — 5, 10, 11, 14, 15, 22, 23. These need a brace-delimited region in
  view, because the evidence is routinely spread over several lines: a request body bound
  to a local before the ORM write (5), a multi-line `cors({ ... })` options object (10),
  a handler body with no auth call anywhere in it (11, 14, 15, 22, 23).
- **`FileRule` (3)** — 16, 17, 21. These describe a config file as a whole and carry
  `scope: 'file'`.
- **`LineRule` (16)** — everything else: pure data, one regex plus a message.

Because scanning is line-by-line, a `LineRule` regex only ever sees one line. Rules whose
evidence *can* span lines are therefore either promoted to `BlockRule` (above) or written
to match single-line forms only, so a multi-line occurrence is skipped rather than
mis-reported. Rule 8 (`insecure-cookie`) is the deliberate example: its regex requires the
call's closing parenthesis on the same line, so a multi-line options object produces no
finding instead of a false one.

Adding a rule means adding an object to an array; the engine does not change.

### 2.4 Block extraction: regex, not AST

"This route handler has no auth check" cannot be expressed as a line regex — the
handler body must be visible. Two options were considered:

**Chosen.** `block.ts` exposes `extractBlock(lines, startIndex)`: locate the handler
declaration, then slice its body by counting brace depth, skipping braces inside string
literals, template literals and comments. Roughly 40 lines, no dependency, no startup
cost, independently unit-testable.

**Rejected.** Full TypeScript AST via the `typescript` package. More accurate, but it
promotes a ~7 MB devDependency to a runtime dependency of a pre-commit hook that must
start fast, and any syntax the installed TypeScript version does not recognise would
force a regex fallback anyway. Most of the accuracy gain lands on rules that §5 already
downgrades to advisory — the highest cost for the lowest return.

The escape hatch is per-rule: `find()` belongs to the rule, so if field data shows an
unacceptable false-positive rate, a single rule can be upgraded to an AST
implementation without touching the engine.

---

## 3. Flow

```
git commit
  → husky pre-commit
  → secretfix scan
      → build ScanContext (detect frameworks, open read cache)
      → run secrets, owasp, deps, web
      → web: for each staged file, run rules whose frameworks match
            line rules   → regex per added line
            block rules  → extractBlock, then match within the body
            file rules   → only if the staged path matches appliesTo  (§4)
            heuristic hits → verify.ts resolves severity            (§5)
  → apply config suppressions, inline markers, diff scoping
  → blocking findings → report, then per finding:
        fix available     → print before/after diff, prompt y/n/skip
        no fix, --ai set  → AI proposes a patch, print diff, prompt   (§7)
        no fix            → explain + example code, no prompt → blocked
  → re-scan the index; anything still blocking blocks the commit
```

---

## 4. False-positive control

Three mechanisms, all load-bearing for the product promise:

**Diff scoping.** `'web'` is added to `DIFF_SCOPED_SCANNERS` in `commands/scan.ts`. Line
and block findings are anchored to the line that triggered them, so editing a handler
body reports it while merely touching an import at the top of the same file does not.

**Staged-anchor gating for project-scope rules.** A `FileRule` declares `appliesTo`,
matched against **staged** paths. `nextjs/missing-security-headers` therefore fires only
on a commit that stages `next.config.*`; a project with no CSP does not get nagged on
every unrelated commit. Without this gate the rule fires forever and the tool gets
uninstalled — which is worse than not gating at all.

**Per-rule disable.** `.secretfixrc.json` gains `webRules: Record<string, boolean>` so a
deliberately public API can silence `nextjs/route-handler-no-auth` without losing the
other 25 rules.

Existing suppressions (`ignoreLines`, `secretfix-ignore-next-line`, `excludeFiles`) apply
unchanged.

---

## 5. Confidence resolution

A `certain` rule emits at its declared severity. A `heuristic` rule is resolved by
`verify.ts` into one of three outcomes:

| Verification result | Outcome |
|---|---|
| Auth evidence found | **No finding emitted** |
| No evidence **and** a risk signal present | Declared severity (high) → blocks |
| No evidence, no risk signal | Downgraded to `medium` → advisory, does not block |

With the default `failOn: 'high'`, the third row reports without blocking, using the
existing advisory path in `scan.ts`. A heuristic rule is never emitted above `high`.

**Auth evidence:** an auth call in the handler body (`auth()`, `getServerSession`,
`requireAuth`, `currentUser`, `session.user`, `supabase.auth.getUser`, `verifyToken`); a
wrapped handler (`export const POST = withAuth(...)`); or a `middleware.ts` whose
`config.matcher` covers the route path.

**Risk signals:** an `/admin` segment in the route path; a state-changing method
(`POST`, `PUT`, `PATCH`, `DELETE`); or a database write inside the handler body.

---

## 6. Fixes

Only mechanically derivable fixes are automated. Everything else explains and blocks —
a wrong auto-fix in a security tool is worse than no fix.

**Automated** (via the existing `replace-line`, plus one new descriptor kind):

| Rule | Fix |
|---|---|
| `agnostic/insecure-cookie` | Add `httpOnly: true, secure: true, sameSite: 'lax'` |
| `agnostic/cors-wildcard-credentials` | Remove `credentials: true` |
| `nextjs/images-wildcard` | Remove the wildcard entry |
| `express/static-serves-project-root` | `express.static(__dirname)` → `express.static('public')` |
| `nextjs/missing-security-headers` | Write a `headers()` block into `next.config.*` (new `add-security-headers` descriptor) |

**Explain-only, blocking** — mass assignment, SSRF, path traversal, NoSQL injection,
plaintext password comparison, unverified JWT, `NEXT_PUBLIC_` secrets, open BaaS rules,
missing helmet. Each prints the problem plus example corrected code. Only the author
knows the safe field list, the allowed origin, or the signing secret.

Findings without a `fix` already flow to `unresolved` in `resolveFindings`, so no new
blocking machinery is needed.

### 6.1 Diff preview before applying

`resolveFindings` currently prints `finding.message` and prompts `Fix this now?` without
showing what it will write. That was acceptable when every fix inserted a suppression
comment; it is not acceptable now that fixes rewrite code. Real rewrites print a
before/after diff first:

```
[high] app/api/login/route.ts:31 — Cookie has no httpOnly/secure flag,
  so any script on the page can read the session.

  - cookies().set('session', token)
  + cookies().set('session', token, { httpOnly: true, secure: true, sameSite: 'lax' })

  Apply this fix? (y/n/skip)
```

### 6.2 `mergeReplacements` collision (existing latent bug)

`fix/interactive.ts` `mergeReplacements` assumes every `replace-line` replacement is
"annotation lines + the original line", and takes `keptLine` from the **last** fix
processed. That held while all fixes were suppression markers. With genuine rewrites it
breaks: if `owasp` emits a marker and `web` emits a rewrite for the same line and the
marker is processed last, **the rewrite is silently discarded while both findings are
marked resolved** — a silent wrong fix, which this tool must not produce.

Fix: add `rewrite?: true` to the `replace-line` descriptor. In `mergeReplacements`, a
rewrite's line always wins as `keptLine`. Two rewrites colliding on one line are not
merged: the first is applied and the rest go to `unresolved`, so the re-scan blocks.

---

## 7. AI layer

Three layers; the top two are optional and off by default.

| Layer | Trigger | AI |
|---|---|---|
| 1. Deterministic | Always, zero config | None |
| 2. Agent handoff | `secretfix scan --json` | The user's installed coding agent |
| 3. Direct API | `--ai`, or `"ai": true` in config | `claude-opus-5` |

**Layer 2** writes a machine-readable report of the findings that have no deterministic
fix. The vibe coder is already running Claude Code or Cursor with full repository
context; the hook blocks, prints the report path, and the user tells their agent to fix
it. No API key, no cost, no added latency.

**Layer 3** calls the Anthropic API directly. It runs in the **fix** phase, not the scan
phase, so the 5-second `SCANNER_TIMEOUT_MS` in `orchestrator.ts` does not apply.

Design points:

- **Structured output, not free text.** `output_config.format` with a JSON schema whose
  shape is `{ file, line, replacement, explanation }` — i.e. the existing
  `replace-line` descriptor. The model's answer enters a code path `fixers.ts` already
  understands; there is no separate patch-application machine. Schema violations are
  retried at the tool-call layer.
- **Model:** `claude-opus-5`, `effort: 'low'`. Latency matters inside a hook, and low
  effort is strong on this model.
- **Prompt caching.** The rule context is a stable prefix, marked with
  `cache_control: { type: 'ephemeral' }`. Opus 5 caches from 512 tokens, so a commit
  with five findings pays one cache write and four cache reads.
- **Refusal handling is mandatory here.** Opus 5 runs cybersecurity classifiers, and
  benign security work can trip a false positive — this tool sends vulnerable code and
  asks for a security fix, which is exactly the shape that gets declined. A refusal
  returns HTTP 200 with `stop_reason: 'refusal'` and an empty `content`, so code that
  reads `content[0].text` unconditionally crashes. Mitigation: opt into
  `fallbacks: 'default'` (beta `server-side-fallback-2026-07-01`), which routes
  cyber-category refusals to `claude-opus-4-8` in the same round trip; and check
  `stop_reason` **before** reading `content`. If the whole chain refuses, fall back to
  explain-and-block.
- **Credentials.** No API key is required. An unset `ANTHROPIC_API_KEY` does not mean no
  credentials: the SDK resolves `ANTHROPIC_API_KEY` → `ANTHROPIC_AUTH_TOKEN` → an
  `ant auth login` OAuth profile → WIF → the default on-disk profile, so a bare
  `new Anthropic()` works for a user who has run `ant auth login`. This is **not** riding
  on a Claude Code subscription login — what is shared is the `ant` profile under
  `~/.config/anthropic/`, which Claude Code and the Claude Agent SDK resolve the same
  way. Note for `init` output: after `ant auth login`, Claude Code may report a conflict
  with its own `/login` credential and one must be chosen.
- **Never hard-fail.** If `--ai` is set but no SDK and no credentials are present, print
  one line (`no credentials found; run "ant auth login" or set ANTHROPIC_API_KEY`) and
  continue in deterministic mode. AI is an optional accelerator, not a required path.
- **Dependency.** `@anthropic-ai/sdk` goes in `optionalDependencies` and is loaded with a
  dynamic import only when layer 3 runs, so `npx secretfix` stays light for everyone
  else.

### Why not the Claude Agent SDK

`@anthropic-ai/claude-agent-sdk` (Claude Code as a library, with built-in
Read/Write/Edit/Bash tools and the full agent loop) is more than this task needs: we want
one structured single-line rewrite, not an agent exploring the filesystem — the file is
already read and the line is already known. Embedding a full agent harness inside a
pre-commit hook also means unpredictable latency. Layer 2 serves that need better,
because there the agent runs on the user's machine with full repository context and
spends from their session rather than ours.

---

## 8. Config and CLI

`.secretfixrc.json` additions:

```json
{
  "web": true,
  "webRules": { "nextjs/route-handler-no-auth": false },
  "ai": false
}
```

CLI additions: `--no-web`, `--ai`, `--json`. Existing flags and precedence
(`applyCliOverrides`) are unchanged.

---

## 9. Error handling

Unchanged in shape from the v1 spec: each scanner runs in isolation, and a throwing
scanner produces a warning while the others still gate the commit. Additions:

- Framework detection never throws. A missing or malformed `package.json` degrades to
  the agnostic rule set.
- `readRepoFile` returns `undefined` for a missing file. A heuristic rule that cannot
  read `middleware.ts` treats that as "no auth evidence found", which routes to the
  advisory outcome rather than a block — absence of evidence must not manufacture a
  high-severity finding.
- `extractBlock` returning no body (unterminated block, unparseable region) skips that
  rule for that file rather than reporting.
- The `add-security-headers` fix throws a clear error when it cannot place the block
  safely (a config that already has a `headers()` function). `resolveFindings` already
  catches fix errors, warns, and pushes the finding to `unresolved`, so the commit stays
  blocked rather than being silently passed.
- Layer 3 network failure, refusal, or schema failure degrades to explain-and-block.

---

## 10. Testing

The product promise is "no false alarms on code you did not touch", so **negative
fixtures matter more than positive ones**. Every rule ships two fixtures: one where it
fires and one closely-related case where it must not (26 rules × 2).

Beyond that:

- **`block.ts`** — braces inside strings, template literals and comments; nested
  functions; unterminated block.
- **`detect.ts`** — Next only, Express only, both, neither, malformed `package.json`.
- **`verify.ts`** — auth in body / wrapped handler / matcher covers / matcher misses /
  no middleware, asserting each of the three outcomes in §5.
- **Staged-anchor gate** — fires with `next.config.js` staged, does not fire when it is
  absent from the commit even though headers are missing.
- **Diff scoping** — a block hit on an unedited handler is suppressed; the same hit on
  an edited line is reported.
- **`mergeReplacements`** — rewrite + marker in both orders, asserting the rewritten
  line survives each time; two rewrites on one line apply one and leave the other
  unresolved.
- **Fixes** — `add-security-headers` against a missing config, an empty config, a config
  that already has `headers()` (must throw → unresolved → blocked), and a `.ts` config.
- **E2E** (following `test/e2e/full-flow.test.ts`) — in a scratch repo: mass assignment
  staged → blocked with no fix offered; cookie flags → fix accepted → re-scan clean →
  commit allowed; auth present in `middleware.ts` → no finding at all.
- **Layer 3** — no live API calls. `ai.ts` takes an injectable `MessageFn` with a
  default, mirroring how `resolveFindings` accepts `fix`/`restage`. Cases: schema-valid
  response → `FixDescriptor`; `stop_reason: 'refusal'` → explain-and-block; no SDK or
  credentials → one-line note plus deterministic mode.
- **Layer 2** — snapshot test of the `--json` report shape.

---

## 11. Out of scope

- The `check-site` DAST command (sub-project B, separate spec).
- Python (FastAPI/Flask/Django) rules — the `deps` scanner is npm-only, so Python
  support would be inconsistent with the rest of the product.
- AST-based analysis (deferred; per-rule upgrade path documented in §2.4).
- Renaming the package or the ignore marker.
- GitHub Action packaging and the VS Code extension (unchanged from the v1 spec).
