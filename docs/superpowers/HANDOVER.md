# Handover — web vulnerability scanner

Written 2026-07-27, mid-execution. Branch `feat/web-scanner`, HEAD `c94e7f1`, 381/381 tests passing, working tree clean.

This document is for whoever picks the work up next, including a future session of me after a context compaction. It says what we set out to build, where we actually are, and exactly what remains.

---

## 1. The goal

`secretfix` is a pre-commit security CLI for "vibe coders" — people shipping AI-assisted code without a security background. Before this work it had three scanners: `secrets`, `owasp` (generic code patterns — `eval`, SQL concatenation, `innerHTML`), and `deps`. None of them saw **web-application** vulnerabilities.

The user asked for exactly that: "catch the well-known basic holes in websites too."

Brainstorming (all decisions the user approved) settled on:

- **Scope split into two sub-projects.** **A** = static rules inside the existing pre-commit flow. **B** = a `check-site` command that probes a live URL over HTTP. **Only A is being built.** B needs its own spec and was deliberately deferred, because B's findings route back into A's rules (a missing CSP is *observed* live but *fixed* in `next.config.js`).
- **Stacks:** Next.js + Express + a framework-agnostic set, detected from `package.json`. Plus three BaaS rules that need no detection.
- **Confidence tiers.** Rules that can be proven block the commit. Rules that cannot — "this route has no auth check" — first run a cheap cross-file verification (is it in `middleware.ts`? wrapped in `withAuth()`?) and, where still unproven, report as a non-blocking advisory. This is the core design decision: a false block trains people to reach for `--no-verify`, which is worse than no gate at all.
- **Fixes only where mechanically derivable** — cookie flags, a `headers()` block, narrowing `express.static`. Everything else explains, shows example code, and blocks. A diff preview is shown before any real rewrite is applied.
- **AI is optional and layered.** Layer 1 deterministic (default). Layer 2 `--json` report for the coding agent the user already has. Layer 3 `--ai` calls `claude-opus-5` directly. No API key is required for layer 3 if the user has run `ant auth login`.

Full reasoning: `docs/superpowers/specs/2026-07-26-web-vuln-detection-design.md`.
Task-by-task plan: `docs/superpowers/plans/2026-07-26-web-scanner.md` (14 tasks, 111 steps).

---

## 2. Where we are

**9 of 15 tasks done** (14 planned + one inserted). 22 commits on the branch. Every task went through an implementer, a spec+quality review, and a fix loop where the review found something.

| Task | What | State |
|---|---|---|
| 1 | `ScanContext`, framework detection, `readIndexFile` | done, `6eb8e63` |
| 2 | `extractBlock` / `forEachBlock` brace slicer | done after **3 fix rounds**, `7724be1` |
| 3 | Rule engine + 8 agnostic line rules | done, `044ad50` |
| 4 | Wiring into config / scan / CLI | done after 1 fix round, `45d3dc8` |
| 5 | `verify.ts` auth heuristics + 3 agnostic block rules | done after 1 fix round, `2885848` |
| 6 | 8 Next.js rules | done, `0ca959f` |
| 7 | 4 Express + 3 BaaS rules — **26-rule catalogue complete** | done after 1 fix round, `6a7e69a` |
| 7b | *(inserted)* line rules skip comment-only lines | done after **2 fix rounds**, `52e5086` |
| 8 | `mergeReplacements` rewrite-aware | done after 1 fix round, `c94e7f1` |
| 9 | Deterministic line-rewrite fixes | done after 1 fix round, `15a18b2` |
| 10 | `add-security-headers` fix | **NEXT** |
| 11 | Diff preview before applying a rewrite | not started |
| 12 | `--json` agent handoff report | not started |
| 13 | Optional AI fix layer behind `--ai` | not started |
| 14 | End-to-end coverage + README | not started |

After Task 14: a **final whole-branch review** on the most capable model, then `superpowers:finishing-a-development-branch`.

### What works today

`git commit` runs the web scanner. 26 rules across four families, gated by framework detection. Diff-scoped, so a pre-existing hole in a file you merely touched does not block you — that test was verified with teeth (removing `'web'` from `DIFF_SCOPED_SCANNERS` makes it fail). Per-rule disable via `webRules` in `.secretfixrc.json`, and `--no-web` to switch the family off.

---

## 3. How to resume

The **ledger is the source of truth**, not anyone's memory:

```
.superpowers/sdd/2026-07-26-web-scanner/progress.md
```

It records every task, every fix round, every deferred finding, and two places where I corrected myself. It is gitignored scratch — if `git clean -fdx` ever destroys it, rebuild from `git log`.

Per-task briefs and reports live beside it as `task-N-brief.md` / `task-N-report.md`.

To continue: invoke `superpowers:subagent-driven-development`, point it at the plan, and it will find the ledger and resume at Task 9. The Task 9 brief is already written to `task-9-brief.md`.

**Two places where the plan text is now wrong** — git is authoritative, not the plan:

- **Task 2's code listing** is known-insufficient. `src/scanners/web/block.ts` in git went through three fix rounds past it.
- **Task 5's `routePathFor` regex** in the plan is broken (`\.{3}?` is an exact count with a no-op lazy modifier). `src/scanners/web/verify.ts` in git has the corrected `(?:\.{3})?`.

---

## 4. What the reviews caught — the interesting part

Nine tasks produced eight fix rounds. Almost every finding traced back to **my own plan code**, not to an implementer's transcription. The pattern worth carrying forward:

- **Task 2, three rounds.** `extractBlock` promised "an unparseable region never manufactures a finding" and didn't deliver. A regex literal containing `}` produced a *truncated-but-plausible* block, which would make a heuristic auth rule see no `auth()` call and **block a correct commit**. My first two fixes chased individual prefixes (`>`, then `)`); round 3 finally changed the structure — one boolean for "provably a regex", and an unconditional divergence check for everything else — which closed the whole keyword family at once. **Lesson: when a fix round ends with "and here is another one", stop patching and change the shape.**
- **Task 5.** `matcherToRegex` escaped before doing anything regex-aware, so **Next.js's own default middleware matcher** matched nothing. Every route in a project using that boilerplate looked unprotected → false blocks on correctly authenticated code. Also `data: req.body` — the most literal form of mass assignment — was never reported, because an alternation ordering captured `req` and then dismissed it.
- **Task 6.** `/admin/:path*` compiled to `^/admin/..*$`, so it stopped covering `/admin`. Task 5's tests and two reviews missed it because **every `:path*` assertion was made against a route that had a subpath** — the zero-width case was never asserted.
- **Task 7b, two rounds.** Fixing comment-blindness over-suppressed live code twice: `/* note */ fs.readFile(req.query.file)` and `--retriesLeft; fs.readFile(...)` both silently returned zero findings. Comment syntax is language-specific and two markers don't run to end-of-line. The second round's `lastIndexOf` temptation was rejected on purpose — it would have traded a noisy failure for a silent one.
- **Task 8.** The pre-existing `coalesce` group key used **raw NUL bytes as separators on purpose** (a NUL cannot occur in a path). The rewrite replaced them with spaces. The reviewer proved it non-exploitable today with a 500-case fuzz plus a structural argument, but it rested on an unenforced invariant, so it was restored — as the `'\0'` escape rather than a raw byte, which is what had made the file read as binary to `grep`.

The reviews earned their cost. Several of them reverted to the pre-fix commit, rebuilt, and confirmed the new tests actually discriminate rather than passing either way.

---

## 5. Deferred findings — for the final review to triage

None of these block progress. All are recorded in the ledger with fuller reasoning.

**Behavioural, worth a decision:**

1. **`owasp.ts` still matches inside comments.** Task 7b fixed this for the 16 web line rules only. Fixing `owasp.ts` changes which commits get blocked for reasons unrelated to this plan, so it was left alone deliberately.
2. **`express/route-no-auth` is position-blind.** A route mounted *before* `app.use(requireAuth)` is suppressed, though Express would not protect it. Errs toward not-blocking, which is this codebase's chosen direction. A named test now documents it.
3. **`routePathFor` can never return a literal `/`.** Low impact — the admin check is segment-based, and a `/`-only matcher would only fail to cover the homepage on a scanner aimed at API handlers.
4. **A line inside a genuine multi-line block comment** that doesn't itself start with `*` or `/*` is still scanned. Inherent to a line-local guard; suppressing it needs cross-line state, which 7b deliberately avoids.
5. **Shorthand `{ where, data }`** where `data` holds the request body is not detected by `agnostic/mass-assignment` — the regex requires a literal colon.
6. **The CSP written by `add-security-headers`** (Task 10, not yet built) keeps `style-src 'unsafe-inline'`, because Next.js injects inline styles and a stricter value breaks the app immediately. A security reviewer will reasonably flag it; the rationale belongs in the code.

**Cosmetic / structural:**

7. `readIndexFile` repeats the read-plus-size/binary-check shape from `getStagedFiles` instead of sharing a helper.
8. `block.ts`'s `lastSignificant` is not updated across a quoted string, so a slash right after a closing quote is classified from a stale character. Only ever produces a safe bail.
9. `nextjs/service-role-key-in-client` is `kind: 'block'` but iterates lines directly instead of using `forEachBlock`.
10. The auth-evidence keyword list misses project-specific helpers (`assertSignedIn`, `getViewer`). Costs missed detections, never false blocks.
11. **One review was skipped.** Task 4's scoped re-review died on a usage limit and I ran the verification myself. Nobody independently checked whether `'pipe'` over `'ignore'` actually preserves diagnostics — i.e. whether the catch blocks read `err.stderr` or only `err.message`.

---

## 6. Open question for the user

**The `deps` scanner's `npm audit` path has never worked on Windows.** `execFileSync('npm', ...)` throws `ENOENT` because it needs `npm.cmd` or a shell. The OSV cross-reference half *does* work — verified live, `express@4.0.0` produced three advisories — so the scanner is not dead, just missing a source.

This is pre-existing and outside this plan. Fixing it changes which commits get blocked, so it is the user's call: fix it as separate work after this branch, squeeze it in now, or leave it as a known limitation. **Not yet answered.**

---

## 7. Environment notes

- **pnpm, never npm.** `pnpm test` runs `tsc -p tsconfig.json` first, so a type error in `src/` fails the test run.
- `tsconfig.json` has `include: ["src"]`, so **files under `test/` are never type-checked**. A type error there will not be caught by the suite.
- ESM: import paths carry `.js` even for TypeScript sources (`module: NodeNext`).
- `any` is forbidden project-wide.
- The package is named `secretfix`; the suppression marker is `secretfix-ignore-next-line`. The directory is `vibeguard` and the older spec says "VibeGuard" — that naming drift is pre-existing and out of scope.
- This session hit usage limits and model-availability errors repeatedly. Several implementers died mid-task. **Always verify what actually landed before re-dispatching** — twice a "stopped" agent had left a broken or half-applied tree, and once it had committed successfully and only failed to write its report.
