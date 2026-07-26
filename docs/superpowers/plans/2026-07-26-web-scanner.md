# Web Vulnerability Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a fourth scanner, `web`, that detects the common web-application vulnerability classes in staged changes, explains each in plain English, and auto-fixes only where the correct fix is mechanically derivable.

**Architecture:** A rule engine driven by three rule shapes (line / block / file) over a framework-detected rule set. Context that lives outside the staged files (`package.json`, `middleware.ts`) is injected into the scanner by closure via a factory, so the shared `Scanner` interface is untouched. Heuristic rules resolve through cross-file auth verification into block / advisory / drop, so an unprovable finding never blocks a commit.

**Tech Stack:** TypeScript (strict, NodeNext ESM), Node ≥18, vitest, commander, prompts. Optional: `@anthropic-ai/sdk` (layer 3 only).

**Spec:** `docs/superpowers/specs/2026-07-26-web-vuln-detection-design.md`

## Global Constraints

- **Never use `any`.** Use `unknown` plus narrowing. This is a hard project rule.
- **pnpm, not npm.** `pnpm test` runs `pnpm build` first via `pretest`, so a type error in `src/` fails the test run.
- **ESM import paths carry `.js`** even for TypeScript sources (`from './types.js'`) — `module: NodeNext`.
- **`tsconfig.json` has `include: ["src"]`**, so files under `test/` are transpiled by vitest but never type-checked. Do not rely on the build to catch test-only type errors.
- **The package is named `secretfix`.** All user-facing strings say `secretfix`; the inline suppression marker is `secretfix-ignore-next-line`. Do not rename anything.
- **Default `failOn` is `'high'`** (`config.ts`). `critical` and `high` block; `medium` and `low` are printed as advisories and let the commit through. Heuristic rules rely on this.
- **Existing scanners must not be modified.** `src/scanners/secrets.ts`, `src/scanners/owasp.ts`, `src/scanners/deps.ts`, `src/orchestrator.ts` and the `Scanner` interface in `src/types.ts` stay as they are, and so do the 25 one-argument `.scan(files)` call sites in existing tests.
- **Rule ids are namespaced and stable:** `agnostic/…`, `nextjs/…`, `express/…`, `baas/…`. They appear in findings and in `webRules` config, so they are public API.
- **No duplicate coverage of `owasp`.** Do not add rules for `eval`, SQL string concatenation, `innerHTML`, `dangerouslySetInnerHTML`, disabled TLS verification, or MD5/SHA-1 hashing — `src/scanners/owasp.ts` already reports those.
- **Commit after every task**, with the test suite green.

---

## File Structure

**Created:**

| File | Responsibility |
|---|---|
| `src/scanners/web/types.ts` | `Framework`, `ScanContext`, `Confidence`, `Hit`, `LineRule`/`BlockRule`/`FileRule`, `WebRule` |
| `src/scanners/web/detect.ts` | Framework detection from `package.json` + file layout |
| `src/scanners/web/context.ts` | `createScanContext` — read cache + detection wiring |
| `src/scanners/web/block.ts` | `extractBlock` — brace-balanced region slicing — and `forEachBlock`, the one place block rules iterate from |
| `src/scanners/web/verify.ts` | Auth-evidence / risk-signal heuristics and heuristic resolution |
| `src/scanners/web/index.ts` | `createWebScanner`, `ALL_RULES` — runs rules, maps confidence to severity |
| `src/scanners/web/rules/agnostic.ts` | Rules 1–11 |
| `src/scanners/web/rules/nextjs.ts` | Rules 12–19 |
| `src/scanners/web/rules/express.ts` | Rules 20–23 |
| `src/scanners/web/rules/baas.ts` | Rules 24–26 |
| `src/report.ts` | Layer 2 — `--json` agent-handoff report |
| `src/fix/ai.ts` | Layer 3 — optional Anthropic API fix proposal |

**Modified:**

| File | Change |
|---|---|
| `src/types.ts` | `Finding.scanner` gains `'web'`; `replace-line` descriptor gains `rewrite?: true`; new `add-security-headers` descriptor |
| `src/git.ts` | New `readIndexFile(path, cwd)` |
| `src/config.ts` | New `web`, `webRules`, `ai` settings + CLI overrides |
| `src/commands/scan.ts` | Build the context, pass it to `selectScanners`, add `'web'` to `DIFF_SCOPED_SCANNERS` |
| `src/cli.ts` | `--no-web`, `--json`, `--ai` |
| `src/fix/interactive.ts` | Rewrite-aware `mergeReplacements`; diff preview before prompting |
| `src/fix/fixers.ts` | `add-security-headers` fix |
| `README.md` | Document the web scanner, the new flags, and layers 2/3 |

Rule files are split by framework rather than by rule kind: a rule's regex, message, and fix change together, and a reader working on Next.js coverage should not have to open four files.

---

## Task 1: ScanContext and framework detection

**Files:**
- Create: `src/scanners/web/types.ts`
- Create: `src/scanners/web/detect.ts`
- Create: `src/scanners/web/context.ts`
- Modify: `src/git.ts` (append `readIndexFile`)
- Modify: `src/types.ts:11` (add `'web'` to the `scanner` union)
- Test: `test/scanners/web/detect.test.ts`
- Test: `test/git.test.ts` (append)

**Interfaces:**
- Consumes: `StagedFile`, `Severity`, `FixDescriptor` from `src/types.ts`.
- Produces: `Framework`, `ScanContext`, `Confidence`, `Resolution`, `Hit`, `RuleGroup`, `LineRule`, `BlockRule`, `FileRule`, `WebRule` (all from `web/types.ts`); `detectFrameworks(readRepoFile)`; `createScanContext(cwd)`; `readIndexFile(path, cwd)`.

- [ ] **Step 1: Write the failing detection test**

Create `test/scanners/web/detect.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { detectFrameworks } from '../../../src/scanners/web/detect.js';

/** Builds a readRepoFile stub over a fixed path->content map. */
function reader(files: Record<string, string>) {
  return (path: string): string | undefined => files[path];
}

describe('detectFrameworks', () => {
  it('always includes agnostic', () => {
    expect(detectFrameworks(reader({}))).toEqual(new Set(['agnostic']));
  });

  it.each([
    ['next', 'nextjs'],
    ['express', 'express'],
    ['@supabase/supabase-js', 'supabase'],
    ['firebase-admin', 'firebase']
  ])('detects %s', (dependency, framework) => {
    const files = { 'package.json': JSON.stringify({ dependencies: { [dependency]: '1.0.0' } }) };
    expect(detectFrameworks(reader(files)).has(framework)).toBe(true);
  });

  it('detects a devDependency too', () => {
    const files = { 'package.json': JSON.stringify({ devDependencies: { express: '4.0.0' } }) };
    expect(detectFrameworks(reader(files)).has('express')).toBe(true);
  });

  it('detects both frameworks in one project', () => {
    const files = { 'package.json': JSON.stringify({ dependencies: { next: '16.0.0', express: '4.0.0' } }) };
    const frameworks = detectFrameworks(reader(files));
    expect(frameworks.has('nextjs')).toBe(true);
    expect(frameworks.has('express')).toBe(true);
  });

  it('does not confuse a lookalike package name', () => {
    const files = { 'package.json': JSON.stringify({ dependencies: { 'express-rate-limit': '7.0.0' } }) };
    expect(detectFrameworks(reader(files)).has('express')).toBe(false);
  });

  it('falls back to agnostic on malformed package.json', () => {
    expect(detectFrameworks(reader({ 'package.json': '{ not json' }))).toEqual(new Set(['agnostic']));
  });

  it('detects Next.js from a config file when package.json is unreadable', () => {
    const frameworks = detectFrameworks(reader({ 'next.config.mjs': 'export default {};' }));
    expect(frameworks.has('nextjs')).toBe(true);
  });
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `pnpm vitest run test/scanners/web/detect.test.ts`
Expected: FAIL — cannot resolve `src/scanners/web/detect.js`.

- [ ] **Step 3: Write `src/scanners/web/types.ts`**

```ts
import type { FixDescriptor, Severity, StagedFile } from '../../types.js';

export type Framework = 'agnostic' | 'nextjs' | 'express' | 'supabase' | 'firebase';

export interface ScanContext {
  cwd: string;
  frameworks: ReadonlySet<Framework>;
  /**
   * Reads a repo file that may not be staged (middleware.ts, next.config.js).
   * Cached per run. Returns undefined when the file does not exist.
   */
  readRepoFile(path: string): string | undefined;
}

/** 'certain' rules report at their declared severity; 'heuristic' rules must corroborate first. */
export type Confidence = 'certain' | 'heuristic';

/** A heuristic rule's own verdict: discard the hit, or report it at this severity. */
export type Resolution = 'drop' | { severity: Severity };

/** One match, anchored to the line the finding is reported against. */
export interface Hit {
  line: number;
  /** Appended to the rule's message when a match needs naming (a route path, a field). */
  detail?: string;
  /** Present only when a deterministic rewrite exists for this match. */
  fix?: FixDescriptor;
  /** Set by a heuristic rule's verification. Absent means "uncorroborated". */
  resolved?: Resolution;
}

export type RuleGroup = 'injection' | 'auth' | 'exposure' | 'hardening';

interface RuleBase {
  /** Namespaced, stable, public: appears in findings and in webRules config. */
  id: string;
  group: RuleGroup;
  frameworks: readonly Framework[];
  severity: Severity;
  confidence: Confidence;
  message: string;
}

export interface LineRule extends RuleBase {
  kind: 'line';
  regex: RegExp;
  fix?: (line: string, lineNumber: number, file: StagedFile) => FixDescriptor | undefined;
}

export interface BlockRule extends RuleBase {
  kind: 'block';
  find: (file: StagedFile, context: ScanContext) => Hit[];
}

export interface FileRule extends RuleBase {
  kind: 'file';
  /** Matched against the staged path. A rule whose anchor is not staged never runs. */
  appliesTo: RegExp;
  check: (file: StagedFile, context: ScanContext) => Hit[];
}

export type WebRule = LineRule | BlockRule | FileRule;
```

- [ ] **Step 4: Write `src/scanners/web/detect.ts`**

```ts
import type { Framework } from './types.js';

/**
 * Anchored patterns, so `express-rate-limit` does not register as Express and
 * `next-auth` does not register as Next.js.
 */
const DEPENDENCY_FRAMEWORKS: ReadonlyArray<readonly [RegExp, Framework]> = [
  [/^next$/, 'nextjs'],
  [/^express$/, 'express'],
  [/^@supabase\//, 'supabase'],
  [/^firebase(?:-admin)?$/, 'firebase']
];

const NEXT_CONFIG_FILES = ['next.config.js', 'next.config.mjs', 'next.config.ts'] as const;

function dependencyNames(raw: string): string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return [];

  const pkg = parsed as { dependencies?: unknown; devDependencies?: unknown };
  const collect = (value: unknown): string[] =>
    typeof value === 'object' && value !== null && !Array.isArray(value) ? Object.keys(value) : [];

  return [...collect(pkg.dependencies), ...collect(pkg.devDependencies)];
}

/**
 * Detection never throws: a missing or malformed package.json degrades to the
 * agnostic rule set rather than failing the commit.
 */
export function detectFrameworks(readRepoFile: (path: string) => string | undefined): Set<Framework> {
  const frameworks = new Set<Framework>(['agnostic']);

  const manifest = readRepoFile('package.json');
  if (manifest !== undefined) {
    for (const name of dependencyNames(manifest)) {
      for (const [pattern, framework] of DEPENDENCY_FRAMEWORKS) {
        if (pattern.test(name)) frameworks.add(framework);
      }
    }
  }

  // A next.config.* is proof of Next.js even where package.json is unreadable.
  if (NEXT_CONFIG_FILES.some((path) => readRepoFile(path) !== undefined)) {
    frameworks.add('nextjs');
  }

  return frameworks;
}
```

- [ ] **Step 5: Run the detection test to verify it passes**

Run: `pnpm vitest run test/scanners/web/detect.test.ts`
Expected: PASS (11 assertions).

- [ ] **Step 6: Write the failing `readIndexFile` test**

Append to `test/git.test.ts`, inside the existing top-level `describe`. Reuse whatever scratch-repo helper that file already defines; if it creates a repo with a helper named differently, adapt the two calls below rather than adding a second helper.

```ts
  it('readIndexFile prefers the staged content over the working tree', () => {
    const cwd = makeRepo();
    writeFileSync(join(cwd, 'a.txt'), 'staged\n');
    execFileSync('git', ['add', 'a.txt'], { cwd });
    writeFileSync(join(cwd, 'a.txt'), 'unstaged\n');

    expect(readIndexFile('a.txt', cwd)).toBe('staged\n');
  });

  it('readIndexFile falls back to the working tree for an untracked file', () => {
    const cwd = makeRepo();
    writeFileSync(join(cwd, 'b.txt'), 'loose\n');

    expect(readIndexFile('b.txt', cwd)).toBe('loose\n');
  });

  it('readIndexFile returns undefined when the file does not exist', () => {
    expect(readIndexFile('nope.txt', makeRepo())).toBeUndefined();
  });
```

Add `readIndexFile` to the existing import from `../src/git.js`.

- [ ] **Step 7: Run it to make sure it fails**

Run: `pnpm vitest run test/git.test.ts`
Expected: FAIL — `readIndexFile is not a function`.

- [ ] **Step 8: Add `readIndexFile` to `src/git.ts`**

Extend the existing `node:fs` import to `import { execFileSync } from 'node:child_process';` plus a new line `import { readFileSync, existsSync } from 'node:fs';` and `import { join } from 'node:path';`, then append:

```ts
/**
 * Reads a repo file as it will be committed: the index first, then the working
 * tree for a file git does not track. The index is the correct source for a
 * verification read — the question is whether the *committed* code has an auth
 * check, not whether an unstaged edit does.
 */
export function readIndexFile(path: string, cwd: string): string | undefined {
  try {
    const buffer = gitBuffer(['show', `:${path}`], cwd);
    if (buffer.byteLength > MAX_SCANNED_BYTES || isBinary(buffer)) return undefined;
    return buffer.toString('utf8');
  } catch {
    // Not in the index; fall through to the working tree.
  }

  const full = join(cwd, path);
  try {
    return existsSync(full) ? readFileSync(full, 'utf8') : undefined;
  } catch {
    return undefined;
  }
}
```

- [ ] **Step 9: Write `src/scanners/web/context.ts`**

```ts
import { readIndexFile } from '../../git.js';
import { detectFrameworks } from './detect.js';
import type { ScanContext } from './types.js';

/**
 * One context per scan run. Reads are memoised — several heuristic rules ask for
 * the same middleware.ts, and the scan must not shell out to git once per rule.
 * `undefined` results are cached too, so a missing file costs one lookup.
 */
export function createScanContext(cwd: string): ScanContext {
  const cache = new Map<string, string | undefined>();

  const readRepoFile = (path: string): string | undefined => {
    if (cache.has(path)) return cache.get(path);
    const content = readIndexFile(path, cwd);
    cache.set(path, content);
    return content;
  };

  return { cwd, frameworks: detectFrameworks(readRepoFile), readRepoFile };
}
```

- [ ] **Step 10: Add `'web'` to the `Finding.scanner` union**

In `src/types.ts:11`, change:

```ts
  scanner: 'secrets' | 'owasp' | 'deps';
```

to:

```ts
  scanner: 'secrets' | 'owasp' | 'deps' | 'web';
```

- [ ] **Step 11: Run the full suite**

Run: `pnpm test`
Expected: PASS. The build must succeed — a type error in `src/` fails here.

- [ ] **Step 12: Commit**

```bash
git add src/scanners/web/types.ts src/scanners/web/detect.ts src/scanners/web/context.ts src/git.ts src/types.ts test/scanners/web/detect.test.ts test/git.test.ts
git commit -m "feat: add ScanContext and framework detection for the web scanner"
```

---

## Task 2: Brace-balanced block extraction

**Files:**
- Create: `src/scanners/web/block.ts`
- Test: `test/scanners/web/block.test.ts`

**Interfaces:**
- Consumes: `Hit` from `web/types.ts` (Task 1); `StagedFile` from `src/types.ts`.
- Produces:
  - `interface Block { startLine: number; endLine: number; text: string }`
  - `extractBlock(lines: string[], fromIndex: number): Block | undefined` — `fromIndex` is 0-based; `startLine`/`endLine` are 1-based.
  - `forEachBlock(file: StagedFile, trigger: RegExp, visit: (blockText: string, line: number, match: RegExpExecArray) => Hit | undefined): Hit[]`

  Every block rule in Tasks 5, 6 and 7 uses `forEachBlock`; it lives here rather than in each rule file so the "unparseable region means skip, never report" decision exists in exactly one place.

- [ ] **Step 1: Write the failing test**

Create `test/scanners/web/block.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { extractBlock } from '../../../src/scanners/web/block.js';

/** Slices from the first line and returns the body text, or undefined. */
function body(source: string): string | undefined {
  return extractBlock(source.split('\n'), 0)?.text;
}

describe('extractBlock', () => {
  it('slices a single-line block', () => {
    const block = extractBlock(['export function f() { return 1; }'], 0);
    expect(block?.startLine).toBe(1);
    expect(block?.endLine).toBe(1);
  });

  it('slices a multi-line block and reports 1-based bounds', () => {
    const block = extractBlock(['export function f() {', '  return 1;', '}', 'after();'], 0);
    expect(block?.startLine).toBe(1);
    expect(block?.endLine).toBe(3);
    expect(block?.text).toBe('export function f() {\n  return 1;\n}');
  });

  it('balances nested blocks', () => {
    expect(body('function f() {\n  if (x) {\n    g();\n  }\n}\nafter();')).toBe(
      'function f() {\n  if (x) {\n    g();\n  }\n}'
    );
  });

  it('ignores braces inside single- and double-quoted strings', () => {
    expect(body('function f() {\n  const s = "}";\n  const t = \'}\';\n}')).toContain("'}'");
  });

  it('ignores braces inside a template literal, including interpolation', () => {
    expect(body('function f() {\n  const s = `a ${b} }`;\n}')).toContain('${b}');
  });

  it('ignores braces inside a multi-line template literal', () => {
    const source = 'function f() {\n  const s = `\n}\n`;\n  return s;\n}';
    expect(extractBlock(source.split('\n'), 0)?.endLine).toBe(6);
  });

  it('ignores braces inside a line comment', () => {
    expect(extractBlock(['function f() {', '  // }', '  return 1;', '}'], 0)?.endLine).toBe(4);
  });

  it('ignores braces inside a block comment', () => {
    expect(extractBlock(['function f() {', '  /* } */', '  return 1;', '}'], 0)?.endLine).toBe(4);
  });

  it('respects an escaped quote rather than ending the string early', () => {
    expect(extractBlock(['function f() {', '  const s = "a\\" }";', '  return s;', '}'], 0)?.endLine).toBe(4);
  });

  it('returns undefined for an unterminated block', () => {
    expect(extractBlock(['function f() {', '  return 1;'], 0)).toBeUndefined();
  });

  it('returns undefined when there is no brace at all', () => {
    expect(extractBlock(['const x = 1;'], 0)).toBeUndefined();
  });

  it('starts at fromIndex, skipping earlier braces', () => {
    const lines = ['const a = { x: 1 };', 'function f() {', '  return 2;', '}'];
    const block = extractBlock(lines, 1);
    expect(block?.startLine).toBe(2);
    expect(block?.endLine).toBe(4);
  });
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `pnpm vitest run test/scanners/web/block.test.ts`
Expected: FAIL — cannot resolve `src/scanners/web/block.js`.

- [ ] **Step 3: Write `src/scanners/web/block.ts`**

```ts
import type { StagedFile } from '../../types.js';
import type { Hit } from './types.js';

export interface Block {
  /** 1-based line holding the opening brace. */
  startLine: number;
  /** 1-based line holding the matching closing brace. */
  endLine: number;
  text: string;
}

/**
 * Slices the brace-delimited region beginning at or after `fromIndex` (0-based
 * line index), balancing braces while ignoring any that sit inside a string,
 * template literal, or comment.
 *
 * Returns undefined when the region never closes, or when there is no brace at
 * all. Callers treat that as "no evidence" and skip the rule for that file —
 * an unparseable region must never manufacture a finding.
 *
 * Known limitation: a regex literal containing an unbalanced brace or a lone
 * quote (`/[{'"]/`) confuses the scan. Rare inside handler bodies, and the
 * failure mode is a skipped rule, not a false positive.
 */
export function extractBlock(lines: string[], fromIndex: number): Block | undefined {
  let depth = 0;
  let started = false;
  let startLine = 0;

  let inBlockComment = false;
  // Persists across lines: a template literal legitimately spans them.
  let quote: string | undefined;

  for (let i = fromIndex; i < lines.length; i += 1) {
    const line = lines[i];

    for (let c = 0; c < line.length; c += 1) {
      const ch = line[c];
      const next = line[c + 1];

      if (inBlockComment) {
        if (ch === '*' && next === '/') {
          inBlockComment = false;
          c += 1;
        }
        continue;
      }

      if (quote !== undefined) {
        if (ch === '\\') {
          c += 1;
        } else if (ch === quote) {
          quote = undefined;
        }
        continue;
      }

      if (ch === '/' && next === '/') break; // rest of the line is a comment
      if (ch === '/' && next === '*') {
        inBlockComment = true;
        c += 1;
        continue;
      }
      if (ch === '"' || ch === "'" || ch === '`') {
        quote = ch;
        continue;
      }

      if (ch === '{') {
        if (!started) {
          started = true;
          startLine = i + 1;
        }
        depth += 1;
      } else if (ch === '}' && started) {
        depth -= 1;
        if (depth === 0) {
          return { startLine, endLine: i + 1, text: lines.slice(fromIndex, i + 1).join('\n') };
        }
      }
    }
  }

  return undefined;
}

/**
 * Runs `visit` at every line matching `trigger`, handing it that line's
 * brace-delimited block.
 *
 * A line whose block does not resolve is skipped silently. That decision lives
 * here, once, because every block rule depends on it: an unparseable region must
 * never manufacture a finding.
 */
export function forEachBlock(
  file: StagedFile,
  trigger: RegExp,
  visit: (blockText: string, line: number, match: RegExpExecArray) => Hit | undefined
): Hit[] {
  const lines = file.content.split('\n');
  const hits: Hit[] = [];

  lines.forEach((line, index) => {
    const match = trigger.exec(line);
    if (match === null) return;

    const block = extractBlock(lines, index);
    if (block === undefined) return;

    const hit = visit(block.text, index + 1, match);
    if (hit !== undefined) hits.push(hit);
  });

  return hits;
}
```

- [ ] **Step 4: Add `forEachBlock` tests**

Append to `test/scanners/web/block.test.ts`:

```ts
import { forEachBlock } from '../../../src/scanners/web/block.js';

describe('forEachBlock', () => {
  it('visits each triggering line with its own block and reports the 1-based line', () => {
    const content = ['function a() {', '  x();', '}', 'const y = 1;', 'function b() {', '  z();', '}'].join('\n');
    const seen: number[] = [];

    forEachBlock({ path: 'a.ts', content }, /function \w+\s*\(/, (_blockText, line) => {
      seen.push(line);
      return undefined;
    });

    expect(seen).toEqual([1, 5]);
  });

  it('passes the regex match through so a rule can read a capture group', () => {
    const content = 'export async function POST(req) {\n  return ok();\n}';
    let method = '';

    forEachBlock({ path: 'route.ts', content }, /function (GET|POST)\b/, (_blockText, _line, match) => {
      method = match[1];
      return undefined;
    });

    expect(method).toBe('POST');
  });

  it('collects only the hits the visitor returns', () => {
    const content = 'function a() {\n  x();\n}\nfunction b() {\n  y();\n}';
    const hits = forEachBlock({ path: 'a.ts', content }, /function (\w+)/, (_blockText, line, match) =>
      match[1] === 'b' ? { line } : undefined
    );

    expect(hits).toEqual([{ line: 4 }]);
  });

  it('skips a triggering line whose block never closes', () => {
    const hits = forEachBlock({ path: 'a.ts', content: 'function a() {\n  x();' }, /function/, (_t, line) => ({ line }));
    expect(hits).toEqual([]);
  });
});
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `pnpm vitest run test/scanners/web/block.test.ts`
Expected: PASS (16 tests).

- [ ] **Step 6: Run the full suite**

Run: `pnpm test`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/scanners/web/block.ts test/scanners/web/block.test.ts
git commit -m "feat: add brace-balanced block extraction for web rules"
```

---

## Task 3: Rule engine and agnostic line rules

**Files:**
- Create: `src/scanners/web/index.ts`
- Create: `src/scanners/web/rules/agnostic.ts`
- Test: `test/scanners/web/agnostic.test.ts`
- Test: `test/scanners/web/index.test.ts`

**Interfaces:**
- Consumes: `WebRule`, `Hit`, `ScanContext` from `web/types.ts` (Task 1).
- Produces: `createWebScanner(context: ScanContext, rules?: readonly WebRule[]): Scanner` and `ALL_RULES: readonly WebRule[]` from `web/index.ts`; `AGNOSTIC_RULES: readonly WebRule[]` from `web/rules/agnostic.ts`. Tasks 4–6 append to `AGNOSTIC_RULES` and add sibling arrays that `ALL_RULES` spreads.

- [ ] **Step 1: Write the failing rule test**

Create `test/scanners/web/agnostic.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { createWebScanner } from '../../../src/scanners/web/index.js';
import type { ScanContext } from '../../../src/scanners/web/types.js';

/** Every framework on, so framework gating never hides the rule under test. */
const context: ScanContext = {
  cwd: '/repo',
  frameworks: new Set(['agnostic', 'nextjs', 'express', 'supabase', 'firebase']),
  readRepoFile: () => undefined
};

async function scan(content: string, path = 'app.ts') {
  return createWebScanner(context).scan([{ path, content }]);
}

/** The rule ids reported for `content`. */
async function ids(content: string): Promise<string[]> {
  return (await scan(content)).map((finding) => finding.message.match(/\[([^\]]+)\]/)?.[1] ?? '');
}

describe('agnostic web rules', () => {
  it.each([
    ['path traversal', 'fs.readFile(path.join(dir, req.query.file), cb);', 'agnostic/path-traversal'],
    ['SSRF', 'const r = await fetch(req.query.url);', 'agnostic/ssrf'],
    ['NoSQL injection via body', "db.collection('u').find(req.body);", 'agnostic/nosql-injection'],
    ['NoSQL injection via $where', 'User.findOne({ $where: input });', 'agnostic/nosql-injection'],
    ['open redirect', 'res.redirect(req.query.next);', 'agnostic/open-redirect'],
    ['plaintext password compare', 'if (user.password === password) return ok();', 'agnostic/plaintext-password-compare'],
    ['reversed password compare', 'if (password === user.password) return ok();', 'agnostic/plaintext-password-compare'],
    ['unverified jwt', 'const payload = jwt.decode(token);', 'agnostic/jwt-unverified'],
    ['jwt alg none', "jwt.verify(t, s, { algorithms: ['none'] });", 'agnostic/jwt-unverified'],
    ['cookie without flags', "res.cookie('session', token);", 'agnostic/insecure-cookie'],
    ['next cookie without flags', "cookies().set('session', token);", 'agnostic/insecure-cookie'],
    ['error stack to client', 'res.status(500).json({ error: err.stack });', 'agnostic/error-stack-to-client'],
    ['raw error object to client', 'return NextResponse.json({ error: err });', 'agnostic/error-stack-to-client']
  ])('flags %s', async (_label, content, id) => {
    expect(await ids(content)).toContain(id);
  });

  it.each([
    ['a filesystem read with no request input', "fs.readFileSync(join(__dirname, 'config.json'));"],
    ['a fetch to a fixed host', "await fetch('https://api.stripe.com/v1/charges');"],
    ['a scoped Mongo filter', 'User.findOne({ email: req.body.email });'],
    ['a redirect to a fixed path', "res.redirect('/dashboard');"],
    ['a password confirmation check', 'if (password === confirmPassword) return ok();'],
    ['a bcrypt comparison', 'if (await bcrypt.compare(password, user.password)) return ok();'],
    ['a hash comparison against a derived value', 'if (user.password === hashedInput) return ok();'],
    ['a verified jwt', 'jwt.verify(token, process.env.JWT_SECRET);'],
    ['a cookie with all flags set', "res.cookie('s', t, { httpOnly: true, secure: true, sameSite: 'lax' });"],
    ['the opening line of a multi-line cookie call', "cookies().set('session', token, {"],
    ['a generic error message', "res.status(500).json({ error: 'Internal server error' });"],
    ['an error message without the stack', 'res.json({ error: err.message });']
  ])('does not flag %s', async (_label, content) => {
    expect(await scan(content)).toHaveLength(0);
  });

  it('reports the 1-based line the match sits on', async () => {
    const findings = await scan('const a = 1;\nconst b = 2;\nres.redirect(req.query.next);');
    expect(findings[0].line).toBe(3);
  });

  it('tags findings with the web scanner', async () => {
    const findings = await scan('const r = await fetch(req.query.url);');
    expect(findings[0].scanner).toBe('web');
  });
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `pnpm vitest run test/scanners/web/agnostic.test.ts`
Expected: FAIL — cannot resolve `src/scanners/web/index.js`.

- [ ] **Step 3: Write `src/scanners/web/rules/agnostic.ts`**

Only line rules land here. Rules 5, 10 and 11 are block rules and arrive in Task 4.

```ts
import type { WebRule } from '../types.js';

/**
 * Rules that hold on any JS/TS file, whatever the framework.
 *
 * Every regex matches a *single* line, because scanning is line-by-line. Where
 * the evidence can legitimately span lines the rule is a BlockRule instead (5,
 * 10, 11) — or, as with insecure-cookie, the regex demands the call's closing
 * parenthesis on the same line, so a multi-line form is skipped rather than
 * mis-reported.
 */
export const AGNOSTIC_RULES: readonly WebRule[] = [
  {
    kind: 'line',
    id: 'agnostic/path-traversal',
    group: 'injection',
    frameworks: ['agnostic'],
    severity: 'critical',
    confidence: 'certain',
    regex: /\bfs(?:\.promises)?\.[a-zA-Z]+\s*\([^)]*\breq(?:uest)?\.(?:params|query|body)\b/,
    message:
      'A file path is built from request input, so a caller can walk out of the intended directory with "../" and read anything the process can. Resolve the path and check it stays inside the directory you meant.'
  },
  {
    kind: 'line',
    id: 'agnostic/ssrf',
    group: 'injection',
    frameworks: ['agnostic'],
    severity: 'high',
    confidence: 'certain',
    regex:
      /\b(?:fetch|got|axios(?:\.(?:get|post|put|patch|delete|request))?)\s*\(\s*[^)]*\breq(?:uest)?\.(?:params|query|body)\b/,
    message:
      'The server fetches a URL the caller chose. That lets them point it at your internal network or cloud metadata endpoint. Accept an identifier instead and map it to a URL you control, or check the host against an allowlist.'
  },
  {
    kind: 'line',
    id: 'agnostic/nosql-injection',
    group: 'injection',
    frameworks: ['agnostic'],
    severity: 'critical',
    confidence: 'certain',
    regex:
      /\$where\b|\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|deleteOne|deleteMany|updateOne|updateMany)\s*\(\s*(?:await\s+)?req(?:uest)?\.(?:body|query)\b/,
    message:
      'A request object is used as the database query itself, so a caller can send operators like {"$ne": null} and change what the query means. Read the specific fields you need instead of passing the whole object.'
  },
  {
    kind: 'line',
    id: 'agnostic/open-redirect',
    group: 'exposure',
    frameworks: ['agnostic'],
    severity: 'medium',
    confidence: 'certain',
    regex: /\bredirect\s*\(\s*[^)]*(?:\breq(?:uest)?\.(?:query|params|body)\.|searchParams\.get\s*\()/i,
    message:
      'The redirect target comes from the request, so this URL can bounce someone to an attacker-controlled site that looks like yours. Allow only relative paths, or check the destination against a list you control.'
  },
  {
    kind: 'line',
    id: 'agnostic/plaintext-password-compare',
    group: 'auth',
    frameworks: ['agnostic'],
    severity: 'critical',
    confidence: 'certain',
    regex:
      /\b\w+\.(?:password|passwd|password_hash)\s*={2,3}\s*(?:password|passwd|pwd|(?:req(?:uest)?\.)?body\.password)\b|\b(?:password|passwd|pwd|(?:req(?:uest)?\.)?body\.password)\s*={2,3}\s*\w+\.(?:password|passwd|password_hash)\b/i,
    message:
      'A stored password is compared directly against the one that was typed, which means passwords are stored in plain text. Hash them with bcrypt, scrypt or argon2 at signup and compare with that library’s own compare function.'
  },
  {
    kind: 'line',
    id: 'agnostic/jwt-unverified',
    group: 'auth',
    frameworks: ['agnostic'],
    severity: 'critical',
    confidence: 'certain',
    regex: /\bjwt\.decode\s*\(|\bjsonwebtoken\.decode\s*\(|algorithms\s*:\s*\[\s*['"]none['"]/i,
    message:
      'This reads a token without checking its signature, so anyone can hand you a token they wrote themselves and claim to be any user. Use jwt.verify() with your signing secret, and never allow the "none" algorithm.'
  },
  {
    kind: 'line',
    id: 'agnostic/insecure-cookie',
    group: 'auth',
    frameworks: ['agnostic'],
    severity: 'high',
    confidence: 'certain',
    regex: /\b(?:res\.cookie|cookies\(\)\.set|cookies\.set|response\.cookies\.set)\s*\((?![^)]*\bhttpOnly\b)[^)]*\)/,
    message:
      'This cookie has no httpOnly flag, so any script on the page can read it — including one injected through an XSS bug. Set httpOnly: true, secure: true and sameSite for anything that identifies a session.'
  },
  {
    kind: 'line',
    id: 'agnostic/error-stack-to-client',
    group: 'exposure',
    frameworks: ['agnostic'],
    severity: 'medium',
    confidence: 'certain',
    regex:
      /\.(?:send|json)\s*\([^)]*\b(?:err|error|e)\.stack\b|\.json\s*\(\s*\{\s*(?:error|message)\s*:\s*(?:err|error|e)\s*[,}]/,
    message:
      'The raw error is sent to the caller. Stack traces and driver errors leak file paths, query shapes and library versions that make the next attack easier. Log the error server-side and return a generic message.'
  }
];
```

- [ ] **Step 4: Write `src/scanners/web/index.ts`**

```ts
import type { Finding, Scanner, Severity, StagedFile } from '../../types.js';
import type { Hit, ScanContext, WebRule } from './types.js';
import { AGNOSTIC_RULES } from './rules/agnostic.js';

export const ALL_RULES: readonly WebRule[] = [...AGNOSTIC_RULES];

/**
 * Where an uncorroborated heuristic finding lands. With the default failOn of
 * 'high' this reports without blocking — the point of the confidence split.
 */
const ADVISORY_SEVERITY: Severity = 'medium';

function applies(rule: WebRule, context: ScanContext): boolean {
  return rule.frameworks.some((framework) => context.frameworks.has(framework));
}

function hitsFor(rule: WebRule, file: StagedFile, context: ScanContext): Hit[] {
  if (rule.kind === 'file') {
    // A project-scope rule runs only when its own anchor file is staged.
    // Otherwise it fires on every unrelated commit until someone silences it.
    return rule.appliesTo.test(file.path) ? rule.check(file, context) : [];
  }

  if (rule.kind === 'block') {
    return rule.find(file, context);
  }

  const hits: Hit[] = [];
  file.content.split('\n').forEach((line, index) => {
    if (rule.regex.test(line)) {
      hits.push({ line: index + 1, fix: rule.fix?.(line, index + 1, file) });
    }
  });
  return hits;
}

/**
 * A heuristic rule reaches its declared severity only where its own verification
 * corroborated it. Uncorroborated it drops to an advisory that reports without
 * blocking; contradicted it is discarded. Absence of evidence must never
 * manufacture a blocking finding.
 */
function severityFor(rule: WebRule, hit: Hit): Severity | undefined {
  if (rule.confidence === 'certain') return rule.severity;
  if (hit.resolved === 'drop') return undefined;
  if (hit.resolved === undefined) return ADVISORY_SEVERITY;
  return hit.resolved.severity;
}

export function createWebScanner(context: ScanContext, rules: readonly WebRule[] = ALL_RULES): Scanner {
  const active = rules.filter((rule) => applies(rule, context));

  return {
    name: 'web',
    async scan(stagedFiles: StagedFile[]): Promise<Finding[]> {
      const findings: Finding[] = [];

      for (const rule of active) {
        for (const file of stagedFiles) {
          for (const hit of hitsFor(rule, file, context)) {
            const severity = severityFor(rule, hit);
            if (severity === undefined) continue;

            const detail = hit.detail === undefined ? '' : ` ${hit.detail}`;
            findings.push({
              scanner: 'web',
              severity,
              file: file.path,
              line: hit.line,
              message: `${rule.message}${detail} [${rule.id}] (${file.path}:${hit.line})`,
              fix: hit.fix,
              scope: rule.kind === 'file' ? 'file' : 'line'
            });
          }
        }
      }

      return findings;
    }
  };
}
```

- [ ] **Step 5: Run the rule test to verify it passes**

Run: `pnpm vitest run test/scanners/web/agnostic.test.ts`
Expected: PASS (27 tests).

- [ ] **Step 6: Write the engine test**

Create `test/scanners/web/index.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { createWebScanner } from '../../../src/scanners/web/index.js';
import type { Framework, ScanContext, WebRule } from '../../../src/scanners/web/types.js';

function contextWith(frameworks: Framework[], files: Record<string, string> = {}): ScanContext {
  return { cwd: '/repo', frameworks: new Set(frameworks), readRepoFile: (path) => files[path] };
}

const NEXT_ONLY: WebRule = {
  kind: 'line',
  id: 'test/next-only',
  group: 'auth',
  frameworks: ['nextjs'],
  severity: 'high',
  confidence: 'certain',
  regex: /BOOM/,
  message: 'boom'
};

/** Reads its hits straight out of the fixture, to exercise the resolution paths. */
const HEURISTIC: WebRule = {
  kind: 'block',
  id: 'test/heuristic',
  group: 'auth',
  frameworks: ['agnostic'],
  severity: 'high',
  confidence: 'heuristic',
  message: 'maybe',
  find: (file) => JSON.parse(file.content) as { line: number; resolved?: 'drop' | { severity: 'high' } }[]
};

const CONFIG_RULE: WebRule = {
  kind: 'file',
  id: 'test/config',
  group: 'hardening',
  frameworks: ['agnostic'],
  severity: 'high',
  confidence: 'certain',
  appliesTo: /(^|\/)next\.config\.[cm]?[jt]s$/,
  message: 'config',
  check: () => [{ line: 1 }]
};

describe('createWebScanner', () => {
  it('skips a rule whose framework is not detected', async () => {
    const scanner = createWebScanner(contextWith(['agnostic']), [NEXT_ONLY]);
    expect(await scanner.scan([{ path: 'a.ts', content: 'BOOM' }])).toHaveLength(0);
  });

  it('runs a rule whose framework is detected', async () => {
    const scanner = createWebScanner(contextWith(['agnostic', 'nextjs']), [NEXT_ONLY]);
    expect(await scanner.scan([{ path: 'a.ts', content: 'BOOM' }])).toHaveLength(1);
  });

  it('drops a heuristic hit its verification contradicted', async () => {
    const scanner = createWebScanner(contextWith(['agnostic']), [HEURISTIC]);
    expect(await scanner.scan([{ path: 'a.ts', content: '[{"line":1,"resolved":"drop"}]' }])).toHaveLength(0);
  });

  it('reports an uncorroborated heuristic hit as a non-blocking advisory', async () => {
    const scanner = createWebScanner(contextWith(['agnostic']), [HEURISTIC]);
    const findings = await scanner.scan([{ path: 'a.ts', content: '[{"line":4}]' }]);
    expect(findings[0].severity).toBe('medium');
  });

  it('reports a corroborated heuristic hit at the resolved severity', async () => {
    const scanner = createWebScanner(contextWith(['agnostic']), [HEURISTIC]);
    const findings = await scanner.scan([{ path: 'a.ts', content: '[{"line":4,"resolved":{"severity":"high"}}]' }]);
    expect(findings[0].severity).toBe('high');
  });

  it('runs a file rule only when its anchor is staged', async () => {
    const scanner = createWebScanner(contextWith(['agnostic']), [CONFIG_RULE]);
    expect(await scanner.scan([{ path: 'next.config.js', content: '' }])).toHaveLength(1);
    expect(await scanner.scan([{ path: 'src/page.tsx', content: '' }])).toHaveLength(0);
  });

  it("marks a file rule's finding with file scope so diff scoping cannot hide it", async () => {
    const scanner = createWebScanner(contextWith(['agnostic']), [CONFIG_RULE]);
    const [finding] = await scanner.scan([{ path: 'next.config.js', content: '' }]);
    expect(finding.scope).toBe('file');
  });

  it('marks a line rule finding with line scope', async () => {
    const scanner = createWebScanner(contextWith(['agnostic', 'nextjs']), [NEXT_ONLY]);
    const [finding] = await scanner.scan([{ path: 'a.ts', content: 'BOOM' }]);
    expect(finding.scope).toBe('line');
  });

  it('includes the rule id in the message so webRules can be discovered from output', async () => {
    const scanner = createWebScanner(contextWith(['agnostic', 'nextjs']), [NEXT_ONLY]);
    const [finding] = await scanner.scan([{ path: 'a.ts', content: 'BOOM' }]);
    expect(finding.message).toContain('[test/next-only]');
  });
});
```

- [ ] **Step 7: Run it, then the full suite**

Run: `pnpm vitest run test/scanners/web/index.test.ts`
Expected: PASS (10 tests).

Run: `pnpm test`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/scanners/web/index.ts src/scanners/web/rules/agnostic.ts test/scanners/web/agnostic.test.ts test/scanners/web/index.test.ts
git commit -m "feat: add web rule engine with agnostic line rules"
```

---

## Task 4: Wire the scanner into config, scan, and CLI

After this task `git commit` actually reports web findings.

**Files:**
- Modify: `src/config.ts` (new settings + overrides)
- Modify: `src/commands/scan.ts:30` (`DIFF_SCOPED_SCANNERS`), `:32-38` (`selectScanners`), `:87` (`scanCommand`)
- Modify: `src/cli.ts:77-94`
- Test: `test/config.test.ts` (append)
- Test: `test/commands/scan.test.ts` (append)

**Interfaces:**
- Consumes: `createScanContext` (Task 1), `createWebScanner`, `ALL_RULES` (Task 3).
- Produces: `SecretFixConfig` gains `web: boolean`, `webRules: Record<string, boolean>`, `ai: boolean`; `CliOverrides` gains `noWeb?: boolean`, `ai?: boolean`; `selectScanners(config, context)`.

- [ ] **Step 1: Write the failing config test**

Append inside the existing top-level `describe` in `test/config.test.ts`. `writeConfig` is the scratch-config helper the file already uses — if it is named differently, adapt these calls rather than adding a second helper.

```ts
  it('enables the web scanner by default', () => {
    expect(defaultConfig.web).toBe(true);
  });

  it('leaves the AI fix layer off by default', () => {
    expect(defaultConfig.ai).toBe(false);
  });

  it('reads per-rule web disables from the config file', () => {
    const cwd = writeConfig({ webRules: { 'nextjs/route-handler-no-auth': false } });
    expect(loadConfig(cwd).webRules['nextjs/route-handler-no-auth']).toBe(false);
  });

  it('ignores non-boolean webRules entries', () => {
    const cwd = writeConfig({ webRules: { 'a/b': 'nope', 'c/d': true } });
    const { webRules } = loadConfig(cwd);
    expect(webRules['a/b']).toBeUndefined();
    expect(webRules['c/d']).toBe(true);
  });

  it('--no-web overrides the config file', () => {
    expect(applyCliOverrides({ ...defaultConfig, web: true }, { noWeb: true }).web).toBe(false);
  });

  it('--ai overrides the config file', () => {
    expect(applyCliOverrides({ ...defaultConfig, ai: false }, { ai: true }).ai).toBe(true);
  });
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `pnpm vitest run test/config.test.ts`
Expected: FAIL — `defaultConfig.web` is undefined.

- [ ] **Step 3: Extend `src/config.ts`**

Add to `SecretFixConfig`, after `deps`:

```ts
  /** The web-application rule family (auth, injection, secret exposure, hardening). */
  web: boolean;
  /** Per-rule disables keyed by rule id. A missing key means enabled. */
  webRules: Record<string, boolean>;
  /** Opt-in: let an LLM propose a patch for findings with no deterministic fix. */
  ai: boolean;
```

Add to `DEFAULT_CONFIG`:

```ts
  web: true,
  webRules: {},
  ai: false,
```

Add a parser beside `readIgnoreLines`:

```ts
function readWebRules(value: unknown): Record<string, boolean> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return {};
  const result: Record<string, boolean> = {};
  for (const [id, enabled] of Object.entries(value as Record<string, unknown>)) {
    if (typeof enabled === 'boolean') result[id] = enabled;
  }
  return result;
}
```

Add to the object `loadConfig` returns:

```ts
    web: readBoolean(parsed.web, DEFAULT_CONFIG.web),
    webRules: readWebRules(parsed.webRules),
    ai: readBoolean(parsed.ai, DEFAULT_CONFIG.ai),
```

Extend `CliOverrides`:

```ts
  noWeb?: boolean;
  ai?: boolean;
```

Extend the object `applyCliOverrides` returns:

```ts
    web: overrides.noWeb ? false : config.web,
    ai: overrides.ai === true ? true : config.ai,
```

- [ ] **Step 4: Run the config test to verify it passes**

Run: `pnpm vitest run test/config.test.ts`
Expected: PASS.

- [ ] **Step 5: Wire `src/commands/scan.ts`**

Add imports:

```ts
import { createScanContext } from '../scanners/web/context.js';
import { createWebScanner, ALL_RULES } from '../scanners/web/index.js';
import type { ScanContext } from '../scanners/web/types.js';
```

Add `'web'` to the diff-scoped set (line 30):

```ts
const DIFF_SCOPED_SCANNERS: ReadonlySet<Finding['scanner']> = new Set<Finding['scanner']>([
  'secrets',
  'owasp',
  'web'
]);
```

Give `selectScanners` the context and build the web scanner:

```ts
function selectScanners(config: SecretFixConfig, context: ScanContext): Scanner[] {
  const scanners: Scanner[] = [];
  if (config.secrets) scanners.push(secretsScanner);
  if (config.owasp) scanners.push(owaspScanner);
  if (config.deps) scanners.push(depsScanner);
  if (config.web) {
    scanners.push(createWebScanner(context, ALL_RULES.filter((rule) => config.webRules[rule.id] !== false)));
  }
  return scanners;
}
```

Replace `const scanners = selectScanners(config);` in `scanCommand` with:

```ts
  const scanners = selectScanners(config, createScanContext(cwd));
```

- [ ] **Step 6: Add `--no-web` to `src/cli.ts`**

Add the option after `--no-deps`:

```ts
    .option('--no-web', 'disable the web-application rule family')
```

Widen the action parameter type and pass the override:

```ts
    .action(
      async (opts: {
        secrets: boolean;
        owasp: boolean;
        deps: boolean;
        web: boolean;
        wholeFile?: boolean;
        failOn?: string;
      }) => {
        process.exitCode = 1;
        process.exitCode = await scanCommand({
          noSecrets: !opts.secrets,
          noOwasp: !opts.owasp,
          noDeps: !opts.deps,
          noWeb: !opts.web,
          wholeFile: opts.wholeFile,
          failOn: opts.failOn,
          prompt: createPrompt()
        });
      }
    );
```

- [ ] **Step 7: Write the failing integration test**

Append inside the existing top-level `describe` in `test/commands/scan.test.ts`. `stageFile` / `makeRepo` are the scratch-repo helpers this file already uses — adapt the names if they differ.

```ts
  it('blocks a commit that stages an SSRF hole', async () => {
    const cwd = makeRepo();
    stageFile(cwd, 'app/api/proxy/route.ts', 'export async function GET(req) {\n  return fetch(req.query.url);\n}\n');

    const code = await scanCommand({ cwd, prompt: async () => 'skip' });

    expect(code).toBe(1);
  });

  it('--no-web turns the family off entirely', async () => {
    const cwd = makeRepo();
    stageFile(cwd, 'app/api/proxy/route.ts', 'export async function GET(req) {\n  return fetch(req.query.url);\n}\n');

    const code = await scanCommand({ cwd, noWeb: true, prompt: async () => 'skip' });

    expect(code).toBe(0);
  });

  it('a per-rule disable silences only that rule', async () => {
    const cwd = makeRepo();
    writeFileSync(join(cwd, '.secretfixrc.json'), JSON.stringify({ webRules: { 'agnostic/ssrf': false } }));
    stageFile(cwd, 'app/api/proxy/route.ts', 'export async function GET(req) {\n  return fetch(req.query.url);\n}\n');

    expect(await scanCommand({ cwd, prompt: async () => 'skip' })).toBe(0);
  });

  it('does not report a web hole on a line this commit did not add', async () => {
    const cwd = makeRepo();
    // Commit the vulnerable line first, so it is history rather than a change.
    stageFile(cwd, 'api.ts', 'export function get(req) {\n  return fetch(req.query.url);\n}\n');
    execFileSync('git', ['commit', '-m', 'seed', '--no-verify'], { cwd });
    stageFile(cwd, 'api.ts', 'export function get(req) {\n  return fetch(req.query.url);\n}\n// a comment\n');

    expect(await scanCommand({ cwd, prompt: async () => 'skip' })).toBe(0);
  });
```

- [ ] **Step 8: Run it, then the full suite**

Run: `pnpm vitest run test/commands/scan.test.ts`
Expected: PASS (4 new tests).

Run: `pnpm test`
Expected: PASS. If an existing scan or CLI fixture now reports a web finding, the fixture contains a real vulnerability — assert on it rather than weakening the rule.

- [ ] **Step 9: Commit**

```bash
git add src/config.ts src/commands/scan.ts src/cli.ts test/config.test.ts test/commands/scan.test.ts
git commit -m "feat: wire the web scanner into config, scan, and CLI"
```

---

## Task 5: Auth verification and agnostic block rules

**Files:**
- Create: `src/scanners/web/verify.ts`
- Modify: `src/scanners/web/rules/agnostic.ts` (append rules 5, 10, 11)
- Test: `test/scanners/web/verify.test.ts`
- Test: `test/scanners/web/agnostic.test.ts` (append)

**Interfaces:**
- Consumes: `forEachBlock` from `web/block.ts` (Task 2); `Resolution`, `ScanContext`, `Hit`, `WebRule` from `web/types.ts` (Task 1).
- Produces, all from `web/verify.ts`:
  - `routePathFor(filePath: string): string`
  - `hasAuthEvidence(blockText: string, filePath: string, context: ScanContext): boolean`
  - `hasRiskSignal(blockText: string, filePath: string, method?: string): boolean`
  - `resolveAuth(blockText: string, filePath: string, context: ScanContext, method?: string): Resolution`
  - `requestBoundLocals(content: string): Set<string>`
  Tasks 6 and 7 call `resolveAuth` for the Next.js and Express auth rules.

- [ ] **Step 1: Write the failing verification test**

Create `test/scanners/web/verify.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import {
  hasAuthEvidence,
  hasRiskSignal,
  requestBoundLocals,
  resolveAuth,
  routePathFor
} from '../../../src/scanners/web/verify.js';
import type { ScanContext } from '../../../src/scanners/web/types.js';

function contextWith(files: Record<string, string> = {}): ScanContext {
  return { cwd: '/repo', frameworks: new Set(['agnostic', 'nextjs']), readRepoFile: (path) => files[path] };
}

describe('routePathFor', () => {
  it.each([
    ['app/api/admin/users/route.ts', '/api/admin/users'],
    ['src/app/api/posts/route.ts', '/api/posts'],
    ['app/(dashboard)/api/billing/route.ts', '/api/billing'],
    ['app/api/posts/[id]/route.ts', '/api/posts/*'],
    ['pages/api/login.ts', '/api/login']
  ])('maps %s to %s', (filePath, expected) => {
    expect(routePathFor(filePath)).toBe(expected);
  });
});

describe('hasAuthEvidence', () => {
  it.each([
    ['a session lookup', 'const session = await getServerSession(authOptions);'],
    ['an auth() call', 'const { userId } = await auth();'],
    ['a requireUser helper', 'const user = requireUser(req);'],
    ['a supabase user lookup', 'const { data } = await supabase.auth.getUser();'],
    ['a session.user read', 'if (!session.user) return unauthorized();'],
    ['a wrapped handler', 'export const POST = withAuth(async (req) => { return ok(); });']
  ])('accepts %s', (_label, blockText) => {
    expect(hasAuthEvidence(blockText, 'app/api/x/route.ts', contextWith())).toBe(true);
  });

  it('rejects a handler with no auth call at all', () => {
    const block = 'export async function POST(req) {\n  const body = await req.json();\n  return ok(body);\n}';
    expect(hasAuthEvidence(block, 'app/api/x/route.ts', contextWith())).toBe(false);
  });

  it('accepts a route a middleware matcher covers', () => {
    const middleware = "export const config = { matcher: ['/api/admin/:path*'] };";
    const context = contextWith({ 'middleware.ts': middleware });
    expect(hasAuthEvidence('return ok();', 'app/api/admin/users/route.ts', context)).toBe(true);
  });

  it('rejects a route the middleware matcher misses', () => {
    const middleware = "export const config = { matcher: ['/dashboard/:path*'] };";
    const context = contextWith({ 'middleware.ts': middleware });
    expect(hasAuthEvidence('return ok();', 'app/api/admin/users/route.ts', context)).toBe(false);
  });

  it('rejects when there is no middleware file', () => {
    expect(hasAuthEvidence('return ok();', 'app/api/admin/users/route.ts', contextWith())).toBe(false);
  });
});

describe('hasRiskSignal', () => {
  it('flags an admin path', () => {
    expect(hasRiskSignal('return ok();', 'app/api/admin/users/route.ts')).toBe(true);
  });

  it('flags a state-changing method', () => {
    expect(hasRiskSignal('return ok();', 'app/api/notes/route.ts', 'DELETE')).toBe(true);
  });

  it('flags a database write in the body', () => {
    expect(hasRiskSignal('await prisma.note.delete({ where: { id } });', 'app/api/notes/route.ts', 'GET')).toBe(true);
  });

  it('does not flag a read-only GET on an ordinary path', () => {
    expect(hasRiskSignal('const notes = await prisma.note.findMany();', 'app/api/notes/route.ts', 'GET')).toBe(false);
  });
});

describe('resolveAuth', () => {
  it('drops the finding when auth evidence exists', () => {
    expect(resolveAuth('const { userId } = await auth();', 'app/api/x/route.ts', contextWith(), 'POST')).toBe('drop');
  });

  it('blocks when there is no evidence and the route is risky', () => {
    expect(resolveAuth('return ok();', 'app/api/admin/x/route.ts', contextWith(), 'POST')).toEqual({ severity: 'high' });
  });

  it('advises when there is neither evidence nor a risk signal', () => {
    expect(resolveAuth('return ok();', 'app/api/x/route.ts', contextWith(), 'GET')).toEqual({ severity: 'medium' });
  });
});

describe('requestBoundLocals', () => {
  it.each([
    ['const body = await req.json();', 'body'],
    ['const payload = request.body;', 'payload'],
    ['let input = await request.json();', 'input']
  ])('binds %s', (source, name) => {
    expect(requestBoundLocals(source).has(name)).toBe(true);
  });

  it('does not bind a destructured read, which names its fields explicitly', () => {
    expect(requestBoundLocals('const { name, bio } = await req.json();').size).toBe(0);
  });

  it('does not bind an unrelated local', () => {
    expect(requestBoundLocals('const total = price * qty;').size).toBe(0);
  });
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `pnpm vitest run test/scanners/web/verify.test.ts`
Expected: FAIL — cannot resolve `src/scanners/web/verify.js`.

- [ ] **Step 3: Write `src/scanners/web/verify.ts`**

```ts
import type { Resolution, ScanContext } from './types.js';

/**
 * Calls that constitute proof somebody checked who is asking. Deliberately
 * generous: a false "auth is present" costs us a missed finding, while a false
 * "auth is absent" costs a blocked commit on correct code — and that is what
 * gets the tool uninstalled.
 */
const AUTH_CALLS =
  /\b(?:auth|getServerSession|getSession|requireAuth|requireUser|requireSession|currentUser|getCurrentUser|verifyToken|verifyJwt|getToken|authorize|isAuthenticated)\s*\(|\bsession\s*\??\.\s*user\b|\bsupabase\s*\.\s*auth\s*\.\s*getUser\b|\bclerkClient\b/;

/** `export const POST = withAuth(...)` and friends. */
const AUTH_WRAPPER = /=\s*(?:with[A-Z]\w*|require[A-Z]\w*|protected?|authed?|guard)\s*\(/;

/** A write is a risk signal: an unauthenticated read is bad, an unauthenticated write is worse. */
const WRITE_CALLS =
  /\.(?:create|createMany|update|updateMany|updateOne|upsert|delete|deleteMany|deleteOne|insert|insertOne|save|destroy)\s*\(|\b(?:INSERT\s+INTO|UPDATE\s+\w|DELETE\s+FROM)/i;

const STATE_CHANGING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

const MIDDLEWARE_FILES = ['middleware.ts', 'middleware.js', 'src/middleware.ts', 'src/middleware.js'] as const;

/**
 * Derives the URL path a route file serves.
 *   app/api/admin/users/route.ts  -> /api/admin/users
 *   app/(dash)/api/billing/route.ts -> /api/billing   (route groups are not URL segments)
 *   app/api/posts/[id]/route.ts   -> /api/posts/*     (dynamic segments become wildcards)
 *   pages/api/login.ts            -> /api/login
 */
export function routePathFor(filePath: string): string {
  let path = filePath.replace(/\\/g, '/');
  path = path.replace(/^src\//, '');
  path = path.replace(/^(?:app|pages)\//, '');
  path = path.replace(/\/route\.[cm]?[jt]sx?$/, '');
  path = path.replace(/\.[cm]?[jt]sx?$/, '');
  path = path.replace(/\((?:[^/)]*)\)\//g, ''); // route groups
  path = path.replace(/\[\[?\.{3}?\w+\]?\]/g, '*'); // [id], [...slug], [[...slug]]
  path = path.replace(/\/index$/, '');
  return `/${path}`.replace(/\/{2,}/g, '/');
}

/** Turns a Next.js middleware matcher into a regex over URL paths. */
function matcherToRegex(matcher: string): RegExp {
  const escaped = matcher
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\\\[[^\]]*\\\]/g, '[^/]+')
    .replace(/:\w+\*/g, '.*')
    .replace(/:\w+/g, '[^/]+')
    .replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`);
}

function middlewareCovers(routePath: string, context: ScanContext): boolean {
  for (const file of MIDDLEWARE_FILES) {
    const content = context.readRepoFile(file);
    if (content === undefined) continue;

    const matcherBlock = /matcher\s*:\s*(\[[^\]]*\]|['"][^'"]*['"])/.exec(content);
    if (matcherBlock === null) {
      // Middleware with no matcher runs on every request, so it covers this route.
      return true;
    }

    const patterns = [...matcherBlock[1].matchAll(/['"]([^'"]+)['"]/g)].map((match) => match[1]);
    if (patterns.some((pattern) => matcherToRegex(pattern).test(routePath))) return true;
  }
  return false;
}

export function hasAuthEvidence(blockText: string, filePath: string, context: ScanContext): boolean {
  if (AUTH_CALLS.test(blockText) || AUTH_WRAPPER.test(blockText)) return true;
  return middlewareCovers(routePathFor(filePath), context);
}

export function hasRiskSignal(blockText: string, filePath: string, method?: string): boolean {
  if (/(^|\/)(?:admin|internal|_admin)(\/|$)/.test(routePathFor(filePath))) return true;
  if (method !== undefined && STATE_CHANGING_METHODS.has(method.toUpperCase())) return true;
  return WRITE_CALLS.test(blockText);
}

/**
 * The three-way outcome for an auth heuristic. Evidence wins outright; without
 * it, a risk signal is what separates "block this" from "mention this".
 */
export function resolveAuth(
  blockText: string,
  filePath: string,
  context: ScanContext,
  method?: string
): Resolution {
  if (hasAuthEvidence(blockText, filePath, context)) return 'drop';
  return hasRiskSignal(blockText, filePath, method) ? { severity: 'high' } : { severity: 'medium' };
}

/**
 * Locals bound to the whole request body — `const body = await req.json()`.
 * A destructured read (`const { name } = await req.json()`) is deliberately not
 * collected: naming the fields is the safe pattern we want people to use.
 */
export function requestBoundLocals(content: string): Set<string> {
  const names = new Set<string>();
  const pattern =
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?req(?:uest)?\s*\.\s*(?:body\b|json\s*\(\s*\))/g;

  for (const match of content.matchAll(pattern)) {
    names.add(match[1]);
  }
  return names;
}
```

- [ ] **Step 4: Run the verification test to verify it passes**

Run: `pnpm vitest run test/scanners/web/verify.test.ts`
Expected: PASS (28 tests).

- [ ] **Step 5: Write the failing block-rule test**

Append inside the existing `describe('agnostic web rules')` in `test/scanners/web/agnostic.test.ts`:

```ts
  it('flags a request body passed straight into an ORM write', async () => {
    const content = [
      'export async function PATCH(req) {',
      '  const body = await req.json();',
      '  return prisma.user.update({',
      '    where: { id },',
      '    data: body,',
      '  });',
      '}'
    ].join('\n');

    expect(await ids(content)).toContain('agnostic/mass-assignment');
  });

  it('flags a spread of the request body into an ORM write', async () => {
    const content = 'const body = await req.json();\nawait prisma.user.update({ data: { ...body } });';
    expect(await ids(content)).toContain('agnostic/mass-assignment');
  });

  it('does not flag an ORM write with an explicit field list', async () => {
    const content = [
      'const body = await req.json();',
      'await prisma.user.update({',
      '  where: { id },',
      '  data: { name: body.name, bio: body.bio },',
      '});'
    ].join('\n');

    expect(await ids(content)).not.toContain('agnostic/mass-assignment');
  });

  it('does not flag an ORM write whose data comes from a value the server computed', async () => {
    const content = 'const data = buildUpdate(input);\nawait prisma.user.update({ data });';
    expect(await ids(content)).not.toContain('agnostic/mass-assignment');
  });

  it('flags a multi-line CORS config that pairs a wildcard origin with credentials', async () => {
    const content = ["app.use(cors({", "  origin: '*',", '  credentials: true,', '}));'].join('\n');
    expect(await ids(content)).toContain('agnostic/cors-wildcard-credentials');
  });

  it('does not flag a wildcard origin without credentials', async () => {
    const content = ["app.use(cors({", "  origin: '*',", '}));'].join('\n');
    expect(await ids(content)).not.toContain('agnostic/cors-wildcard-credentials');
  });

  it('does not flag credentials with an explicit origin', async () => {
    const content = ['app.use(cors({', "  origin: 'https://app.example.com',", '  credentials: true,', '}));'].join('\n');
    expect(await ids(content)).not.toContain('agnostic/cors-wildcard-credentials');
  });

  it('advises when a login handler has no rate limiting', async () => {
    const content = 'export async function POST(req) {\n  const body = await req.json();\n  return signIn(body);\n}';
    const findings = await scan(content, 'app/api/login/route.ts');
    const rateLimit = findings.find((finding) => finding.message.includes('agnostic/no-rate-limit-on-auth'));
    expect(rateLimit?.severity).toBe('medium');
  });

  it('does not flag a login handler that rate limits', async () => {
    const content =
      'export async function POST(req) {\n  await limiter.check(req);\n  const body = await req.json();\n  return signIn(body);\n}';
    expect(await ids(content, 'app/api/login/route.ts')).not.toContain('agnostic/no-rate-limit-on-auth');
  });
```

Widen the `ids` helper in that file to accept a path, matching `scan`:

```ts
async function ids(content: string, path?: string): Promise<string[]> {
  return (await scan(content, path)).map((finding) => finding.message.match(/\[([^\]]+)\]/)?.[1] ?? '');
}
```

- [ ] **Step 6: Run it to make sure it fails**

Run: `pnpm vitest run test/scanners/web/agnostic.test.ts`
Expected: FAIL — the three new rule ids are not reported.

- [ ] **Step 7: Append the three block rules to `src/scanners/web/rules/agnostic.ts`**

Add imports at the top of the file:

```ts
import { forEachBlock } from '../block.js';
import { requestBoundLocals } from '../verify.js';
import type { WebRule } from '../types.js';
```

Add these helpers above `AGNOSTIC_RULES`:

```ts
const ORM_WRITE = /\b\w+(?:\.\w+)*\.(?:create|createMany|update|updateMany|upsert)\s*\(/;

/** `data: body`, `data: await req.json()`, `data: { ...body }`, or shorthand `data`. */
const DATA_ASSIGNMENT = /\bdata\s*:\s*(?:\{\s*\.{3}\s*)?([A-Za-z_$][\w$]*)|\bdata\s*:\s*(?:await\s+)?req(?:uest)?\s*\.\s*(?:body|json\s*\(\s*\))/;

const CORS_TRIGGER = /\bcors\s*\(|Access-Control-Allow-Origin/;
const WILDCARD_ORIGIN = /(?:origin|Access-Control-Allow-Origin)\s*[:=]\s*['"`]\*['"`]/;
const CREDENTIALS_ON = /credentials\s*:\s*true|Access-Control-Allow-Credentials\s*[:=]\s*['"`]?true/;

const AUTH_ENDPOINT = /(?:^|\/)(?:login|signin|sign-in|register|signup|sign-up|auth|token|password|reset)(?:\/|$)/i;
const AUTH_HANDLER = /\b(?:export\s+(?:async\s+)?function\s+(?:POST|PUT)|export\s+const\s+(?:POST|PUT)\s*=|app\.post\s*\()/;
const RATE_LIMIT_EVIDENCE = /\b(?:rate[-_]?limit\w*|ratelimit\w*|limiter|Ratelimit|throttle|slowDown|Bottleneck)\b/i;
```

Then append these three entries to the `AGNOSTIC_RULES` array:

```ts
  {
    kind: 'block',
    id: 'agnostic/mass-assignment',
    group: 'injection',
    frameworks: ['agnostic'],
    severity: 'critical',
    confidence: 'certain',
    message:
      'The whole request body is handed to the database write, so a caller can set any column — including ones you never meant to expose, like isAdmin or credits. List the fields you actually accept.',
    find: (file) => {
      const bound = requestBoundLocals(file.content);
      return forEachBlock(file, ORM_WRITE, (blockText, line) => {
        const match = DATA_ASSIGNMENT.exec(blockText);
        if (match === null) return undefined;
        // A named local counts only when it was bound to the request body;
        // `data: computedValues` is the server's own object and is fine.
        const identifier = match[1];
        if (identifier !== undefined && !bound.has(identifier)) return undefined;
        return { line };
      });
    }
  },
  {
    kind: 'block',
    id: 'agnostic/cors-wildcard-credentials',
    group: 'hardening',
    frameworks: ['agnostic'],
    severity: 'high',
    confidence: 'certain',
    message:
      'CORS allows every origin and also allows credentials, so any site can make authenticated requests as your logged-in users. Name the origins you trust, or drop credentials.',
    find: (file) =>
      forEachBlock(file, CORS_TRIGGER, (blockText, line) =>
        WILDCARD_ORIGIN.test(blockText) && CREDENTIALS_ON.test(blockText) ? { line } : undefined
      )
  },
  {
    kind: 'block',
    id: 'agnostic/no-rate-limit-on-auth',
    group: 'auth',
    frameworks: ['agnostic'],
    severity: 'medium',
    confidence: 'heuristic',
    message:
      'This looks like a sign-in or sign-up handler with no rate limiting, which leaves passwords open to being guessed in bulk. Add a per-IP and per-account limit.',
    find: (file) => {
      if (!AUTH_ENDPOINT.test(file.path)) return [];
      return forEachBlock(file, AUTH_HANDLER, (blockText, line) =>
        RATE_LIMIT_EVIDENCE.test(blockText) || RATE_LIMIT_EVIDENCE.test(file.content)
          ? { line, resolved: 'drop' }
          : { line, resolved: { severity: 'medium' } }
      );
    }
  }
```

- [ ] **Step 8: Run the rule test, then the full suite**

Run: `pnpm vitest run test/scanners/web/agnostic.test.ts`
Expected: PASS.

Run: `pnpm test`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add src/scanners/web/verify.ts src/scanners/web/rules/agnostic.ts test/scanners/web/verify.test.ts test/scanners/web/agnostic.test.ts
git commit -m "feat: add auth verification and agnostic block rules"
```

---

## Task 6: Next.js rules

**Files:**
- Create: `src/scanners/web/rules/nextjs.ts`
- Modify: `src/scanners/web/index.ts` (spread `NEXTJS_RULES` into `ALL_RULES`)
- Test: `test/scanners/web/nextjs.test.ts`

**Interfaces:**
- Consumes: `forEachBlock` (Task 2); `resolveAuth`, `routePathFor` (Task 5); `Hit`, `WebRule`, `ScanContext` (Task 1).
- Produces: `NEXTJS_RULES: readonly WebRule[]`.

- [ ] **Step 1: Write the failing test**

Create `test/scanners/web/nextjs.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { createWebScanner } from '../../../src/scanners/web/index.js';
import { NEXTJS_RULES } from '../../../src/scanners/web/rules/nextjs.js';
import type { ScanContext } from '../../../src/scanners/web/types.js';

function contextWith(files: Record<string, string> = {}): ScanContext {
  return { cwd: '/repo', frameworks: new Set(['agnostic', 'nextjs']), readRepoFile: (path) => files[path] };
}

/** Only the Next.js rules, so agnostic hits do not muddy the assertions. */
async function findings(content: string, path: string, files?: Record<string, string>) {
  return createWebScanner(contextWith(files), NEXTJS_RULES).scan([{ path, content }]);
}

async function ids(content: string, path: string, files?: Record<string, string>): Promise<string[]> {
  return (await findings(content, path, files)).map((f) => f.message.match(/\[([^\]]+)\]/)?.[1] ?? '');
}

describe('Next.js web rules', () => {
  it.each([
    ['a secret-shaped public env var', 'NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_x', '.env.local'],
    ['a public API key', 'NEXT_PUBLIC_API_KEY=abc', '.env'],
    ['a public token', 'const t = process.env.NEXT_PUBLIC_ADMIN_TOKEN;', 'lib/api.ts']
  ])('flags %s', async (_label, content, path) => {
    expect(await ids(content, path)).toContain('nextjs/public-env-secret');
  });

  it.each([
    ['a Stripe publishable key', 'NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_x'],
    ['a Supabase anon key', 'NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGci'],
    ['an OAuth client id', 'NEXT_PUBLIC_GOOGLE_CLIENT_ID=123.apps.googleusercontent.com'],
    ['a plain public var', 'NEXT_PUBLIC_SITE_URL=https://example.com']
  ])('does not flag %s', async (_label, content) => {
    expect(await ids(content, '.env')).not.toContain('nextjs/public-env-secret');
  });

  it('flags a service-role key used in a client component', async () => {
    const content = "'use client';\nconst admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);";
    expect(await ids(content, 'app/admin/page.tsx')).toContain('nextjs/service-role-key-in-client');
  });

  it('does not flag a service-role key in a server file', async () => {
    const content = 'const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);';
    expect(await ids(content, 'lib/admin.ts')).not.toContain('nextjs/service-role-key-in-client');
  });

  it('blocks an admin route handler with no auth check', async () => {
    const content = 'export async function POST(req) {\n  const body = await req.json();\n  return save(body);\n}';
    const [finding] = await findings(content, 'app/api/admin/users/route.ts');
    expect(finding.severity).toBe('high');
  });

  it('advises a plain GET route handler with no auth check', async () => {
    const content = 'export async function GET() {\n  return list();\n}';
    const [finding] = await findings(content, 'app/api/posts/route.ts');
    expect(finding.severity).toBe('medium');
  });

  it('reports nothing when the handler checks auth itself', async () => {
    const content =
      'export async function POST(req) {\n  const { userId } = await auth();\n  if (!userId) return unauthorized();\n  return save(await req.json());\n}';
    expect(await ids(content, 'app/api/admin/users/route.ts')).not.toContain('nextjs/route-handler-no-auth');
  });

  it('reports nothing when middleware covers the route', async () => {
    const content = 'export async function POST(req) {\n  return save(await req.json());\n}';
    const files = { 'middleware.ts': "export const config = { matcher: ['/api/admin/:path*'] };" };
    expect(await ids(content, 'app/api/admin/users/route.ts', files)).not.toContain('nextjs/route-handler-no-auth');
  });

  it('blocks a server action with no auth check', async () => {
    const content = "'use server';\nexport async function deletePost(id) {\n  await prisma.post.delete({ where: { id } });\n}";
    const [finding] = await findings(content, 'app/actions.ts');
    expect(finding.severity).toBe('high');
  });

  it('reports nothing for a server action that checks auth', async () => {
    const content =
      "'use server';\nexport async function deletePost(id) {\n  const session = await getServerSession();\n  if (!session.user) throw new Error('no');\n  await prisma.post.delete({ where: { id } });\n}";
    expect(await ids(content, 'app/actions.ts')).not.toContain('nextjs/server-action-no-auth');
  });

  it('flags a next config with no security headers', async () => {
    expect(await ids('export default { reactStrictMode: true };', 'next.config.mjs')).toContain(
      'nextjs/missing-security-headers'
    );
  });

  it('does not flag a next config that already sets headers', async () => {
    const content = 'export default {\n  async headers() {\n    return [];\n  },\n};';
    expect(await ids(content, 'next.config.mjs')).not.toContain('nextjs/missing-security-headers');
  });

  it('does not run the headers rule when the config is not staged', async () => {
    expect(await ids('export default {};', 'lib/other.ts')).not.toContain('nextjs/missing-security-headers');
  });

  it('flags a middleware matcher that leaves an existing admin route uncovered', async () => {
    const content = "export const config = { matcher: ['/dashboard/:path*'] };";
    const files = { 'app/admin/page.tsx': 'export default function Page() { return null; }' };
    expect(await ids(content, 'middleware.ts', files)).toContain('nextjs/middleware-matcher-gap');
  });

  it('does not flag a middleware matcher that covers the admin route', async () => {
    const content = "export const config = { matcher: ['/admin/:path*'] };";
    const files = { 'app/admin/page.tsx': 'export default function Page() { return null; }' };
    expect(await ids(content, 'middleware.ts', files)).not.toContain('nextjs/middleware-matcher-gap');
  });

  it('does not flag a middleware matcher when the project has no admin route', async () => {
    const content = "export const config = { matcher: ['/dashboard/:path*'] };";
    expect(await ids(content, 'middleware.ts')).not.toContain('nextjs/middleware-matcher-gap');
  });

  it.each([
    ['a wildcard image domain', "export default { images: { domains: ['*'] } };", 'nextjs/images-wildcard'],
    ['a wildcard remote pattern', "export default { images: { remotePatterns: [{ hostname: '**' }] } };", 'nextjs/images-wildcard'],
    ['a proxying rewrite', "destination: 'https://:host/:path*',", 'nextjs/dangerous-rewrite']
  ])('flags %s', async (_label, content, id) => {
    expect(await ids(content, 'next.config.mjs')).toContain(id);
  });

  it.each([
    ['a named image domain', "export default { images: { domains: ['cdn.example.com'] } };"],
    ['a fixed rewrite destination', "destination: 'https://api.example.com/v1/:path*',"]
  ])('does not flag %s', async (_label, content) => {
    const reported = await ids(content, 'next.config.mjs');
    expect(reported).not.toContain('nextjs/images-wildcard');
    expect(reported).not.toContain('nextjs/dangerous-rewrite');
  });
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `pnpm vitest run test/scanners/web/nextjs.test.ts`
Expected: FAIL — cannot resolve `src/scanners/web/rules/nextjs.js`.

- [ ] **Step 3: Write `src/scanners/web/rules/nextjs.ts`**

```ts
import { forEachBlock } from '../block.js';
import { resolveAuth, routePathFor } from '../verify.js';
import type { Hit, ScanContext, WebRule } from '../types.js';

/**
 * A NEXT_PUBLIC_ variable whose name reads like a credential. The negative
 * lookahead spares the keys that are *designed* to be public — a Stripe
 * publishable key, a Supabase anon key, an OAuth client id — because flagging
 * those is the fastest way to teach people to ignore this rule.
 */
const PUBLIC_ENV_SECRET =
  /\bNEXT_PUBLIC_(?!\w*(?:PUBLISHABLE|ANON|CLIENT_ID))\w*(?:SECRET|_KEY|TOKEN|PASSWORD|PASSWD|PRIVATE|CREDENTIAL)\w*/i;

const SERVICE_ROLE_KEY = /service_role|SERVICE_ROLE_KEY|supabaseAdmin|SUPABASE_SECRET/i;
const USE_CLIENT = /^\s*['"]use client['"]/m;
const USE_SERVER = /^\s*['"]use server['"]/m;

const ROUTE_FILE = /(?:^|\/)route\.[cm]?[jt]sx?$/;
const ROUTE_HANDLER = /export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b|export\s+const\s+(GET|POST|PUT|PATCH|DELETE)\s*=/;
const EXPORTED_ASYNC_FUNCTION = /export\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/;

const NEXT_CONFIG = /(?:^|\/)next\.config\.[cm]?[jt]s$/;
const MIDDLEWARE_FILE = /(?:^|\/)middleware\.[cm]?[jt]s$/;
const HEADERS_BLOCK = /\bheaders\s*\(\s*\)|\bheaders\s*:\s*(?:async\s*)?\(/;

/** Conventional locations for an admin surface, used by the matcher-gap rule. */
const ADMIN_ROUTE_FILES: ReadonlyArray<readonly [string, string]> = [
  ['app/admin/page.tsx', '/admin'],
  ['src/app/admin/page.tsx', '/admin'],
  ['app/api/admin/route.ts', '/api/admin'],
  ['src/app/api/admin/route.ts', '/api/admin'],
  ['pages/admin/index.tsx', '/admin']
];

function matcherPatterns(content: string): string[] | undefined {
  const block = /matcher\s*:\s*(\[[^\]]*\]|['"][^'"]*['"])/.exec(content);
  if (block === null) return undefined;
  return [...block[1].matchAll(/['"]([^'"]+)['"]/g)].map((match) => match[1]);
}

function covers(patterns: string[], path: string): boolean {
  return patterns.some((pattern) => {
    const escaped = pattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/:\w+\*/g, '.*')
      .replace(/:\w+/g, '[^/]+')
      .replace(/\*/g, '.*');
    return new RegExp(`^${escaped}$`).test(path);
  });
}

export const NEXTJS_RULES: readonly WebRule[] = [
  {
    kind: 'line',
    id: 'nextjs/public-env-secret',
    group: 'exposure',
    frameworks: ['nextjs'],
    severity: 'critical',
    confidence: 'certain',
    regex: PUBLIC_ENV_SECRET,
    message:
      'NEXT_PUBLIC_ variables are compiled into the browser bundle, so anyone who opens the site can read this value. Drop the NEXT_PUBLIC_ prefix and read it server-side only, then rotate the key — assume the current one is burned.'
  },
  {
    kind: 'block',
    id: 'nextjs/service-role-key-in-client',
    group: 'exposure',
    frameworks: ['nextjs', 'supabase'],
    severity: 'critical',
    confidence: 'certain',
    message:
      'This file runs in the browser and references a service-role key, which bypasses every row-level security policy you have. Move the call to a server component, route handler or server action.',
    find: (file) => {
      if (!USE_CLIENT.test(file.content)) return [];
      const hits: Hit[] = [];
      file.content.split('\n').forEach((line, index) => {
        if (SERVICE_ROLE_KEY.test(line)) hits.push({ line: index + 1 });
      });
      return hits;
    }
  },
  {
    kind: 'block',
    id: 'nextjs/route-handler-no-auth',
    group: 'auth',
    frameworks: ['nextjs'],
    severity: 'high',
    confidence: 'heuristic',
    message:
      'This route handler has no auth check, and none of your middleware covers its path. Anyone who knows the URL can call it. If it is meant to be public, silence this line.',
    find: (file, context: ScanContext) => {
      if (!ROUTE_FILE.test(file.path)) return [];
      return forEachBlock(file, ROUTE_HANDLER, (blockText, line, match) => ({
        line,
        detail: `— ${match[1] ?? match[2]} ${routePathFor(file.path)}`,
        resolved: resolveAuth(blockText, file.path, context, match[1] ?? match[2])
      }));
    }
  },
  {
    kind: 'block',
    id: 'nextjs/server-action-no-auth',
    group: 'auth',
    frameworks: ['nextjs'],
    severity: 'high',
    confidence: 'heuristic',
    message:
      'A server action is a public endpoint: the client can call it directly, whatever the UI shows. This one has no auth check, so add one inside the action itself.',
    find: (file, context: ScanContext) => {
      if (!USE_SERVER.test(file.content)) return [];
      return forEachBlock(file, EXPORTED_ASYNC_FUNCTION, (blockText, line, match) => ({
        line,
        detail: `— ${match[1]}()`,
        // A server action is always a POST, so treat it as state-changing.
        resolved: resolveAuth(blockText, file.path, context, 'POST')
      }));
    }
  },
  {
    kind: 'file',
    id: 'nextjs/missing-security-headers',
    group: 'hardening',
    frameworks: ['nextjs'],
    severity: 'high',
    confidence: 'certain',
    appliesTo: NEXT_CONFIG,
    message:
      'No security headers are configured. Without a Content-Security-Policy your site has no defence-in-depth against injected scripts, and without Strict-Transport-Security and X-Frame-Options it can be downgraded or framed.',
    check: (file) => (HEADERS_BLOCK.test(file.content) ? [] : [{ line: 1 }])
  },
  {
    kind: 'file',
    id: 'nextjs/middleware-matcher-gap',
    group: 'auth',
    frameworks: ['nextjs'],
    severity: 'high',
    confidence: 'heuristic',
    appliesTo: MIDDLEWARE_FILE,
    message:
      'Your middleware matcher does not cover an admin route that exists in this project, so whatever the middleware enforces is simply not applied there.',
    check: (file, context) => {
      const patterns = matcherPatterns(file.content);
      // No matcher means the middleware runs everywhere — nothing to leave uncovered.
      if (patterns === undefined || patterns.length === 0) return [];

      const uncovered = ADMIN_ROUTE_FILES.filter(
        ([path, url]) => context.readRepoFile(path) !== undefined && !covers(patterns, url)
      );
      if (uncovered.length === 0) return [];

      return [
        {
          line: 1,
          detail: `— ${uncovered.map(([, url]) => url).join(', ')} not matched`,
          resolved: { severity: 'high' as const }
        }
      ];
    }
  },
  {
    kind: 'line',
    id: 'nextjs/images-wildcard',
    group: 'hardening',
    frameworks: ['nextjs'],
    severity: 'medium',
    confidence: 'certain',
    regex: /domains\s*:\s*\[[^\]]*['"]\*['"]|hostname\s*:\s*['"]\*\*?['"]/,
    message:
      'The image optimiser will fetch from any host, which turns your server into an open image proxy others can run their bandwidth through. List the hosts you actually serve images from.'
  },
  {
    kind: 'line',
    id: 'nextjs/dangerous-rewrite',
    group: 'hardening',
    frameworks: ['nextjs'],
    severity: 'high',
    confidence: 'certain',
    regex: /destination\s*:\s*['"`]https?:\/\/(?::\w+|\$\{)/,
    message:
      'The rewrite destination host comes from the incoming request, so this route is an open proxy: anyone can make your server fetch arbitrary URLs, including ones inside your own network. Hard-code the host.'
  }
];
```

- [ ] **Step 4: Spread the rules into `ALL_RULES`**

In `src/scanners/web/index.ts`:

```ts
import { AGNOSTIC_RULES } from './rules/agnostic.js';
import { NEXTJS_RULES } from './rules/nextjs.js';

export const ALL_RULES: readonly WebRule[] = [...AGNOSTIC_RULES, ...NEXTJS_RULES];
```

- [ ] **Step 5: Run the test, then the full suite**

Run: `pnpm vitest run test/scanners/web/nextjs.test.ts`
Expected: PASS.

Run: `pnpm test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/scanners/web/rules/nextjs.ts src/scanners/web/index.ts test/scanners/web/nextjs.test.ts
git commit -m "feat: add Next.js web rules"
```

---

## Task 7: Express and BaaS rules

This completes the 26-rule catalogue.

**Files:**
- Create: `src/scanners/web/rules/express.ts`
- Create: `src/scanners/web/rules/baas.ts`
- Modify: `src/scanners/web/index.ts` (spread both into `ALL_RULES`)
- Test: `test/scanners/web/express.test.ts`
- Test: `test/scanners/web/baas.test.ts`

**Interfaces:**
- Consumes: `forEachBlock` (Task 2); `resolveAuth` (Task 5); `Hit`, `WebRule` (Task 1).
- Produces: `EXPRESS_RULES: readonly WebRule[]`, `BAAS_RULES: readonly WebRule[]`.

Note on framework gating: rules 24 and 25 are declared `frameworks: ['agnostic']` on purpose. Firestore rules syntax and `DISABLE ROW LEVEL SECURITY` appear nowhere else, so they need no detection to be safe — and a project whose only Firebase artifact is a `.rules` file would otherwise never be scanned.

- [ ] **Step 1: Write the failing Express test**

Create `test/scanners/web/express.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { createWebScanner } from '../../../src/scanners/web/index.js';
import { EXPRESS_RULES } from '../../../src/scanners/web/rules/express.js';
import type { ScanContext } from '../../../src/scanners/web/types.js';

const context: ScanContext = {
  cwd: '/repo',
  frameworks: new Set(['agnostic', 'express']),
  readRepoFile: () => undefined
};

async function findings(content: string, path = 'server.js') {
  return createWebScanner(context, EXPRESS_RULES).scan([{ path, content }]);
}

async function ids(content: string, path?: string): Promise<string[]> {
  return (await findings(content, path)).map((f) => f.message.match(/\[([^\]]+)\]/)?.[1] ?? '');
}

describe('Express web rules', () => {
  it.each([
    ['__dirname', 'app.use(express.static(__dirname));'],
    ['the current directory', "app.use(express.static('.'));"],
    ['process.cwd()', 'app.use(express.static(process.cwd()));'],
    ['a parent of __dirname', "app.use(express.static(path.join(__dirname, '..')));"]
  ])('flags static serving of %s', async (_label, content) => {
    expect(await ids(content)).toContain('express/static-serves-project-root');
  });

  it.each([
    ['a public directory', "app.use(express.static('public'));"],
    ['a joined public directory', "app.use(express.static(path.join(__dirname, 'public')));"]
  ])('does not flag static serving of %s', async (_label, content) => {
    expect(await ids(content)).not.toContain('express/static-serves-project-root');
  });

  it('flags an app entry with no helmet', async () => {
    expect(await ids('const app = express();\napp.listen(3000);', 'server.js')).toContain('express/no-helmet');
  });

  it('does not flag an app entry that uses helmet', async () => {
    const content = "const app = express();\napp.use(helmet());\napp.listen(3000);";
    expect(await ids(content, 'server.js')).not.toContain('express/no-helmet');
  });

  it('does not run the helmet rule on a file that is not an app entry', async () => {
    expect(await ids('const app = express();', 'routes/users.js')).not.toContain('express/no-helmet');
  });

  it('offers no automatic fix for the helmet finding', async () => {
    const [finding] = (await findings('const app = express();', 'server.js')).filter((f) =>
      f.message.includes('express/no-helmet')
    );
    expect(finding.fix).toBeUndefined();
  });

  it('blocks a state-changing route with no auth', async () => {
    const content = "app.delete('/api/notes/:id', async (req, res) => {\n  await db.notes.delete(req.params.id);\n  res.end();\n});";
    const [finding] = (await findings(content)).filter((f) => f.message.includes('express/route-no-auth'));
    expect(finding.severity).toBe('high');
  });

  it('reports nothing when the route checks auth inline', async () => {
    const content =
      "app.post('/api/notes', async (req, res) => {\n  const user = requireUser(req);\n  res.json(await save(user, req.body));\n});";
    expect(await ids(content)).not.toContain('express/route-no-auth');
  });

  it('reports nothing when a global auth middleware is mounted', async () => {
    const content =
      "app.use(requireAuth);\napp.post('/api/notes', async (req, res) => {\n  res.json(await save(req.body));\n});";
    expect(await ids(content)).not.toContain('express/route-no-auth');
  });

  it('advises a cookie-session app with a state-changing route and no CSRF protection', async () => {
    const content = [
      "const session = require('express-session');",
      'app.use(session({ secret: s }));',
      "app.post('/transfer', (req, res) => {",
      '  transfer(req.body);',
      '  res.end();',
      '});'
    ].join('\n');
    const [finding] = (await findings(content)).filter((f) => f.message.includes('express/csrf-missing'));
    expect(finding.severity).toBe('medium');
  });

  it('reports nothing when CSRF protection is present', async () => {
    const content = [
      "const session = require('express-session');",
      "const csrf = require('csurf');",
      'app.use(session({ secret: s }));',
      'app.use(csrf());',
      "app.post('/transfer', (req, res) => {",
      '  transfer(req.body);',
      '  res.end();',
      '});'
    ].join('\n');
    expect(await ids(content)).not.toContain('express/csrf-missing');
  });

  it('reports nothing about CSRF for a token-authenticated API with no cookie session', async () => {
    const content = "app.post('/api/notes', (req, res) => {\n  res.json(save(req.body));\n});";
    expect(await ids(content)).not.toContain('express/csrf-missing');
  });
});
```

- [ ] **Step 2: Write the failing BaaS test**

Create `test/scanners/web/baas.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { createWebScanner } from '../../../src/scanners/web/index.js';
import { BAAS_RULES } from '../../../src/scanners/web/rules/baas.js';
import type { ScanContext } from '../../../src/scanners/web/types.js';

const context: ScanContext = {
  cwd: '/repo',
  frameworks: new Set(['agnostic', 'supabase', 'firebase']),
  readRepoFile: () => undefined
};

async function ids(content: string, path: string): Promise<string[]> {
  const findings = await createWebScanner(context, BAAS_RULES).scan([{ path, content }]);
  return findings.map((f) => f.message.match(/\[([^\]]+)\]/)?.[1] ?? '');
}

describe('BaaS web rules', () => {
  it.each([
    ['a fully open rule', 'allow read, write: if true;'],
    ['an open write', 'allow write: if true;'],
    ['an open rule with spacing', 'allow  read , write :  if  true ;']
  ])('flags %s', async (_label, content) => {
    expect(await ids(content, 'firestore.rules')).toContain('baas/firebase-rules-open');
  });

  it.each([
    ['an authenticated rule', 'allow read, write: if request.auth != null;'],
    ['an owner-scoped rule', 'allow write: if request.auth.uid == userId;']
  ])('does not flag %s', async (_label, content) => {
    expect(await ids(content, 'firestore.rules')).not.toContain('baas/firebase-rules-open');
  });

  it('flags a migration that disables row level security', async () => {
    expect(await ids('ALTER TABLE profiles DISABLE ROW LEVEL SECURITY;', 'supabase/migrations/001.sql')).toContain(
      'baas/supabase-rls-disabled'
    );
  });

  it('does not flag a migration that enables row level security', async () => {
    expect(await ids('ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;', 'supabase/migrations/001.sql')).not.toContain(
      'baas/supabase-rls-disabled'
    );
  });

  it.each([
    ['a public-prefixed service role key', 'NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=eyJ', '.env'],
    ['a Vite-prefixed service role key', 'VITE_SUPABASE_SERVICE_ROLE_KEY=eyJ', '.env'],
    ['a service role key inside a served directory', 'const key = "service_role_abc";', 'public/config.js']
  ])('flags %s', async (_label, content, path) => {
    expect(await ids(content, path)).toContain('baas/service-role-key-exposed');
  });

  it('does not flag a server-side service role key', async () => {
    expect(await ids('SUPABASE_SERVICE_ROLE_KEY=eyJ', '.env')).not.toContain('baas/service-role-key-exposed');
  });

  it('leaves a client component to the Next.js rule, so it is reported once', async () => {
    const content = "'use client';\nconst k = process.env.SUPABASE_SERVICE_ROLE_KEY;";
    expect(await ids(content, 'app/page.tsx')).not.toContain('baas/service-role-key-exposed');
  });
});
```

- [ ] **Step 3: Run both to make sure they fail**

Run: `pnpm vitest run test/scanners/web/express.test.ts test/scanners/web/baas.test.ts`
Expected: FAIL — cannot resolve the two new rule modules.

- [ ] **Step 4: Write `src/scanners/web/rules/express.ts`**

```ts
import { forEachBlock } from '../block.js';
import { resolveAuth } from '../verify.js';
import type { WebRule } from '../types.js';

const STATIC_PROJECT_ROOT =
  /express\.static\s*\(\s*(?:__dirname\s*\)|process\.cwd\s*\(\s*\)\s*\)|['"]\.\/?['"]|path\.(?:join|resolve)\s*\(\s*__dirname\s*,\s*['"]\.\.)/;

/** Conventional app-entry filenames; the helmet rule anchors to these. */
const APP_ENTRY = /(?:^|\/)(?:app|server|index)\.[cm]?[jt]s$/;
const EXPRESS_APP = /\bexpress\s*\(\s*\)/;
const HELMET = /\bhelmet\b/;

const STATE_CHANGING_ROUTE = /\b(?:app|router)\.(post|put|patch|delete)\s*\(/;
const GLOBAL_AUTH_MIDDLEWARE =
  /\b(?:app|router)\.use\s*\(\s*[^)]*(?:requireAuth|requireUser|ensureLoggedIn|isAuthenticated|passport\.authenticate|authMiddleware|authenticate)\b/i;

const COOKIE_SESSION = /\b(?:express-session|cookie-session|cookieParser|cookie-parser)\b/;
const CSRF_EVIDENCE = /\b(?:csurf|csrf|doubleCsrf|csrfProtection|csrfSync|lusca)\b/i;

export const EXPRESS_RULES: readonly WebRule[] = [
  {
    kind: 'line',
    id: 'express/static-serves-project-root',
    group: 'exposure',
    frameworks: ['express'],
    severity: 'critical',
    confidence: 'certain',
    regex: STATIC_PROJECT_ROOT,
    message:
      'This serves your entire project directory as static files, so anyone can fetch /.env, /package.json or your source. Serve a dedicated directory such as "public" instead.'
  },
  {
    kind: 'file',
    id: 'express/no-helmet',
    group: 'hardening',
    frameworks: ['express'],
    severity: 'medium',
    confidence: 'certain',
    appliesTo: APP_ENTRY,
    message:
      'This app sets no security headers. Install helmet ("pnpm add helmet") and mount it with app.use(helmet()) before your routes — it sets Content-Security-Policy, HSTS, X-Frame-Options and several others in one line.',
    check: (file) => (EXPRESS_APP.test(file.content) && !HELMET.test(file.content) ? [{ line: 1 }] : [])
  },
  {
    kind: 'block',
    id: 'express/route-no-auth',
    group: 'auth',
    frameworks: ['express'],
    severity: 'high',
    confidence: 'heuristic',
    message:
      'This route changes state and has no auth check, and no auth middleware is mounted on the app. Anyone who knows the URL can call it.',
    find: (file, context) => {
      // A global auth middleware protects every route below it, so one
      // app.use(requireAuth) is evidence for the whole file.
      if (GLOBAL_AUTH_MIDDLEWARE.test(file.content)) return [];

      return forEachBlock(file, STATE_CHANGING_ROUTE, (blockText, line, match) => ({
        line,
        detail: `— ${match[1].toUpperCase()}`,
        resolved: resolveAuth(blockText, file.path, context, match[1])
      }));
    }
  },
  {
    kind: 'block',
    id: 'express/csrf-missing',
    group: 'auth',
    frameworks: ['express'],
    severity: 'medium',
    confidence: 'heuristic',
    message:
      'This app authenticates with cookies and has state-changing routes but no CSRF protection, so another site can make your logged-in users submit requests without knowing it. Add a CSRF token check, or use SameSite=Strict cookies plus an origin check.',
    find: (file) => {
      // Only cookie-authenticated apps are vulnerable; a bearer-token API is not.
      if (!COOKIE_SESSION.test(file.content)) return [];
      if (CSRF_EVIDENCE.test(file.content)) return [];

      return forEachBlock(file, STATE_CHANGING_ROUTE, (_blockText, line, match) => ({
        line,
        detail: `— ${match[1].toUpperCase()}`,
        resolved: { severity: 'medium' as const }
      }));
    }
  }
];
```

- [ ] **Step 5: Write `src/scanners/web/rules/baas.ts`**

```ts
import type { Hit, WebRule } from '../types.js';

const OPEN_FIREBASE_RULE = /allow\s+[\w\s,]*:\s*if\s+true\b/i;
const RLS_DISABLED = /\bDISABLE\s+ROW\s+LEVEL\s+SECURITY\b/i;

const PUBLIC_PREFIXED_SERVICE_ROLE = /\b(?:NEXT_PUBLIC|VITE|PUBLIC|REACT_APP|EXPO_PUBLIC)_\w*SERVICE_ROLE\w*/i;
const SERVICE_ROLE = /service_role/i;
/** Directories whose contents are shipped to the browser verbatim. */
const SERVED_DIRECTORY = /^(?:public|static|dist|build)\//;
const USE_CLIENT = /^\s*['"]use client['"]/m;

export const BAAS_RULES: readonly WebRule[] = [
  {
    kind: 'line',
    id: 'baas/firebase-rules-open',
    group: 'auth',
    // Firestore rules syntax appears nowhere else, so this needs no framework
    // detection — and a project whose only Firebase artifact is a .rules file
    // would otherwise never be scanned.
    frameworks: ['agnostic'],
    severity: 'critical',
    confidence: 'certain',
    regex: OPEN_FIREBASE_RULE,
    message:
      'This security rule allows the operation for everyone, with no condition at all — any visitor can read or overwrite the data straight from the browser. Require request.auth and scope the rule to the owning user.'
  },
  {
    kind: 'line',
    id: 'baas/supabase-rls-disabled',
    group: 'auth',
    frameworks: ['agnostic'],
    severity: 'critical',
    confidence: 'certain',
    regex: RLS_DISABLED,
    message:
      'Row level security is being turned off, which means the anon key can read and write every row in this table directly from the browser. Keep RLS enabled and write a policy for the access you need.'
  },
  {
    kind: 'block',
    id: 'baas/service-role-key-exposed',
    group: 'exposure',
    frameworks: ['agnostic'],
    severity: 'critical',
    confidence: 'certain',
    message:
      'A service-role key is exposed to the browser. That key bypasses every row level security policy, so whoever reads it owns your database. Move it server-side and rotate it — assume the current one is burned.',
    find: (file) => {
      // A 'use client' file is reported by nextjs/service-role-key-in-client, so
      // skipping it here keeps one problem to one finding.
      if (USE_CLIENT.test(file.content)) return [];

      const inServedDirectory = SERVED_DIRECTORY.test(file.path);
      const hits: Hit[] = [];

      file.content.split('\n').forEach((line, index) => {
        const exposed = PUBLIC_PREFIXED_SERVICE_ROLE.test(line) || (inServedDirectory && SERVICE_ROLE.test(line));
        if (exposed) hits.push({ line: index + 1 });
      });

      return hits;
    }
  }
];
```

- [ ] **Step 6: Spread both into `ALL_RULES`**

In `src/scanners/web/index.ts`:

```ts
import { AGNOSTIC_RULES } from './rules/agnostic.js';
import { NEXTJS_RULES } from './rules/nextjs.js';
import { EXPRESS_RULES } from './rules/express.js';
import { BAAS_RULES } from './rules/baas.js';

export const ALL_RULES: readonly WebRule[] = [
  ...AGNOSTIC_RULES,
  ...NEXTJS_RULES,
  ...EXPRESS_RULES,
  ...BAAS_RULES
];
```

- [ ] **Step 7: Add a catalogue guard test**

Append to `test/scanners/web/index.test.ts`:

```ts
  it('ships the full catalogue with unique ids', async () => {
    const { ALL_RULES } = await import('../../../src/scanners/web/index.js');
    expect(ALL_RULES).toHaveLength(26);
    expect(new Set(ALL_RULES.map((rule) => rule.id)).size).toBe(26);
  });

  it('never lets a heuristic rule declare a blocking severity without resolving it', async () => {
    const { ALL_RULES } = await import('../../../src/scanners/web/index.js');
    const heuristics = ALL_RULES.filter((rule) => rule.confidence === 'heuristic');
    expect(heuristics.length).toBeGreaterThan(0);
    // Every heuristic rule must be a block or file rule: a line rule has no
    // opportunity to set `resolved`, so it could never be corroborated.
    expect(heuristics.every((rule) => rule.kind !== 'line')).toBe(true);
  });
```

- [ ] **Step 8: Run the new tests, then the full suite**

Run: `pnpm vitest run test/scanners/web`
Expected: PASS.

Run: `pnpm test`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add src/scanners/web/rules/express.ts src/scanners/web/rules/baas.ts src/scanners/web/index.ts test/scanners/web/express.test.ts test/scanners/web/baas.test.ts test/scanners/web/index.test.ts
git commit -m "feat: add Express and BaaS web rules"
```

---

## Task 8: Make `mergeReplacements` rewrite-aware

This fixes a latent bug before Task 9 can trigger it. Today every `replace-line` replacement is "annotation lines + the original line", and `mergeReplacements` takes the kept line from the **last** fix processed. Once a web rule rewrites a line for real, a suppression marker processed after it silently discards the rewrite — while both findings are reported as fixed.

**Files:**
- Modify: `src/types.ts:6` (`replace-line` gains `rewrite?: true`)
- Modify: `src/fix/interactive.ts:36-51` (`mergeReplacements`), `:53-79` (`coalesce`), `:88-134` (`resolveFindings`)
- Test: `test/fix/interactive.test.ts` (append)

**Interfaces:**
- Consumes: `FixDescriptor`, `Finding` from `src/types.ts`.
- Produces: `FixDescriptor`'s `replace-line` variant gains an optional `rewrite?: true`; `coalesce` returns `{ writes: AcceptedFix[]; conflicted: Finding[] }`. Task 9 sets `rewrite: true` on every fix it emits.

- [ ] **Step 1: Write the failing test**

Append inside the existing top-level `describe` in `test/fix/interactive.test.ts`. `resolveFindings` accepts injectable `fix` and `restage` functions (`src/fix/interactive.ts:81-87`); use those rather than touching the filesystem.

```ts
  it("keeps a rewrite's line when a suppression marker collides with it", async () => {
    const writes: FixDescriptor[] = [];
    const findings: Finding[] = [
      {
        scanner: 'web',
        severity: 'high',
        file: 'a.ts',
        line: 3,
        message: 'rewrite',
        fix: { kind: 'replace-line', file: 'a.ts', line: 3, replacement: 'FIXED', rewrite: true }
      },
      {
        scanner: 'owasp',
        severity: 'high',
        file: 'a.ts',
        line: 3,
        message: 'marker',
        fix: { kind: 'replace-line', file: 'a.ts', line: 3, replacement: '// marker\nORIGINAL' }
      }
    ];

    const result = await resolveFindings(
      findings,
      '/repo',
      async () => 'y',
      (fix) => {
        writes.push(fix);
        return [];
      },
      () => undefined
    );

    expect(writes).toHaveLength(1);
    expect(writes[0]).toMatchObject({ kind: 'replace-line', replacement: '// marker\nFIXED' });
    expect(result.unresolved).toHaveLength(0);
  });

  it('keeps the rewrite regardless of the order the fixes arrive in', async () => {
    const writes: FixDescriptor[] = [];
    const marker: Finding = {
      scanner: 'owasp',
      severity: 'high',
      file: 'a.ts',
      line: 3,
      message: 'marker',
      fix: { kind: 'replace-line', file: 'a.ts', line: 3, replacement: '// marker\nORIGINAL' }
    };
    const rewrite: Finding = {
      scanner: 'web',
      severity: 'high',
      file: 'a.ts',
      line: 3,
      message: 'rewrite',
      fix: { kind: 'replace-line', file: 'a.ts', line: 3, replacement: 'FIXED', rewrite: true }
    };

    await resolveFindings([marker, rewrite], '/repo', async () => 'y', (fix) => {
      writes.push(fix);
      return [];
    }, () => undefined);

    expect(writes[0]).toMatchObject({ replacement: '// marker\nFIXED' });
  });

  it('applies one of two colliding rewrites and leaves the other unresolved', async () => {
    const writes: FixDescriptor[] = [];
    const rewriteOf = (replacement: string, message: string): Finding => ({
      scanner: 'web',
      severity: 'high',
      file: 'a.ts',
      line: 3,
      message,
      fix: { kind: 'replace-line', file: 'a.ts', line: 3, replacement, rewrite: true }
    });

    const result = await resolveFindings(
      [rewriteOf('FIRST', 'one'), rewriteOf('SECOND', 'two')],
      '/repo',
      async () => 'y',
      (fix) => {
        writes.push(fix);
        return [];
      },
      () => undefined
    );

    expect(writes).toHaveLength(1);
    expect(writes[0]).toMatchObject({ replacement: 'FIRST' });
    expect(result.unresolved.map((finding) => finding.message)).toEqual(['two']);
  });
```

Add `FixDescriptor` to the type import from `../../src/types.js` if the file does not already import it.

- [ ] **Step 2: Run it to make sure it fails**

Run: `pnpm vitest run test/fix/interactive.test.ts`
Expected: FAIL — the first test writes `'// marker\nORIGINAL'`, because the marker is processed last and wins the kept-line slot.

- [ ] **Step 3: Add the `rewrite` flag to `src/types.ts`**

Change the `replace-line` variant at line 6:

```ts
  /**
   * Replaces a single line. `rewrite` marks a genuine code change, as opposed to
   * a suppression marker that re-emits the original line unchanged — the merge
   * logic needs the distinction to know which line survives a collision.
   */
  | { kind: 'replace-line'; file: string; line: number; replacement: string; rewrite?: true }
```

- [ ] **Step 4: Rewrite `mergeReplacements` and `coalesce` in `src/fix/interactive.ts`**

Replace the existing `mergeReplacements` and `coalesce` with:

```ts
type ReplaceLineFix = Extract<FixDescriptor, { kind: 'replace-line' }>;

function isReplaceLine(fix: FixDescriptor): fix is ReplaceLineFix {
  return fix.kind === 'replace-line';
}

/**
 * Several scanners can flag the same line (e.g. `eval()` around a concatenated
 * SQL string). Each carries its own `replace-line` fix: a suppression marker's
 * replacement is "annotation lines + the original line", while a web rule's is
 * a genuine rewrite of the line itself.
 *
 * Applying them one after another would drop every annotation but the last, so
 * they are merged into a single write: all annotations, then one final line.
 * A rewrite always wins that final slot — otherwise a marker merged after it
 * would silently discard the rewrite while both findings were reported fixed.
 */
function mergeReplacements(fixes: readonly ReplaceLineFix[]): string {
  const annotations: string[] = [];
  let keptLine = '';
  let keptFromRewrite = false;

  for (const fix of fixes) {
    const parts = fix.replacement.split('\n');
    const last = parts[parts.length - 1];

    if (fix.rewrite === true) {
      if (!keptFromRewrite) {
        keptLine = last;
        keptFromRewrite = true;
      }
    } else if (!keptFromRewrite) {
      keptLine = last;
    }

    for (const annotation of parts.slice(0, -1)) {
      if (!annotations.includes(annotation)) annotations.push(annotation);
    }
  }

  return [...annotations, keptLine].join('\n');
}

/**
 * Collapses accepted fixes so that at most one write targets any given
 * file:line. Findings whose fix loses a collision are returned separately so
 * the caller can leave them unresolved — reporting them fixed when their change
 * was dropped is the one outcome this tool must never produce.
 */
function coalesce(accepted: { finding: Finding; fix: FixDescriptor }[]): {
  writes: AcceptedFix[];
  conflicted: Finding[];
} {
  const groups = new Map<string, { findings: Finding[]; fixes: FixDescriptor[] }>();

  for (const { finding, fix } of accepted) {
    // The key includes the kind, so every fix in a group shares it — which is
    // what lets the replace-line branch below assume index alignment.
    const key = `${fix.kind} ${targetFile(fix)} ${targetLine(fix)}`;
    const group = groups.get(key);
    if (group) {
      group.findings.push(finding);
      group.fixes.push(fix);
    } else {
      groups.set(key, { findings: [finding], fixes: [fix] });
    }
  }

  const writes: AcceptedFix[] = [];
  const conflicted: Finding[] = [];

  for (const { findings, fixes } of groups.values()) {
    const [first] = fixes;

    if (!isReplaceLine(first)) {
      writes.push({ findings, fix: first });
      continue;
    }

    const replaceLine = fixes.filter(isReplaceLine);
    const rewrites = replaceLine.filter((fix) => fix.rewrite === true);
    // Two independent rewrites of one line cannot both be right. Apply the
    // first and leave the rest unresolved, so the re-scan still blocks.
    const losing = new Set(rewrites.slice(1));

    const applied: Finding[] = [];
    const usable: ReplaceLineFix[] = [];
    replaceLine.forEach((fix, index) => {
      if (losing.has(fix)) {
        conflicted.push(findings[index]);
        return;
      }
      applied.push(findings[index]);
      usable.push(fix);
    });

    const base = rewrites[0] ?? first;
    writes.push({ findings: applied, fix: { ...base, replacement: mergeReplacements(usable) } });
  }

  return { writes, conflicted };
}
```

- [ ] **Step 5: Consume the new shape in `resolveFindings`**

Replace the `const writes = coalesce(accepted).sort(...)` statement with:

```ts
  const { writes: pending, conflicted } = coalesce(accepted);
  unresolved.push(...conflicted);

  // Two write phases. In-place fixes (move-to-env, bump-dependency) never change
  // a file's line count, so they run top-down, which keeps generated env var names
  // in source order. Only replace-line can insert lines, so it runs bottom-up to
  // avoid shifting line numbers that were computed against the original file.
  const writes = pending.sort((a, b) => {
    const phaseA = a.fix.kind === 'replace-line' ? 1 : 0;
    const phaseB = b.fix.kind === 'replace-line' ? 1 : 0;
    if (phaseA !== phaseB) return phaseA - phaseB;
    return phaseA === 0 ? targetLine(a.fix) - targetLine(b.fix) : targetLine(b.fix) - targetLine(a.fix);
  });
```

- [ ] **Step 6: Run the test, then the full suite**

Run: `pnpm vitest run test/fix/interactive.test.ts`
Expected: PASS.

Run: `pnpm test`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/types.ts src/fix/interactive.ts test/fix/interactive.test.ts
git commit -m "fix: keep a genuine rewrite when a suppression marker collides on the same line"
```

---

## Task 9: Deterministic line-rewrite fixes

**Files:**
- Modify: `src/scanners/web/rules/agnostic.ts` (fixes for `insecure-cookie` and `cors-wildcard-credentials`)
- Modify: `src/scanners/web/rules/nextjs.ts` (fix for `images-wildcard`)
- Modify: `src/scanners/web/rules/express.ts` (fix for `static-serves-project-root`)
- Test: `test/scanners/web/fixes.test.ts`

**Interfaces:**
- Consumes: `FixDescriptor` with `rewrite?: true` (Task 8); the rule arrays from Tasks 5–7.
- Produces: no new exports. Every fix emitted here sets `rewrite: true`.

Two rules whose fix needs a different anchor line than the one Task 5 gave them:

- `agnostic/cors-wildcard-credentials` currently reports at the `cors(` line. Re-anchor it to the line holding `credentials: true`, because that is the line the fix rewrites. The detection logic is unchanged — only the reported line moves.

- `nextjs/images-wildcard` gets a fix only for the `domains: ['*']` form, which has an unambiguous safe rewrite (`domains: []`). A `hostname: '**'` remote pattern is left fix-less: removing one entry from a `remotePatterns` array is not a single-line edit.

- [ ] **Step 1: Write the failing test**

Create `test/scanners/web/fixes.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { createWebScanner } from '../../../src/scanners/web/index.js';
import type { ScanContext } from '../../../src/scanners/web/types.js';

const context: ScanContext = {
  cwd: '/repo',
  frameworks: new Set(['agnostic', 'nextjs', 'express']),
  readRepoFile: () => undefined
};

/** The replacement text of the first fix offered for `content`, or undefined. */
async function replacement(content: string, path = 'app.ts'): Promise<string | undefined> {
  const findings = await createWebScanner(context).scan([{ path, content }]);
  const fix = findings.map((finding) => finding.fix).find((candidate) => candidate !== undefined);
  return fix !== undefined && fix.kind === 'replace-line' ? fix.replacement : undefined;
}

async function fixes(content: string, path = 'app.ts') {
  const findings = await createWebScanner(context).scan([{ path, content }]);
  return findings.map((finding) => finding.fix).filter((fix) => fix !== undefined);
}

describe('deterministic web fixes', () => {
  it('adds cookie flags to a call that has no options object', async () => {
    expect(await replacement("res.cookie('session', token);")).toBe(
      "res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'lax' });"
    );
  });

  it('adds cookie flags into an existing options object', async () => {
    expect(await replacement("cookies().set('session', token, { path: '/' });")).toBe(
      "cookies().set('session', token, { httpOnly: true, secure: true, sameSite: 'lax', path: '/' });"
    );
  });

  it('marks every web fix as a rewrite so it wins a merge collision', async () => {
    const [fix] = await fixes("res.cookie('session', token);");
    expect(fix).toMatchObject({ kind: 'replace-line', rewrite: true });
  });

  it('removes credentials from a wildcard CORS config and anchors on that line', async () => {
    const content = ['app.use(cors({', "  origin: '*',", '  credentials: true,', '}));'].join('\n');
    const findings = await createWebScanner(context).scan([{ path: 'server.js', content }]);
    const cors = findings.find((finding) => finding.message.includes('agnostic/cors-wildcard-credentials'));

    expect(cors?.line).toBe(3);
    expect(cors?.fix).toMatchObject({ kind: 'replace-line', line: 3, replacement: '', rewrite: true });
  });

  it('empties a wildcard image domain list', async () => {
    const content = "export default { images: { domains: ['*'] } };";
    expect(await replacement(content, 'next.config.mjs')).toBe('export default { images: { domains: [] } };');
  });

  it('offers no fix for a wildcard remote pattern', async () => {
    const content = "export default { images: { remotePatterns: [{ hostname: '**' }] } };";
    expect(await fixes(content, 'next.config.mjs')).toHaveLength(0);
  });

  it.each([
    ['app.use(express.static(__dirname));', "app.use(express.static('public'));"],
    ["app.use(express.static('.'));", "app.use(express.static('public'));"],
    ['app.use(express.static(process.cwd()));', "app.use(express.static('public'));"],
    ["app.use(express.static(path.join(__dirname, '..')));", "app.use(express.static(path.join(__dirname, 'public')));"]
  ])('rewrites %s', async (content, expected) => {
    expect(await replacement(content, 'server.js')).toBe(expected);
  });
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `pnpm vitest run test/scanners/web/fixes.test.ts`
Expected: FAIL — no fixes are offered yet.

- [ ] **Step 3: Add the cookie fix in `src/scanners/web/rules/agnostic.ts`**

Add above `AGNOSTIC_RULES`:

```ts
const COOKIE_FLAGS = "httpOnly: true, secure: true, sameSite: 'lax'";
const COOKIE_CALL = /\b(?:res\.cookie|cookies\(\)\.set|cookies\.set|response\.cookies\.set)\s*\(/;

/**
 * Adds the missing flags to a single-line cookie call: into an existing options
 * object where there is one, otherwise as a new final argument. Returns
 * undefined when the shape is not one of those two, so an unusual call is left
 * to the author rather than mangled.
 */
function cookieFlagFix(line: string): string | undefined {
  const call = COOKIE_CALL.exec(line);
  if (call === null) return undefined;

  const openIndex = line.indexOf('(', call.index + call[0].length - 1);
  const closeIndex = line.lastIndexOf(')');
  if (openIndex === -1 || closeIndex <= openIndex) return undefined;

  const args = line.slice(openIndex + 1, closeIndex);
  const braceIndex = args.indexOf('{');

  if (braceIndex !== -1) {
    const inner = args.slice(braceIndex + 1);
    const separator = inner.trim() === '' || inner.trim().startsWith('}') ? '' : ', ';
    const patched = `${args.slice(0, braceIndex + 1)} ${COOKIE_FLAGS}${separator}${inner.replace(/^\s+/, '')}`;
    return `${line.slice(0, openIndex + 1)}${patched}${line.slice(closeIndex)}`;
  }

  return `${line.slice(0, closeIndex)}, { ${COOKIE_FLAGS} }${line.slice(closeIndex)}`;
}
```

Attach it to the `agnostic/insecure-cookie` rule:

```ts
    fix: (line, lineNumber, file) => {
      const replacement = cookieFlagFix(line);
      return replacement === undefined
        ? undefined
        : { kind: 'replace-line', file: file.path, line: lineNumber, replacement, rewrite: true };
    },
```

- [ ] **Step 4: Re-anchor the CORS rule and give it a fix**

Replace the `find` of `agnostic/cors-wildcard-credentials` with:

```ts
    find: (file) => {
      const lines = file.content.split('\n');

      return forEachBlock(file, CORS_TRIGGER, (blockText, line) => {
        if (!WILDCARD_ORIGIN.test(blockText) || !CREDENTIALS_ON.test(blockText)) return undefined;

        // Anchor on the credentials line, because that is the line the fix
        // rewrites — and dropping credentials is the safe half of the pair:
        // narrowing the origin needs a value only the author knows.
        const offset = lines.slice(line - 1).findIndex((candidate) => CREDENTIALS_ON.test(candidate));
        if (offset === -1) return { line };

        const credentialsLine = line + offset;
        return {
          line: credentialsLine,
          fix: {
            kind: 'replace-line',
            file: file.path,
            line: credentialsLine,
            replacement: '',
            rewrite: true
          }
        };
      });
    }
```

- [ ] **Step 5: Add the images fix in `src/scanners/web/rules/nextjs.ts`**

Attach to `nextjs/images-wildcard`:

```ts
    fix: (line, lineNumber, file) => {
      // Only the domains-array form has an unambiguous single-line rewrite;
      // pruning one entry from remotePatterns is not a line edit.
      if (!/domains\s*:\s*\[[^\]]*['"]\*['"]/.test(line)) return undefined;
      return {
        kind: 'replace-line',
        file: file.path,
        line: lineNumber,
        replacement: line.replace(/(domains\s*:\s*)\[[^\]]*\]/, '$1[]'),
        rewrite: true
      };
    },
```

- [ ] **Step 6: Add the static-directory fix in `src/scanners/web/rules/express.ts`**

Attach to `express/static-serves-project-root`:

```ts
    fix: (line, lineNumber, file) => {
      const replacement = line
        .replace(/express\.static\s*\(\s*path\.(join|resolve)\s*\(\s*__dirname\s*,\s*['"]\.\.['"]\s*\)/, (match) =>
          match.replace(/['"]\.\.['"]/, "'public'")
        )
        .replace(/express\.static\s*\(\s*(?:__dirname|process\.cwd\s*\(\s*\)|['"]\.\/?['"])\s*\)/, "express.static('public')");

      return replacement === line
        ? undefined
        : { kind: 'replace-line', file: file.path, line: lineNumber, replacement, rewrite: true };
    },
```

- [ ] **Step 7: Run the fix test, then the full suite**

Run: `pnpm vitest run test/scanners/web/fixes.test.ts`
Expected: PASS. If the CORS assertion fails on the line number, check that `forEachBlock`'s `line` is the trigger line and the offset search starts from it.

Run: `pnpm test`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/scanners/web/rules/agnostic.ts src/scanners/web/rules/nextjs.ts src/scanners/web/rules/express.ts test/scanners/web/fixes.test.ts
git commit -m "feat: add deterministic line-rewrite fixes for web findings"
```

---

## Task 10: The `add-security-headers` fix

**Files:**
- Modify: `src/types.ts:3-8` (new descriptor variant)
- Modify: `src/fix/fixers.ts:62-141` (new `applyFix` case)
- Modify: `src/fix/interactive.ts:21-27` (`targetLine`/`targetFile` must handle the new kind)
- Modify: `src/scanners/web/rules/nextjs.ts` (attach the fix to `missing-security-headers`)
- Test: `test/fix/fixers.test.ts` (append)

**Interfaces:**
- Consumes: `FixDescriptor` (Task 8).
- Produces: `FixDescriptor` gains `| { kind: 'add-security-headers'; file: string }`.

- [ ] **Step 1: Write the failing test**

Append inside the existing top-level `describe` in `test/fix/fixers.test.ts`. `makeDir` / `writeFileSync` are whatever scratch helpers this file already uses — adapt the names if they differ.

```ts
  it('inserts a headers() block into an ESM next config', () => {
    const cwd = makeDir();
    writeFileSync(join(cwd, 'next.config.mjs'), 'export default {\n  reactStrictMode: true,\n};\n');

    const touched = applyFix({ kind: 'add-security-headers', file: 'next.config.mjs' }, cwd);

    const updated = readFileSync(join(cwd, 'next.config.mjs'), 'utf8');
    expect(touched).toEqual(['next.config.mjs']);
    expect(updated).toContain('Content-Security-Policy');
    expect(updated).toContain('Strict-Transport-Security');
    expect(updated).toContain('X-Frame-Options');
    expect(updated).toContain('reactStrictMode: true');
  });

  it('inserts a headers() block into a CommonJS next config', () => {
    const cwd = makeDir();
    writeFileSync(join(cwd, 'next.config.js'), 'module.exports = {\n  poweredByHeader: false,\n};\n');

    applyFix({ kind: 'add-security-headers', file: 'next.config.js' }, cwd);

    expect(readFileSync(join(cwd, 'next.config.js'), 'utf8')).toContain('async headers()');
  });

  it('refuses to touch a config that already defines headers()', () => {
    const cwd = makeDir();
    writeFileSync(join(cwd, 'next.config.mjs'), 'export default {\n  async headers() {\n    return [];\n  },\n};\n');

    expect(() => applyFix({ kind: 'add-security-headers', file: 'next.config.mjs' }, cwd)).toThrow(/already defines/);
  });

  it('refuses to guess when there is no config object literal', () => {
    const cwd = makeDir();
    writeFileSync(join(cwd, 'next.config.mjs'), 'export default withPlugins(plugins);\n');

    expect(() => applyFix({ kind: 'add-security-headers', file: 'next.config.mjs' }, cwd)).toThrow(/config object/);
  });

  it('reports a missing config file rather than creating one', () => {
    expect(() => applyFix({ kind: 'add-security-headers', file: 'next.config.mjs' }, makeDir())).toThrow(/not found/);
  });
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `pnpm vitest run test/fix/fixers.test.ts`
Expected: FAIL — `applyFix` has no case for `add-security-headers`.

- [ ] **Step 3: Add the descriptor variant to `src/types.ts`**

Append to the `FixDescriptor` union:

```ts
  /** Writes a security-headers block into a Next.js config that has none. */
  | { kind: 'add-security-headers'; file: string }
```

- [ ] **Step 4: Add the `applyFix` case in `src/fix/fixers.ts`**

Add above `applyFix`:

```ts
/**
 * A deliberately conservative baseline. `unsafe-inline` for styles is kept
 * because Next.js injects inline styles and a stricter value would break the
 * app on the spot — a header that gets reverted protects nobody.
 */
const SECURITY_HEADERS_BLOCK = `  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'Content-Security-Policy',
            value: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-ancestors 'none'"
          },
          { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' }
        ]
      }
    ];
  },
`;
```

Add this case inside the `switch`:

```ts
    case 'add-security-headers': {
      const filePath = join(cwd, fix.file);
      if (!existsSync(filePath)) {
        throw new Error(`cannot add security headers: ${fix.file} not found`);
      }

      const content = readFileSync(filePath, 'utf8');
      if (/\bheaders\s*\(/.test(content)) {
        throw new Error(`cannot add security headers: ${fix.file} already defines a headers() function`);
      }

      // Only a plain object literal is safe to edit. A config wrapped in a
      // plugin call has no literal to insert into, and guessing would corrupt it
      // — throwing leaves the finding unresolved, which keeps the commit blocked.
      const opening = /(?:export\s+default|module\.exports\s*=)\s*\{/.exec(content);
      if (opening === null) {
        throw new Error(`cannot add security headers: no config object literal found in ${fix.file}`);
      }

      const insertAt = opening.index + opening[0].length;
      writeFileSync(filePath, `${content.slice(0, insertAt)}\n${SECURITY_HEADERS_BLOCK}${content.slice(insertAt)}`);
      return [fix.file];
    }
```

- [ ] **Step 5: Teach `src/fix/interactive.ts` about the new kind**

`targetLine` and `targetFile` switch on the descriptor kind. Update both so the new kind behaves like a whole-file fix:

```ts
function targetLine(fix: FixDescriptor): number {
  return fix.kind === 'bump-dependency' || fix.kind === 'unstage-file' || fix.kind === 'add-security-headers'
    ? 0
    : fix.line;
}
```

`targetFile` already returns `fix.file` for everything except `bump-dependency`, so it needs no change — but re-read it to confirm the narrowing still compiles after the union grew.

- [ ] **Step 6: Attach the fix to the rule**

In `src/scanners/web/rules/nextjs.ts`, change the `check` of `nextjs/missing-security-headers`:

```ts
    check: (file) =>
      HEADERS_BLOCK.test(file.content)
        ? []
        : [{ line: 1, fix: { kind: 'add-security-headers', file: file.path } }]
```

- [ ] **Step 7: Run the tests, then the full suite**

Run: `pnpm vitest run test/fix/fixers.test.ts test/scanners/web`
Expected: PASS.

Run: `pnpm test`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/types.ts src/fix/fixers.ts src/fix/interactive.ts src/scanners/web/rules/nextjs.ts test/fix/fixers.test.ts
git commit -m "feat: add the add-security-headers fix for Next.js configs"
```

---

## Task 11: Diff preview before applying a rewrite

`resolveFindings` prints the message and asks "Fix this now?" without showing what it will write. That was fine when every fix inserted a comment; it is not fine now that fixes rewrite code.

**Files:**
- Modify: `src/fix/interactive.ts:81-106` (`resolveFindings`)
- Test: `test/fix/interactive.test.ts` (append)

**Interfaces:**
- Consumes: `FixDescriptor` with `rewrite?: true` (Task 8).
- Produces: `resolveFindings` gains a fifth injectable parameter, `readLine: (file: string, line: number, cwd: string) => string | undefined`, defaulting to a disk read that returns `undefined` on any failure. Existing four-argument call sites are unaffected.

- [ ] **Step 1: Write the failing test**

Append inside the existing top-level `describe` in `test/fix/interactive.test.ts`:

```ts
  it('shows a before/after diff before asking about a rewrite', async () => {
    const printed: string[] = [];
    const log = vi.spyOn(console, 'log').mockImplementation((message: unknown) => {
      printed.push(String(message));
    });

    const finding: Finding = {
      scanner: 'web',
      severity: 'high',
      file: 'a.ts',
      line: 3,
      message: 'cookie has no flags',
      fix: {
        kind: 'replace-line',
        file: 'a.ts',
        line: 3,
        replacement: "res.cookie('s', t, { httpOnly: true });",
        rewrite: true
      }
    };

    await resolveFindings(
      [finding],
      '/repo',
      async () => 'n',
      () => [],
      () => undefined,
      () => "res.cookie('s', t);"
    );

    log.mockRestore();
    expect(printed.join('\n')).toContain("- res.cookie('s', t);");
    expect(printed.join('\n')).toContain("+ res.cookie('s', t, { httpOnly: true });");
  });

  it('shows no diff for a suppression marker', async () => {
    const printed: string[] = [];
    const log = vi.spyOn(console, 'log').mockImplementation((message: unknown) => {
      printed.push(String(message));
    });

    const finding: Finding = {
      scanner: 'owasp',
      severity: 'high',
      file: 'a.ts',
      line: 3,
      message: 'reviewed',
      fix: { kind: 'replace-line', file: 'a.ts', line: 3, replacement: '// marker\nORIGINAL' }
    };

    await resolveFindings([finding], '/repo', async () => 'n', () => [], () => undefined, () => 'ORIGINAL');

    log.mockRestore();
    expect(printed.join('\n')).not.toContain('+ ');
  });

  it('asks without a diff when the original line cannot be read', async () => {
    const answers: string[] = [];
    const finding: Finding = {
      scanner: 'web',
      severity: 'high',
      file: 'a.ts',
      line: 3,
      message: 'cookie has no flags',
      fix: { kind: 'replace-line', file: 'a.ts', line: 3, replacement: 'FIXED', rewrite: true }
    };

    const result = await resolveFindings(
      [finding],
      '/repo',
      async () => {
        answers.push('asked');
        return 'y';
      },
      () => [],
      () => undefined,
      () => undefined
    );

    expect(answers).toEqual(['asked']);
    expect(result.resolved).toHaveLength(1);
  });
```

Add `vi` to the `vitest` import in that file if it is not already there.

- [ ] **Step 2: Run it to make sure it fails**

Run: `pnpm vitest run test/fix/interactive.test.ts`
Expected: FAIL — `resolveFindings` takes five parameters, and nothing prints a diff.

- [ ] **Step 3: Implement the preview in `src/fix/interactive.ts`**

Add the imports and reader:

```ts
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
```

```ts
type ReadLineFn = (file: string, line: number, cwd: string) => string | undefined;

/** Best-effort: a preview that cannot be produced is simply not shown. */
const readWorkingTreeLine: ReadLineFn = (file, line, cwd) => {
  try {
    return readFileSync(join(cwd, file), 'utf8').split('\n')[line - 1];
  } catch {
    return undefined;
  }
};

/**
 * Prints what the fix will write, for a fix that genuinely changes code.
 * Accepting a suppression marker is low-stakes and self-explanatory; accepting a
 * rewrite is not, so the author sees the new line before saying yes.
 */
function previewRewrite(fix: FixDescriptor, cwd: string, readLine: ReadLineFn): void {
  if (fix.kind !== 'replace-line' || fix.rewrite !== true) return;

  const before = readLine(fix.file, fix.line, cwd);
  if (before === undefined) return;

  const after = fix.replacement.split('\n');
  console.log(`\n  - ${before.trim()}`);
  for (const added of after) {
    console.log(`  + ${added.trim()}`);
  }
  console.log('');
}
```

Extend the signature and call it before the prompt:

```ts
export async function resolveFindings(
  findings: Finding[],
  cwd: string,
  prompt: PromptFn,
  fix: ApplyFn = applyFix,
  restage: RestageFn = restageFile,
  readLine: ReadLineFn = readWorkingTreeLine
): Promise<ResolveResult> {
```

Inside the prompting loop, between the `if (!finding.fix)` guard and `await prompt(finding)`:

```ts
    previewRewrite(finding.fix, cwd, readLine);
    const answer = await prompt(finding);
```

- [ ] **Step 4: Run the test, then the full suite**

Run: `pnpm vitest run test/fix/interactive.test.ts`
Expected: PASS.

Run: `pnpm test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/fix/interactive.ts test/fix/interactive.test.ts
git commit -m "feat: show a before/after diff before applying a rewrite"
```

---

## Task 12: Layer 2 — the `--json` agent handoff report

**Files:**
- Create: `src/report.ts`
- Modify: `src/commands/scan.ts` (a reporting mode that skips prompting)
- Modify: `src/cli.ts` (`--json`)
- Test: `test/report.test.ts`
- Test: `test/commands/scan.test.ts` (append)

**Interfaces:**
- Consumes: `Finding` from `src/types.ts`.
- Produces: `buildReport(findings: Finding[]): Report` and `interface Report { version: 1; findings: ReportFinding[] }` where `ReportFinding = { rule: string | undefined; scanner: string; severity: string; file: string; line: number; message: string; hasAutomaticFix: boolean }`. `ScanOptions` gains `json?: boolean`.

The report deliberately carries no timestamp: identical staged content must produce identical bytes, so the file can be committed, diffed, or cached.

- [ ] **Step 1: Write the failing report test**

Create `test/report.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { buildReport } from '../src/report.js';
import type { Finding } from '../src/types.js';

const finding: Finding = {
  scanner: 'web',
  severity: 'critical',
  file: 'app/api/user/route.ts',
  line: 12,
  message: 'The whole request body is handed to the write. [agnostic/mass-assignment] (app/api/user/route.ts:12)',
  scope: 'line'
};

describe('buildReport', () => {
  it('extracts the rule id from the message', () => {
    expect(buildReport([finding]).findings[0].rule).toBe('agnostic/mass-assignment');
  });

  it('leaves the rule undefined for a scanner that does not tag ids', () => {
    const secret: Finding = { ...finding, scanner: 'secrets', message: 'AWS key found (a.ts:1)' };
    expect(buildReport([secret]).findings[0].rule).toBeUndefined();
  });

  it('records whether an automatic fix is available', () => {
    const fixable: Finding = {
      ...finding,
      fix: { kind: 'replace-line', file: 'a.ts', line: 1, replacement: 'x', rewrite: true }
    };
    expect(buildReport([fixable]).findings[0].hasAutomaticFix).toBe(true);
    expect(buildReport([finding]).findings[0].hasAutomaticFix).toBe(false);
  });

  it('stamps a schema version so a consumer can detect a change', () => {
    expect(buildReport([]).version).toBe(1);
  });

  it('is byte-stable for the same input', () => {
    expect(JSON.stringify(buildReport([finding]))).toBe(JSON.stringify(buildReport([finding])));
  });
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `pnpm vitest run test/report.test.ts`
Expected: FAIL — cannot resolve `src/report.js`.

- [ ] **Step 3: Write `src/report.ts`**

```ts
import type { Finding } from './types.js';

export interface ReportFinding {
  /** The web scanner's rule id, where the message carries one. */
  rule: string | undefined;
  scanner: string;
  severity: string;
  file: string;
  line: number;
  message: string;
  hasAutomaticFix: boolean;
}

export interface Report {
  /** Bumped whenever the shape changes, so a consumer can notice. */
  version: 1;
  findings: ReportFinding[];
}

/**
 * A machine-readable view of the findings, for handing to a coding agent that
 * already has the whole repository in context. No timestamp: identical staged
 * content must produce identical bytes so the file can be committed or diffed.
 */
export function buildReport(findings: Finding[]): Report {
  return {
    version: 1,
    findings: findings.map((finding) => ({
      rule: /\[([a-z]+\/[a-z0-9-]+)\]/.exec(finding.message)?.[1],
      scanner: finding.scanner,
      severity: finding.severity,
      file: finding.file,
      line: finding.line,
      message: finding.message,
      hasAutomaticFix: finding.fix !== undefined
    }))
  };
}
```

- [ ] **Step 4: Add the reporting mode to `src/commands/scan.ts`**

Add `json?: boolean;` to `ScanOptions` and the import:

```ts
import { buildReport } from '../report.js';
```

Insert this block in `scanCommand`, immediately after `const { findings, warnings } = await collectFindings(...)`:

```ts
  // Reporting mode: emit the findings and exit cleanly. This is run by hand,
  // not by the hook, so it must never prompt and never block.
  if (options.json === true) {
    console.log(JSON.stringify(buildReport(findings), null, 2));
    return 0;
  }
```

- [ ] **Step 5: Tell the user the report exists**

In `scanCommand`, replace the unresolved-findings error message so it points at the handoff:

```ts
  if (unresolved.length > 0) {
    console.error(
      `\nsecretfix: ${unresolved.length} unresolved issue(s). Commit blocked.\n` +
        'Fix them, or silence a line with "// secretfix-ignore-next-line", or run "git commit --no-verify" to bypass.\n' +
        'Working with an AI coding agent? Run "secretfix scan --json > .secretfix-report.json"\n' +
        'and tell it: "fix everything in this report".'
    );
    return 1;
  }
```

- [ ] **Step 6: Add `--json` to `src/cli.ts`**

Add the option and pass it through, extending the action's parameter type with `json?: boolean`:

```ts
    .option('--json', 'print findings as JSON and exit without prompting or blocking')
```

```ts
          json: opts.json,
```

- [ ] **Step 7: Write the failing integration test**

Append inside the existing top-level `describe` in `test/commands/scan.test.ts`:

```ts
  it('--json prints a report and does not block', async () => {
    const printed: string[] = [];
    const log = vi.spyOn(console, 'log').mockImplementation((message: unknown) => {
      printed.push(String(message));
    });

    const cwd = makeRepo();
    stageFile(cwd, 'app/api/proxy/route.ts', 'export async function GET(req) {\n  return fetch(req.query.url);\n}\n');

    const code = await scanCommand({ cwd, json: true, prompt: async () => 'skip' });
    log.mockRestore();

    expect(code).toBe(0);
    const report = JSON.parse(printed.join('\n')) as { version: number; findings: { rule?: string }[] };
    expect(report.version).toBe(1);
    expect(report.findings.some((finding) => finding.rule === 'agnostic/ssrf')).toBe(true);
  });

  it('--json never prompts', async () => {
    const cwd = makeRepo();
    stageFile(cwd, 'app/api/proxy/route.ts', 'export async function GET(req) {\n  return fetch(req.query.url);\n}\n');

    await scanCommand({
      cwd,
      json: true,
      prompt: async () => {
        throw new Error('should not prompt in reporting mode');
      }
    });
  });
```

Add `vi` to the `vitest` import if it is not already there.

- [ ] **Step 8: Run the tests, then the full suite**

Run: `pnpm vitest run test/report.test.ts test/commands/scan.test.ts`
Expected: PASS.

Run: `pnpm test`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add src/report.ts src/commands/scan.ts src/cli.ts test/report.test.ts test/commands/scan.test.ts
git commit -m "feat: add --json report for handing findings to a coding agent"
```

---

## Task 13: Layer 3 — the optional AI fix layer

Off by default. It runs in the **fix** phase, so the 5-second `SCANNER_TIMEOUT_MS` in `orchestrator.ts` does not apply to it.

**Files:**
- Create: `src/fix/ai.ts`
- Modify: `src/commands/scan.ts` (attach AI fixes before `resolveFindings`)
- Modify: `src/cli.ts` (`--ai`)
- Modify: `package.json` (`optionalDependencies`)
- Test: `test/fix/ai.test.ts`

**Interfaces:**
- Consumes: `Finding`, `FixDescriptor` from `src/types.ts`; `SecretFixConfig` from `src/config.ts`.
- Produces, from `src/fix/ai.ts`:
  - `interface AiMessage { stop_reason?: string; content: { type: string; text?: string }[] }`
  - `type SendFn = (prompt: string, system: string) => Promise<AiMessage | undefined>`
  - `proposeFixes(findings: Finding[], cwd: string, send?: SendFn): Promise<Finding[]>`

`proposeFixes` returns the findings with a `fix` attached where the model produced a usable patch, and unchanged otherwise. `send` returning `undefined` means "no credentials or no SDK" and is not an error.

- [ ] **Step 1: Write the failing test**

Create `test/fix/ai.test.ts`:

```ts
import { describe, it, expect, vi } from 'vitest';
import { proposeFixes } from '../../src/fix/ai.js';
import type { Finding } from '../../src/types.js';

const finding: Finding = {
  scanner: 'web',
  severity: 'critical',
  file: 'app/api/user/route.ts',
  line: 2,
  message: 'mass assignment [agnostic/mass-assignment] (app/api/user/route.ts:2)'
};

function reply(text: string) {
  return async () => ({ content: [{ type: 'text', text }] });
}

describe('proposeFixes', () => {
  it('turns a schema-valid patch into a rewrite fix', async () => {
    const patch = JSON.stringify({
      file: 'app/api/user/route.ts',
      line: 2,
      replacement: '  data: { name: body.name },',
      explanation: 'Only the name field is accepted.'
    });

    const [result] = await proposeFixes([finding], '/repo', reply(patch));

    expect(result.fix).toMatchObject({
      kind: 'replace-line',
      file: 'app/api/user/route.ts',
      line: 2,
      replacement: '  data: { name: body.name },',
      rewrite: true
    });
  });

  it('leaves the finding untouched when the model refuses', async () => {
    const send = async () => ({ stop_reason: 'refusal', content: [] });
    const [result] = await proposeFixes([finding], '/repo', send);
    expect(result.fix).toBeUndefined();
  });

  it('leaves the finding untouched when there are no credentials', async () => {
    const [result] = await proposeFixes([finding], '/repo', async () => undefined);
    expect(result.fix).toBeUndefined();
  });

  it('rejects a patch that points at a different file', async () => {
    const patch = JSON.stringify({ file: 'other.ts', line: 2, replacement: 'x', explanation: 'y' });
    const [result] = await proposeFixes([finding], '/repo', reply(patch));
    expect(result.fix).toBeUndefined();
  });

  it('rejects a patch that points at a different line', async () => {
    const patch = JSON.stringify({ file: 'app/api/user/route.ts', line: 9, replacement: 'x', explanation: 'y' });
    const [result] = await proposeFixes([finding], '/repo', reply(patch));
    expect(result.fix).toBeUndefined();
  });

  it('rejects unparseable output rather than throwing', async () => {
    const [result] = await proposeFixes([finding], '/repo', reply('sorry, no idea'));
    expect(result.fix).toBeUndefined();
  });

  it('never asks about a finding that already has a deterministic fix', async () => {
    const send = vi.fn(reply('{}'));
    const fixable: Finding = {
      ...finding,
      fix: { kind: 'replace-line', file: 'a.ts', line: 1, replacement: 'x', rewrite: true }
    };

    await proposeFixes([fixable], '/repo', send);

    expect(send).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `pnpm vitest run test/fix/ai.test.ts`
Expected: FAIL — cannot resolve `src/fix/ai.js`.

- [ ] **Step 3: Write `src/fix/ai.ts`**

```ts
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type AnthropicSdk from '@anthropic-ai/sdk';
import type { Finding, FixDescriptor } from '../types.js';

const MODEL = 'claude-opus-5';

/** Lines of surrounding code sent with each finding. */
const CONTEXT_RADIUS = 12;

const SYSTEM_PROMPT = `You fix security defects in web application code.
You are given one finding and the lines around it. Reply with a JSON object and nothing else:
{"file": string, "line": number, "replacement": string, "explanation": string}
"replacement" replaces exactly that one line, preserving its indentation.
"file" and "line" must repeat the values you were given.
If a single-line replacement cannot fix the defect correctly, reply {"file":"","line":0,"replacement":"","explanation":"reason"}.`;

const PATCH_SCHEMA = {
  type: 'object',
  properties: {
    file: { type: 'string' },
    line: { type: 'integer' },
    replacement: { type: 'string' },
    explanation: { type: 'string' }
  },
  required: ['file', 'line', 'replacement', 'explanation'],
  additionalProperties: false
} as const;

export interface AiMessage {
  stop_reason?: string;
  content: { type: string; text?: string }[];
}

/** Returns undefined when there is no SDK or no credentials — not an error. */
export type SendFn = (prompt: string, system: string) => Promise<AiMessage | undefined>;

interface AiPatch {
  file: string;
  line: number;
  replacement: string;
  explanation: string;
}

/**
 * Sends one request per finding.
 *
 * `fallbacks: 'default'` matters here specifically: Claude Opus 5 runs
 * cybersecurity classifiers, and this tool's whole job is to send vulnerable
 * code and ask for a security fix — exactly the shape that gets declined. With
 * fallbacks on, a cyber-category refusal is retried server-side on another model
 * inside the same call. `stop_reason` is still checked before `content`, because
 * a refusal returns HTTP 200 with an empty content array.
 */
const defaultSend: SendFn = async (prompt, system) => {
  let Anthropic: typeof AnthropicSdk;
  try {
    ({ default: Anthropic } = await import('@anthropic-ai/sdk'));
  } catch {
    console.warn('secretfix: --ai needs @anthropic-ai/sdk — run "pnpm add -O @anthropic-ai/sdk".');
    return undefined;
  }

  // The SDK resolves credentials itself: ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN,
  // then an `ant auth login` profile on disk. An unset env var does not mean
  // there are no credentials, so construct the client and let it decide.
  const client = new Anthropic();

  try {
    // `fallbacks` and `output_config.format` are beta fields the SDK's typings
    // lag behind, so the request object is asserted rather than inferred. Keep
    // this the only assertion in the file, and drop it once the types land.
    const request = {
      model: MODEL,
      max_tokens: 2048,
      betas: ['server-side-fallback-2026-07-01'],
      fallbacks: 'default',
      output_config: { effort: 'low', format: { type: 'json_schema', schema: PATCH_SCHEMA } },
      system: [{ type: 'text', text: system, cache_control: { type: 'ephemeral' } }],
      messages: [{ role: 'user', content: prompt }]
    } as unknown as Parameters<typeof client.beta.messages.create>[0];

    return (await client.beta.messages.create(request)) as AiMessage;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.warn(`secretfix: --ai request failed — ${message}`);
    return undefined;
  }
};

function snippet(file: string, line: number, cwd: string): string | undefined {
  try {
    const lines = readFileSync(join(cwd, file), 'utf8').split('\n');
    const from = Math.max(0, line - 1 - CONTEXT_RADIUS);
    const to = Math.min(lines.length, line + CONTEXT_RADIUS);
    return lines
      .slice(from, to)
      .map((text, index) => `${from + index + 1}: ${text}`)
      .join('\n');
  } catch {
    return undefined;
  }
}

function parsePatch(message: AiMessage): AiPatch | undefined {
  // A refusal is HTTP 200 with an empty content array, so check this first —
  // reading content[0] unconditionally would throw.
  if (message.stop_reason === 'refusal') return undefined;

  const text = message.content.find((block) => block.type === 'text')?.text;
  if (text === undefined) return undefined;

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (typeof parsed !== 'object' || parsed === null) return undefined;

  const patch = parsed as Partial<AiPatch>;
  if (
    typeof patch.file !== 'string' ||
    typeof patch.line !== 'number' ||
    typeof patch.replacement !== 'string' ||
    typeof patch.explanation !== 'string'
  ) {
    return undefined;
  }
  return { file: patch.file, line: patch.line, replacement: patch.replacement, explanation: patch.explanation };
}

/**
 * Attaches an AI-proposed fix to findings that have no deterministic one.
 * Findings that already carry a fix are never sent anywhere.
 */
export async function proposeFixes(
  findings: Finding[],
  cwd: string,
  send: SendFn = defaultSend
): Promise<Finding[]> {
  const result: Finding[] = [];

  for (const finding of findings) {
    if (finding.fix !== undefined) {
      result.push(finding);
      continue;
    }

    const code = snippet(finding.file, finding.line, cwd);
    if (code === undefined) {
      result.push(finding);
      continue;
    }

    const prompt = [
      `Finding: ${finding.message}`,
      `File: ${finding.file}`,
      `Line: ${finding.line}`,
      '',
      code
    ].join('\n');

    const message = await send(prompt, SYSTEM_PROMPT);
    if (message === undefined) {
      result.push(finding);
      continue;
    }

    const patch = parsePatch(message);
    // The model must confirm the exact target it was given. Anything else is a
    // patch for a line we did not ask about, and applying it would be a silent
    // wrong fix.
    if (patch === undefined || patch.file !== finding.file || patch.line !== finding.line) {
      result.push(finding);
      continue;
    }

    const fix: FixDescriptor = {
      kind: 'replace-line',
      file: finding.file,
      line: finding.line,
      replacement: patch.replacement,
      rewrite: true
    };
    result.push({ ...finding, message: `${finding.message}\n  AI: ${patch.explanation}`, fix });
  }

  return result;
}
```

- [ ] **Step 4: Run the AI test to verify it passes**

Run: `pnpm vitest run test/fix/ai.test.ts`
Expected: PASS (7 tests). No network call happens — every case injects `send`.

- [ ] **Step 5: Wire it into `src/commands/scan.ts`**

Add the import:

```ts
import { proposeFixes } from '../fix/ai.js';
```

In `scanCommand`, replace the `resolveFindings` call with:

```ts
  const withFixes = config.ai ? await proposeFixes(blocking, cwd) : blocking;
  const { resolved, unresolved } = await resolveFindings(withFixes, cwd, options.prompt);
```

- [ ] **Step 6: Add `--ai` to `src/cli.ts`**

```ts
    .option('--ai', 'let Claude propose a patch for findings with no automatic fix (sends code to the API)')
```

```ts
          ai: opts.ai,
```

Extend the action's parameter type with `ai?: boolean`.

- [ ] **Step 7: Declare the optional dependency**

In `package.json`, after `devDependencies`:

```json
  "optionalDependencies": {
    "@anthropic-ai/sdk": "^0.110.0"
  }
```

It is optional and dynamically imported, so `npx secretfix` stays light for everyone who never passes `--ai`.

Note the tradeoff this creates: `ai.ts` uses `import type AnthropicSdk from '@anthropic-ai/sdk'`, so `tsc` needs the package present. pnpm installs optional dependencies by default, and consumers install `dist/` rather than building, so this is fine — but a CI job running `pnpm install --no-optional` would fail the build. If that ever becomes a constraint, drop the type import and assert the constructor instead.

- [ ] **Step 8: Run the full suite**

Run: `pnpm test`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add src/fix/ai.ts src/commands/scan.ts src/cli.ts package.json test/fix/ai.test.ts
git commit -m "feat: add the optional AI fix layer behind --ai"
```

---

## Task 14: End-to-end coverage and documentation

**Files:**
- Modify: `test/e2e/full-flow.test.ts` (append)
- Modify: `README.md`
- Test: the E2E file is the test

**Interfaces:**
- Consumes: everything from Tasks 1–13.
- Produces: no new exports.

- [ ] **Step 1: Write the failing end-to-end tests**

Append inside the existing top-level `describe` in `test/e2e/full-flow.test.ts`, reusing that file's scratch-repo and staging helpers.

```ts
  it('blocks a commit that stages mass assignment, and offers no fix for it', async () => {
    const cwd = makeRepo();
    writeFileSync(join(cwd, 'package.json'), JSON.stringify({ dependencies: { next: '16.0.0' } }));
    stageFile(cwd, 'package.json', readFileSync(join(cwd, 'package.json'), 'utf8'));
    stageFile(
      cwd,
      'app/api/user/route.ts',
      [
        'export async function PATCH(req) {',
        '  const session = await auth();',
        '  const body = await req.json();',
        '  return prisma.user.update({ where: { id: session.userId }, data: body });',
        '}',
        ''
      ].join('\n')
    );

    const answers: string[] = [];
    const code = await scanCommand({
      cwd,
      prompt: async () => {
        answers.push('asked');
        return 'y';
      }
    });

    expect(code).toBe(1);
    // No fix exists, so the user is never asked — the finding goes straight to blocked.
    expect(answers).toEqual([]);
  });

  it('fixes a cookie finding, re-stages, and lets the commit through', async () => {
    const cwd = makeRepo();
    stageFile(
      cwd,
      'server.js',
      ['const app = express();', "app.use(helmet());", "app.get('/', (req, res) => {", "  res.cookie('session', 't');", '  res.end();', '});', ''].join('\n')
    );

    const code = await scanCommand({ cwd, prompt: async () => 'y' });

    expect(code).toBe(0);
    const updated = readFileSync(join(cwd, 'server.js'), 'utf8');
    expect(updated).toContain('httpOnly: true');
    // The fix must be in the index, not just the working tree.
    expect(execFileSync('git', ['diff', '--cached', '--', 'server.js'], { cwd, encoding: 'utf8' })).toContain(
      'httpOnly: true'
    );
  });

  it('reports nothing for a route handler that middleware already protects', async () => {
    const cwd = makeRepo();
    writeFileSync(join(cwd, 'package.json'), JSON.stringify({ dependencies: { next: '16.0.0' } }));
    writeFileSync(join(cwd, 'middleware.ts'), "export const config = { matcher: ['/api/admin/:path*'] };\n");
    execFileSync('git', ['add', 'package.json', 'middleware.ts'], { cwd });
    stageFile(cwd, 'app/api/admin/users/route.ts', 'export async function POST(req) {\n  return save(await req.json());\n}\n');

    expect(await scanCommand({ cwd, prompt: async () => 'skip' })).toBe(0);
  });

  it('skips Next.js rules entirely in a project that is not Next.js', async () => {
    const cwd = makeRepo();
    writeFileSync(join(cwd, 'package.json'), JSON.stringify({ dependencies: { express: '4.0.0' } }));
    execFileSync('git', ['add', 'package.json'], { cwd });
    stageFile(cwd, '.env', 'NEXT_PUBLIC_API_KEY=abc\n');

    expect(await scanCommand({ cwd, prompt: async () => 'skip' })).toBe(0);
  });
```

- [ ] **Step 2: Run them**

Run: `pnpm vitest run test/e2e/full-flow.test.ts`
Expected: PASS. If the fourth test fails, `.env` is probably in `DEFAULT_EXCLUDES` or is being caught by the secrets scanner instead — check which scanner reported it before changing a rule.

- [ ] **Step 3: Document the scanner in `README.md`**

Add a section after the existing scanner descriptions:

```markdown
### Web scanner

Catches the web-application holes the OWASP pattern scanner does not see: API
routes with no auth check, request bodies passed straight into database writes,
secrets compiled into the browser bundle, wide-open Firebase or Supabase rules,
and missing security headers. 26 rules across four families, and only the ones
matching your stack run — the scanner reads `package.json` and skips the Next.js
rules in an Express project, and vice versa.

Some of these cannot be proven from the code alone. "This route has no auth
check" is true unless the check lives in `middleware.ts`, in a `withAuth()`
wrapper, or in a shared helper — so secretfix looks in those places first, and
where it still cannot tell, it prints a note instead of blocking your commit.

Turn the family off with `--no-web`, or silence a single rule:

```json
{
  "webRules": { "nextjs/route-handler-no-auth": false }
}
```

Fixes are automated only where the correct change is mechanical — adding cookie
flags, writing a `headers()` block, narrowing `express.static`. For anything
where only you know the right answer (which fields an update should accept, which
origins CORS should allow), secretfix explains the problem and blocks the commit
rather than guessing.

#### Working with an AI agent

```bash
secretfix scan --json > .secretfix-report.json
```

Then tell your agent to fix everything in the report. It already has your whole
repository in context, and this costs nothing extra.

Alternatively `--ai` lets secretfix propose the patch itself. It is off by
default because it sends the affected code to the Anthropic API. No API key is
required if you have run `ant auth login` — the SDK picks that profile up
automatically. Note that Claude Code may then warn about a conflict with its own
`/login` credential; keep one of the two.
```

- [ ] **Step 4: Run the full suite one last time**

Run: `pnpm test`
Expected: PASS, with every task's tests green.

- [ ] **Step 5: Commit**

```bash
git add test/e2e/full-flow.test.ts README.md
git commit -m "test: add end-to-end web scanner coverage and document the scanner"
```

---

## Coverage map

| Spec section | Task |
|---|---|
| §1 rule catalogue, rules 1–4, 6–9 | 3 |
| §1 rules 5, 10, 11 | 5 |
| §1 rules 12–19 | 6 |
| §1 rules 20–26 | 7 |
| §1 rule 13/26 de-duplication | 7 |
| §2.1 `ScanContext`, factory injection | 1, 4 |
| §2.2 framework detection | 1 |
| §2.3 rule shapes, `Hit` | 1, 3 |
| §2.4 block extraction, no AST | 2 |
| §3 flow | 4, 11, 12, 13 |
| §4 diff scoping | 4 |
| §4 staged-anchor gating | 3, 6 |
| §4 per-rule disable | 4 |
| §5 confidence resolution | 3, 5 |
| §6 automated fixes | 9, 10 |
| §6 explain-only findings | 3, 5, 7 (no `fix` attached) |
| §6.1 diff preview | 11 |
| §6.2 `mergeReplacements` collision | 8 |
| §7 layer 2 | 12 |
| §7 layer 3, refusal, credentials, optional dep | 13 |
| §8 config and CLI | 4, 12, 13 |
| §9 error handling | 1 (detection), 2 (unparseable block), 5 (missing middleware), 10 (unsafe config), 13 (network/refusal) |
| §10 testing | every task; E2E in 14 |
