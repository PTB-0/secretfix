import { describe, it, expect } from 'vitest';
import { createWebScanner, isCommentOnlyLine } from '../../../src/scanners/web/index.js';
import { ALL_RULES } from '../../../src/scanners/web/index.js';
import type { Framework, ScanContext, WebRule } from '../../../src/scanners/web/types.js';

function contextWith(frameworks: Framework[], files: Record<string, string> = {}): ScanContext {
  return { cwd: '/repo', frameworks: new Set(frameworks), readRepoFile: (path) => files[path] };
}

/** All frameworks the catalogue recognizes, so every rule in ALL_RULES is active. */
const EVERY_FRAMEWORK: Framework[] = ['agnostic', 'nextjs', 'express', 'supabase', 'firebase'];

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
});

describe('isCommentOnlyLine', () => {
  it.each([
    ['// a JS/TS/Firestore-rules line comment', '// res.cookie(...)'],
    ['a -- SQL line comment', '-- ALTER TABLE profiles DISABLE ROW LEVEL SECURITY;'],
    ['a # .env/YAML line comment', '# NEXT_PUBLIC_API_SECRET=abc123'],
    ['a /* block-comment opening line', '/* fs.readFile(req.query.file) */'],
    ['a * block-comment continuation line', ' * still describing the old call']
  ])('treats %s as comment-only', (_label, line) => {
    expect(isCommentOnlyLine(line)).toBe(true);
  });

  it('treats an empty line as not comment-only', () => {
    expect(isCommentOnlyLine('')).toBe(false);
  });

  it('treats a whitespace-only line as not comment-only', () => {
    expect(isCommentOnlyLine('    ')).toBe(false);
  });

  it('treats a live line as not comment-only', () => {
    expect(isCommentOnlyLine("res.cookie('session', token);")).toBe(false);
  });

  it('treats a live line with a trailing comment as not comment-only', () => {
    expect(isCommentOnlyLine("doThing(); // and req.body here")).toBe(false);
  });
});

describe('comment-only line guard (end-to-end)', () => {
  it('does not report a commented-out path-traversal call', async () => {
    const scanner = createWebScanner(contextWith(EVERY_FRAMEWORK), ALL_RULES);
    const findings = await scanner.scan([
      { path: 'server.ts', content: '// old code used to call fs.readFile(req.query.file) unsafely' }
    ]);
    expect(findings).toHaveLength(0);
  });

  it('still reports the live path-traversal call', async () => {
    const scanner = createWebScanner(contextWith(EVERY_FRAMEWORK), ALL_RULES);
    const findings = await scanner.scan([{ path: 'server.ts', content: 'fs.readFile(req.query.file);' }]);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('[agnostic/path-traversal]');
  });

  it('does not report a commented-out insecure cookie call', async () => {
    const scanner = createWebScanner(contextWith(EVERY_FRAMEWORK), ALL_RULES);
    const findings = await scanner.scan([{ path: 'server.ts', content: "// res.cookie('session', token);" }]);
    expect(findings).toHaveLength(0);
  });

  it('still reports the live insecure cookie call', async () => {
    const scanner = createWebScanner(contextWith(EVERY_FRAMEWORK), ALL_RULES);
    const findings = await scanner.scan([{ path: 'server.ts', content: "res.cookie('session', token);" }]);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('[agnostic/insecure-cookie]');
  });

  it('does not report a commented-out RLS-disabled statement in a SQL migration', async () => {
    const scanner = createWebScanner(contextWith(EVERY_FRAMEWORK), ALL_RULES);
    const findings = await scanner.scan([
      { path: 'migrations/0001_init.sql', content: '-- ALTER TABLE profiles DISABLE ROW LEVEL SECURITY;' }
    ]);
    expect(findings).toHaveLength(0);
  });

  it('still reports the live RLS-disabled statement in a SQL migration', async () => {
    const scanner = createWebScanner(contextWith(EVERY_FRAMEWORK), ALL_RULES);
    const findings = await scanner.scan([
      { path: 'migrations/0001_init.sql', content: 'ALTER TABLE profiles DISABLE ROW LEVEL SECURITY;' }
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('[baas/supabase-rls-disabled]');
  });

  it('does not report a commented-out open Firestore rule', async () => {
    const scanner = createWebScanner(contextWith(EVERY_FRAMEWORK), ALL_RULES);
    const findings = await scanner.scan([
      { path: 'firestore.rules', content: '// allow read, write: if true;' }
    ]);
    expect(findings).toHaveLength(0);
  });

  it('still reports the live open Firestore rule', async () => {
    const scanner = createWebScanner(contextWith(EVERY_FRAMEWORK), ALL_RULES);
    const findings = await scanner.scan([{ path: 'firestore.rules', content: 'allow read, write: if true;' }]);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('[baas/firebase-rules-open]');
  });

  it('does not report a commented-out NEXT_PUBLIC_ secret in a .env file', async () => {
    const scanner = createWebScanner(contextWith(EVERY_FRAMEWORK), ALL_RULES);
    const findings = await scanner.scan([{ path: '.env', content: '# NEXT_PUBLIC_API_SECRET=abc123' }]);
    expect(findings).toHaveLength(0);
  });

  it('still reports the live NEXT_PUBLIC_ secret in a .env file', async () => {
    const scanner = createWebScanner(contextWith(EVERY_FRAMEWORK), ALL_RULES);
    const findings = await scanner.scan([{ path: '.env', content: 'NEXT_PUBLIC_API_SECRET=abc123' }]);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('[nextjs/public-env-secret]');
  });

  it('still reports a live line whose trailing comment happens to quote a pattern', async () => {
    // Documents the deliberate limit: only whole-line comments are suppressed.
    // A trailing comment on live code needs real tokenisation to strip safely,
    // and this rule set does not attempt it.
    const scanner = createWebScanner(contextWith(EVERY_FRAMEWORK), ALL_RULES);
    const findings = await scanner.scan([
      { path: 'server.ts', content: 'fs.readFile(req.query.file); // used to be unsafe, now it is not' }
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('[agnostic/path-traversal]');
  });

  it('keeps 1-based line numbering when leading lines are comment-only', async () => {
    const scanner = createWebScanner(contextWith(EVERY_FRAMEWORK), ALL_RULES);
    const content = ['// this is fine', '// still fine', 'fs.readFile(req.query.file);'].join('\n');
    const findings = await scanner.scan([{ path: 'server.ts', content }]);
    expect(findings).toHaveLength(1);
    expect(findings[0].line).toBe(3);
  });
});
