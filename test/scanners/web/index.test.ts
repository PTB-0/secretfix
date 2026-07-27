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
    ['// a JS/TS/Firestore-rules line comment', '// res.cookie(...)', 'a.ts'],
    ['a -- SQL line comment in a .sql file', '-- ALTER TABLE profiles DISABLE ROW LEVEL SECURITY;', 'supabase/migrations/001.sql'],
    ['a # comment in a .env file', '# NEXT_PUBLIC_API_SECRET=abc123', '.env.local'],
    ['a /* ... */ block comment with nothing after the close', '/* fs.readFile(req.query.file) */', 'a.ts'],
    ['a * block-comment continuation line with no close', ' * still describing the old call', 'a.ts']
  ])('treats %s as comment-only', (_label, line, path) => {
    expect(isCommentOnlyLine(line, path)).toBe(true);
  });

  it('treats an empty line as not comment-only', () => {
    expect(isCommentOnlyLine('', 'a.ts')).toBe(false);
  });

  it('treats a whitespace-only line as not comment-only', () => {
    expect(isCommentOnlyLine('    ', 'a.ts')).toBe(false);
  });

  it('treats a live line as not comment-only', () => {
    expect(isCommentOnlyLine("res.cookie('session', token);", 'a.ts')).toBe(false);
  });

  it('treats a live line with a trailing comment as not comment-only', () => {
    expect(isCommentOnlyLine("doThing(); // and req.body here", 'a.ts')).toBe(false);
  });

  it('does not treat a decrement statement in a .js file as a comment', () => {
    // `--` only starts a comment in SQL; in JavaScript it is the decrement operator.
    expect(isCommentOnlyLine('--retriesLeft;', 'app.js')).toBe(false);
  });

  it('does not treat a private class field in a .ts file as a comment', () => {
    // `#` only starts a comment in .env/YAML; in JavaScript/TypeScript it begins
    // a private class member.
    expect(isCommentOnlyLine('#token = process.env.SECRET;', 'src/config.ts')).toBe(false);
  });

  it('treats an unclosed block comment as comment-only even mid-way through code', () => {
    expect(isCommentOnlyLine('/* legacy helper still calls fs.readFile(req.query.file)', 'server.ts')).toBe(true);
  });

  it('treats a block comment that closes and hands back to live code as not comment-only', () => {
    expect(
      isCommentOnlyLine('/* legacy helper */ fs.readFile(req.query.file);', 'server.ts')
    ).toBe(false);
  });

  it('treats a lone block-comment closer as comment-only', () => {
    expect(isCommentOnlyLine(' */', 'server.ts')).toBe(true);
  });

  it('treats a dead call between two block comments as comment-only', () => {
    // Round 1 reasoned about the first `*/` only, so it read the second comment
    // as live code. This is the regression the round-2 fix corrects.
    expect(isCommentOnlyLine('/* a */ /* calls fs.readFile(req.query.file) but is dead */', 'server.ts')).toBe(true);
  });

  it('treats live code sitting between two block comments as not comment-only', () => {
    expect(isCommentOnlyLine("/* a */ res.cookie('session', token) /* b */", 'server.ts')).toBe(false);
  });

  it('treats a live call after a bare block-comment closer as not comment-only', () => {
    expect(isCommentOnlyLine('*/ fs.readFile(req.query.file);', 'server.ts')).toBe(false);
  });

  it('treats live code after two block comments in a row as not comment-only', () => {
    expect(isCommentOnlyLine("/* a */ /* b */ res.cookie('session', token);", 'server.ts')).toBe(false);
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
      { path: 'supabase/migrations/001.sql', content: '-- ALTER TABLE profiles DISABLE ROW LEVEL SECURITY;' }
    ]);
    expect(findings).toHaveLength(0);
  });

  it('still reports the live RLS-disabled statement in a SQL migration', async () => {
    const scanner = createWebScanner(contextWith(EVERY_FRAMEWORK), ALL_RULES);
    const findings = await scanner.scan([
      { path: 'supabase/migrations/001.sql', content: 'ALTER TABLE profiles DISABLE ROW LEVEL SECURITY;' }
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
    const findings = await scanner.scan([{ path: '.env.local', content: '# NEXT_PUBLIC_API_SECRET=abc123' }]);
    expect(findings).toHaveLength(0);
  });

  it('still reports the live NEXT_PUBLIC_ secret in a .env file', async () => {
    const scanner = createWebScanner(contextWith(EVERY_FRAMEWORK), ALL_RULES);
    const findings = await scanner.scan([{ path: '.env.local', content: 'NEXT_PUBLIC_API_SECRET=abc123' }]);
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

  // Fix round 1: the guard originally suppressed a live call sitting after a
  // closed block comment, and treated `--`/`#` as comments in languages where
  // they are not — a decrement operator and a private class field, respectively.
  // These pin the corrected, path-aware behaviour.

  it('reports a live call that follows a block comment closed earlier on the same line', async () => {
    const scanner = createWebScanner(contextWith(EVERY_FRAMEWORK), ALL_RULES);
    const findings = await scanner.scan([
      { path: 'server.ts', content: '/* legacy helper */ fs.readFile(req.query.file);' }
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('[agnostic/path-traversal]');
  });

  it('does not report a dangerous call sitting inside an unclosed block comment', async () => {
    const scanner = createWebScanner(contextWith(EVERY_FRAMEWORK), ALL_RULES);
    const findings = await scanner.scan([
      { path: 'server.ts', content: '/* legacy helper still calls fs.readFile(req.query.file)' }
    ]);
    expect(findings).toHaveLength(0);
  });

  it('does not report a dangerous call fully commented on one /* ... */ line', async () => {
    const scanner = createWebScanner(contextWith(EVERY_FRAMEWORK), ALL_RULES);
    const findings = await scanner.scan([
      { path: 'server.ts', content: '/* legacy helper covers fs.readFile(req.query.file) */' }
    ]);
    expect(findings).toHaveLength(0);
  });

  it('does not report anything on a line that is only a block-comment closer', async () => {
    const scanner = createWebScanner(contextWith(EVERY_FRAMEWORK), ALL_RULES);
    const findings = await scanner.scan([{ path: 'server.ts', content: ' */' }]);
    expect(findings).toHaveLength(0);
  });

  it('does not report a dangerous call written as a JSDoc continuation line', async () => {
    const scanner = createWebScanner(contextWith(EVERY_FRAMEWORK), ALL_RULES);
    const findings = await scanner.scan([{ path: 'server.ts', content: '* fs.readFile(req.query.file);' }]);
    expect(findings).toHaveLength(0);
  });

  it('reports a decrement statement followed by a live call in a .js file', async () => {
    // `--` is a decrement operator in JavaScript, not a comment marker.
    const scanner = createWebScanner(contextWith(EVERY_FRAMEWORK), ALL_RULES);
    const findings = await scanner.scan([
      { path: 'app.js', content: "--retriesLeft; res.cookie('session', token);" }
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('[agnostic/insecure-cookie]');
  });

  it('reports a NEXT_PUBLIC_ secret assigned to a private class field in a .ts file', async () => {
    // `#` begins a private class member in JS/TS, not a comment — the gate must
    // key off file type, not the marker alone.
    const scanner = createWebScanner(contextWith(EVERY_FRAMEWORK), ALL_RULES);
    const findings = await scanner.scan([
      { path: 'src/config.ts', content: '#token = process.env.NEXT_PUBLIC_ADMIN_TOKEN;' }
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('[nextjs/public-env-secret]');
  });

  it('reports the same # line when staged as a .ts file, proving the gate is by file type', async () => {
    const scanner = createWebScanner(contextWith(EVERY_FRAMEWORK), ALL_RULES);
    const findings = await scanner.scan([
      { path: 'src/config.ts', content: '# NEXT_PUBLIC_ADMIN_TOKEN=abc' }
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('[nextjs/public-env-secret]');
  });

  // Fix round 2: round 1's block-comment check reasoned about a single `*/`
  // position, so a second comment sitting after the first close read as "live
  // code" and produced a spurious finding on an entirely inert line. The fix
  // strips every closed block comment and judges what is left, so two comments
  // around live code still fire and two comments with nothing between them
  // don't.

  it('does not report a dangerous call that is dead between two block comments on one line', async () => {
    const scanner = createWebScanner(contextWith(EVERY_FRAMEWORK), ALL_RULES);
    const findings = await scanner.scan([
      { path: 'server.ts', content: '/* a */ /* calls fs.readFile(req.query.file) but is dead */' }
    ]);
    expect(findings).toHaveLength(0);
  });

  it('reports live code sitting between two block comments on one line', async () => {
    // Guards against a lastIndexOf-based fix: that would silence this line,
    // trading a noisy failure for a silent one.
    const scanner = createWebScanner(contextWith(EVERY_FRAMEWORK), ALL_RULES);
    const findings = await scanner.scan([
      { path: 'server.ts', content: "/* a */ res.cookie('session', token) /* b */" }
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('[agnostic/insecure-cookie]');
  });

  it('reports a live call following a bare block-comment closer', async () => {
    const scanner = createWebScanner(contextWith(EVERY_FRAMEWORK), ALL_RULES);
    const findings = await scanner.scan([{ path: 'server.ts', content: '*/ fs.readFile(req.query.file);' }]);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('[agnostic/path-traversal]');
  });

  it('reports live code following two block comments in a row', async () => {
    const scanner = createWebScanner(contextWith(EVERY_FRAMEWORK), ALL_RULES);
    const findings = await scanner.scan([
      { path: 'server.ts', content: "/* a */ /* b */ res.cookie('session', token);" }
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('[agnostic/insecure-cookie]');
  });
});
