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
