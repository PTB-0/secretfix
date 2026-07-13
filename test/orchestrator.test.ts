import { describe, it, expect } from 'vitest';
import { runScanners } from '../src/orchestrator.js';
import type { Scanner, Finding, StagedFile } from '../src/types.js';

const noFiles: StagedFile[] = [];

function makeFinding(scanner: Finding['scanner']): Finding {
  return { scanner, severity: 'high', file: 'x.ts', line: 1, message: 'found' };
}

describe('runScanners', () => {
  it('collects findings from a successful scanner', async () => {
    const good: Scanner = { name: 'good', scan: async () => [makeFinding('secrets')] };
    const { findings, warnings } = await runScanners([good], noFiles);
    expect(findings).toHaveLength(1);
    expect(warnings).toHaveLength(0);
  });

  it('isolates a throwing scanner and still returns other findings', async () => {
    const bad: Scanner = {
      name: 'bad',
      scan: async () => {
        throw new Error('boom');
      }
    };
    const good: Scanner = { name: 'good', scan: async () => [makeFinding('owasp')] };
    const { findings, warnings } = await runScanners([bad, good], noFiles);
    expect(findings).toHaveLength(1);
    expect(warnings).toEqual(['bad scanner failed: boom']);
  });

  it('treats a scanner that never resolves as a timeout warning', async () => {
    const hanging: Scanner = { name: 'hanging', scan: () => new Promise(() => {}) };
    const { findings, warnings } = await runScanners([hanging], noFiles, 20);
    expect(findings).toHaveLength(0);
    expect(warnings).toEqual(['hanging scanner failed: scanner timed out']);
  });
});
