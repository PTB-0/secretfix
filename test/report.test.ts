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
