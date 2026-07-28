import { describe, it, expect, vi } from 'vitest';
import { execFileSync } from 'node:child_process';
import { defaultRunNpmAudit } from '../../src/scanners/deps.js';

vi.mock('node:child_process', () => ({ execFileSync: vi.fn(() => JSON.stringify({ vulnerabilities: {} })) }));

describe('defaultRunNpmAudit', () => {
  it('runs npm through a shell on Windows, so npm.cmd actually spawns instead of ENOENT/EINVAL', () => {
    defaultRunNpmAudit('/repo');

    const [command, args, options] = vi.mocked(execFileSync).mock.calls[0];
    if (process.platform === 'win32') {
      // A single fixed command string, not array args + shell:true — Node
      // warns (DEP0190) on that combination because the args aren't escaped.
      expect(command).toBe('npm audit --json');
      expect(args).toEqual([]);
      expect((options as { shell?: boolean }).shell).toBe(true);
    } else {
      expect(command).toBe('npm');
      expect(args).toEqual(['audit', '--json']);
      expect((options as { shell?: boolean }).shell).toBeUndefined();
    }
  });
});
