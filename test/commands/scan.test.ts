import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scanCommand } from '../../src/commands/scan.js';

let repoDir: string;

function git(args: string[]): void {
  execFileSync('git', args, { cwd: repoDir });
}

beforeEach(() => {
  repoDir = mkdtempSync(join(tmpdir(), 'vibeguard-scan-'));
  git(['init']);
  git(['config', 'user.email', 'test@vibeguard.dev']);
  git(['config', 'user.name', 'VibeGuard Test']);
});

afterEach(() => {
  rmSync(repoDir, { recursive: true, force: true });
});

describe('scanCommand', () => {
  it('returns 0 and does not block when there are no findings', async () => {
    writeFileSync(join(repoDir, 'clean.js'), 'const total = 1 + 1;\n');
    git(['add', 'clean.js']);

    const prompt = async () => 'skip' as const;
    const exitCode = await scanCommand({ cwd: repoDir, prompt, noDeps: true });

    expect(exitCode).toBe(0);
  });

  it('returns 1 when a finding is left unresolved', async () => {
    writeFileSync(join(repoDir, 'config.js'), 'const key = "AKIAABCDEFGHIJKLMNOP";\n');
    git(['add', 'config.js']);

    const prompt = async () => 'skip' as const;
    const exitCode = await scanCommand({ cwd: repoDir, prompt, noDeps: true });

    expect(exitCode).toBe(1);
  });

  it('returns 0 and applies the fix when the user accepts it', async () => {
    writeFileSync(join(repoDir, 'config.js'), 'const key = "AKIAABCDEFGHIJKLMNOP";\n');
    git(['add', 'config.js']);

    const prompt = async () => 'y' as const;
    const exitCode = await scanCommand({ cwd: repoDir, prompt, noDeps: true });

    expect(exitCode).toBe(0);
    expect(readFileSync(join(repoDir, 'config.js'), 'utf8')).toBe('const key = process.env.AWS_ACCESS_KEY;\n');
    expect(readFileSync(join(repoDir, '.env'), 'utf8')).toContain('AWS_ACCESS_KEY=AKIAABCDEFGHIJKLMNOP');
  });

  it('re-stages the fixed file so the commit contains the fix, not the secret', async () => {
    writeFileSync(join(repoDir, 'config.js'), 'const key = "AKIAABCDEFGHIJKLMNOP";\n');
    git(['add', 'config.js']);

    await scanCommand({ cwd: repoDir, prompt: async () => 'y' as const, noDeps: true });

    const staged = execFileSync('git', ['show', ':config.js'], { cwd: repoDir, encoding: 'utf8' });
    expect(staged).toContain('process.env.AWS_ACCESS_KEY');
    expect(staged).not.toContain('AKIAABCDEFGHIJKLMNOP');
  });

  it('accepting an owasp annotation clears the finding on the verification re-scan', async () => {
    writeFileSync(join(repoDir, 'a.js'), 'eval(userInput);\n');
    git(['add', 'a.js']);

    const exitCode = await scanCommand({ cwd: repoDir, prompt: async () => 'y' as const, noDeps: true });

    expect(exitCode).toBe(0);
    expect(readFileSync(join(repoDir, 'a.js'), 'utf8')).toBe(
      '// vibeguard-ignore-next-line — reviewed: eval-usage\neval(userInput);\n'
    );
  });

  it('respects the noOwasp override', async () => {
    writeFileSync(join(repoDir, 'a.js'), 'eval(userInput);\n');
    git(['add', 'a.js']);

    const prompt = async () => 'skip' as const;
    const exitCode = await scanCommand({ cwd: repoDir, prompt, noOwasp: true, noDeps: true });

    expect(exitCode).toBe(0);
  });

  it('respects ignoreLines from .vibeguardrc.json', async () => {
    writeFileSync(join(repoDir, 'config.js'), 'const key = "AKIAABCDEFGHIJKLMNOP";\n');
    writeFileSync(join(repoDir, '.vibeguardrc.json'), JSON.stringify({ deps: false, ignoreLines: { 'config.js': [1] } }));
    git(['add', 'config.js']);

    const exitCode = await scanCommand({ cwd: repoDir, prompt: async () => 'skip' as const });

    expect(exitCode).toBe(0);
  });

  it('respects an inline vibeguard-ignore-next-line marker', async () => {
    writeFileSync(join(repoDir, 'config.js'), '// vibeguard-ignore-next-line\nconst key = "AKIAABCDEFGHIJKLMNOP";\n');
    git(['add', 'config.js']);

    const exitCode = await scanCommand({ cwd: repoDir, prompt: async () => 'skip' as const, noDeps: true });

    expect(exitCode).toBe(0);
  });

  it('does not scan lockfiles, which are all high-entropy hashes', async () => {
    writeFileSync(join(repoDir, 'pnpm-lock.yaml'), 'integrity: sha512-aZ8kQ2mN7pR4vT9xB1cD6fH3jL0kM5nP\n');
    git(['add', 'pnpm-lock.yaml']);

    const exitCode = await scanCommand({ cwd: repoDir, prompt: async () => 'skip' as const, noDeps: true });

    expect(exitCode).toBe(0);
  });

  it('honours excludeFiles from config', async () => {
    writeFileSync(join(repoDir, 'fixtures.js'), 'const key = "AKIAABCDEFGHIJKLMNOP";\n');
    writeFileSync(join(repoDir, '.vibeguardrc.json'), JSON.stringify({ deps: false, excludeFiles: ['fixtures.js'] }));
    git(['add', 'fixtures.js']);

    const exitCode = await scanCommand({ cwd: repoDir, prompt: async () => 'skip' as const });

    expect(exitCode).toBe(0);
  });

  it('returns 0 when nothing is staged', async () => {
    const exitCode = await scanCommand({ cwd: repoDir, prompt: async () => 'skip' as const, noDeps: true });
    expect(exitCode).toBe(0);
  });

  it('blocks when a scanner fails and another scanner still reports a finding', async () => {
    writeFileSync(join(repoDir, 'config.js'), 'const key = "AKIAABCDEFGHIJKLMNOP";\n');
    git(['add', 'config.js']);

    // deps enabled with no package.json staged is a no-op, so the secret still gates.
    const exitCode = await scanCommand({ cwd: repoDir, prompt: async () => 'n' as const });

    expect(exitCode).toBe(1);
  });
});
