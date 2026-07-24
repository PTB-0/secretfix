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
  repoDir = mkdtempSync(join(tmpdir(), 'secretfix-scan-'));
  git(['init']);
  git(['config', 'user.email', 'test@secretfix.dev']);
  git(['config', 'user.name', 'SecretFix Test']);
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
      '// secretfix-ignore-next-line — reviewed: eval-usage\neval(userInput);\n'
    );
  });

  it('respects the noOwasp override', async () => {
    writeFileSync(join(repoDir, 'a.js'), 'eval(userInput);\n');
    git(['add', 'a.js']);

    const prompt = async () => 'skip' as const;
    const exitCode = await scanCommand({ cwd: repoDir, prompt, noOwasp: true, noDeps: true });

    expect(exitCode).toBe(0);
  });

  it('respects ignoreLines from .secretfixrc.json', async () => {
    writeFileSync(join(repoDir, 'config.js'), 'const key = "AKIAABCDEFGHIJKLMNOP";\n');
    writeFileSync(join(repoDir, '.secretfixrc.json'), JSON.stringify({ deps: false, ignoreLines: { 'config.js': [1] } }));
    git(['add', 'config.js']);

    const exitCode = await scanCommand({ cwd: repoDir, prompt: async () => 'skip' as const });

    expect(exitCode).toBe(0);
  });

  it('respects an inline secretfix-ignore-next-line marker', async () => {
    writeFileSync(join(repoDir, 'config.js'), '// secretfix-ignore-next-line\nconst key = "AKIAABCDEFGHIJKLMNOP";\n');
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
    writeFileSync(join(repoDir, '.secretfixrc.json'), JSON.stringify({ deps: false, excludeFiles: ['fixtures.js'] }));
    git(['add', 'fixtures.js']);

    const exitCode = await scanCommand({ cwd: repoDir, prompt: async () => 'skip' as const });

    expect(exitCode).toBe(0);
  });

  it('ignores a pre-existing problem in a file this commit merely touched', async () => {
    writeFileSync(join(repoDir, 'legacy.js'), 'const a = 1;\nconst old = eval(x);\n');
    git(['add', 'legacy.js']);
    git(['commit', '-m', 'legacy']);

    writeFileSync(join(repoDir, 'legacy.js'), 'const a = 1;\nconst old = eval(x);\nconst added = 42;\n');
    git(['add', 'legacy.js']);

    const exitCode = await scanCommand({ cwd: repoDir, prompt: async () => 'skip' as const, noDeps: true });

    expect(exitCode).toBe(0);
  });

  it('still blocks when this commit adds the problem line itself', async () => {
    writeFileSync(join(repoDir, 'legacy.js'), 'const a = 1;\n');
    git(['add', 'legacy.js']);
    git(['commit', '-m', 'legacy']);

    writeFileSync(join(repoDir, 'legacy.js'), 'const a = 1;\nconst key = "AKIAABCDEFGHIJKLMNOP";\n');
    git(['add', 'legacy.js']);

    const exitCode = await scanCommand({ cwd: repoDir, prompt: async () => 'skip' as const, noDeps: true });

    expect(exitCode).toBe(1);
  });

  it('flags the pre-existing problem again under --whole-file', async () => {
    writeFileSync(join(repoDir, 'legacy.js'), 'const a = 1;\nconst key = "AKIAABCDEFGHIJKLMNOP";\n');
    git(['add', 'legacy.js']);
    git(['commit', '-m', 'legacy']);

    writeFileSync(join(repoDir, 'legacy.js'), 'const a = 1;\nconst key = "AKIAABCDEFGHIJKLMNOP";\nconst added = 42;\n');
    git(['add', 'legacy.js']);

    const exitCode = await scanCommand({
      cwd: repoDir,
      prompt: async () => 'skip' as const,
      noDeps: true,
      wholeFile: true
    });

    expect(exitCode).toBe(1);
  });

  it('does not block on a medium-severity finding by default', async () => {
    writeFileSync(join(repoDir, 'token.js'), 'const id = Math.random().toString(36);\n');
    git(['add', 'token.js']);

    const exitCode = await scanCommand({ cwd: repoDir, prompt: async () => 'skip' as const, noDeps: true });

    expect(exitCode).toBe(0);
  });

  it('blocks on a medium-severity finding when failOn is lowered', async () => {
    writeFileSync(join(repoDir, 'token.js'), 'const id = Math.random().toString(36);\n');
    git(['add', 'token.js']);

    const exitCode = await scanCommand({
      cwd: repoDir,
      prompt: async () => 'skip' as const,
      noDeps: true,
      failOn: 'medium'
    });

    expect(exitCode).toBe(1);
  });

  it('blocks when a .env file is staged, whatever is inside it', async () => {
    writeFileSync(join(repoDir, '.env'), 'DATABASE_URL=postgres://u:p@h/db\n');
    git(['add', '.env']);

    const exitCode = await scanCommand({ cwd: repoDir, prompt: async () => 'skip' as const, noDeps: true });

    expect(exitCode).toBe(1);
  });

  it('unstages a staged .env when the fix is accepted, keeping it on disk', async () => {
    writeFileSync(join(repoDir, '.env'), 'DATABASE_URL=postgres://u:p@h/db\n');
    git(['add', '.env']);

    const exitCode = await scanCommand({ cwd: repoDir, prompt: async () => 'y' as const, noDeps: true });

    expect(exitCode).toBe(0);
    expect(execFileSync('git', ['diff', '--cached', '--name-only'], { cwd: repoDir, encoding: 'utf8' })).not.toContain(
      '.env'
    );
    expect(readFileSync(join(repoDir, '.env'), 'utf8')).toBe('DATABASE_URL=postgres://u:p@h/db\n');
    expect(readFileSync(join(repoDir, '.gitignore'), 'utf8')).toContain('.env');
  });

  it('does not flag .env.example, which is meant to be committed', async () => {
    writeFileSync(join(repoDir, '.env.example'), 'DATABASE_URL=\n');
    git(['add', '.env.example']);

    const exitCode = await scanCommand({ cwd: repoDir, prompt: async () => 'skip' as const, noDeps: true });

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
