import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, mkdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildHookScript } from '../../src/commands/init.js';
import { scanCommand } from '../../src/commands/scan.js';

const binPath = join(process.cwd(), 'bin', 'secretfix.js');

let repoDir: string;

function git(args: string[]): void {
  execFileSync('git', args, { cwd: repoDir });
}

/** Runs the built CLI as a subprocess and reports its exit code and output. */
function runCli(args: string[], input = ''): { status: number; output: string } {
  try {
    const output = execFileSync('node', [binPath, ...args], { cwd: repoDir, input, encoding: 'utf8' });
    return { status: 0, output };
  } catch (err) {
    const execErr = err as { status: number | null; stdout?: string; stderr?: string };
    return { status: execErr.status ?? 1, output: `${execErr.stdout ?? ''}${execErr.stderr ?? ''}` };
  }
}

/**
 * Installs the real hook script that `secretfix init` generates, with only the
 * invocation swapped for this working copy's CLI. Hand-writing a simpler hook
 * here would leave the generated shell logic — the /dev/tty probe in particular
 * — completely untested.
 */
function installLocalHook(): void {
  mkdirSync(join(repoDir, '.git', 'hooks'), { recursive: true });
  const invocation = `node "${binPath.replace(/\\/g, '/')}" scan --no-deps`;
  writeFileSync(join(repoDir, '.git', 'hooks', 'pre-commit'), `#!/usr/bin/env sh\n${buildHookScript(invocation)}`);
}

beforeEach(() => {
  repoDir = mkdtempSync(join(tmpdir(), 'secretfix-e2e-'));
  git(['init']);
  git(['config', 'user.email', 'test@secretfix.dev']);
  git(['config', 'user.name', 'SecretFix Test']);
});

afterEach(() => {
  rmSync(repoDir, { recursive: true, force: true });
});

describe('secretfix scan (e2e)', () => {
  it('blocks the commit when a secret is left unresolved', () => {
    writeFileSync(join(repoDir, 'config.js'), 'const key = "AKIAABCDEFGHIJKLMNOP";\n');
    git(['add', 'config.js']);

    const { status } = runCli(['scan', '--no-deps'], 'skip\n');

    expect(status).toBe(1);
  });

  it('allows the commit and rewrites the file when the fix is accepted', () => {
    writeFileSync(join(repoDir, 'config.js'), 'const key = "AKIAABCDEFGHIJKLMNOP";\n');
    git(['add', 'config.js']);

    const { status } = runCli(['scan', '--no-deps'], 'y\n');

    expect(status).toBe(0);
    expect(readFileSync(join(repoDir, 'config.js'), 'utf8')).toBe('const key = process.env.AWS_ACCESS_KEY;\n');
    expect(readFileSync(join(repoDir, '.env'), 'utf8')).toContain('AWS_ACCESS_KEY=AKIAABCDEFGHIJKLMNOP');
    expect(readFileSync(join(repoDir, '.gitignore'), 'utf8')).toContain('.env');
  });

  it('blocks the commit when there is no stdin to answer the prompts', () => {
    writeFileSync(join(repoDir, 'config.js'), 'const key = "AKIAABCDEFGHIJKLMNOP";\n');
    git(['add', 'config.js']);

    // A hook launched by a GUI client or CI has no readable stdin. Reporting the
    // secret and then exiting 0 would be the worst possible outcome.
    const { status } = runCli(['scan', '--no-deps'], '');

    expect(status).toBe(1);
    expect(readFileSync(join(repoDir, 'config.js'), 'utf8')).toContain('AKIAABCDEFGHIJKLMNOP');
  });

  it('exits 0 on a clean staged change', () => {
    writeFileSync(join(repoDir, 'clean.js'), 'const total = price * quantity;\n');
    git(['add', 'clean.js']);

    expect(runCli(['scan', '--no-deps']).status).toBe(0);
  });

  it('prints its version', () => {
    const { status, output } = runCli(['--version']);
    expect(status).toBe(0);
    expect(output.trim()).toMatch(/^\d+\.\d+\.\d+$/);
  });
});

describe('secretfix init (e2e)', () => {
  it('installs a working hook and a default config', () => {
    const { status } = runCli(['init']);

    expect(status).toBe(0);
    const hookPath = existsSync(join(repoDir, '.husky', 'pre-commit'))
      ? join(repoDir, '.husky', 'pre-commit')
      : join(repoDir, '.git', 'hooks', 'pre-commit');
    expect(readFileSync(hookPath, 'utf8')).toContain('npx secretfix scan');
    expect(JSON.parse(readFileSync(join(repoDir, '.secretfixrc.json'), 'utf8')).secrets).toBe(true);
  });
});

describe('git commit through the hook (e2e)', () => {
  it('refuses the commit when staged code contains a secret', () => {
    installLocalHook();
    writeFileSync(join(repoDir, 'config.js'), 'const key = "AKIAABCDEFGHIJKLMNOP";\n');
    git(['add', 'config.js']);

    let failed = false;
    try {
      execFileSync('git', ['commit', '-m', 'add config'], { cwd: repoDir, encoding: 'utf8', stdio: 'pipe' });
    } catch {
      failed = true;
    }

    expect(failed).toBe(true);
    // `git log` errors on a repo with no commits, so count instead.
    expect(execFileSync('git', ['rev-list', '--count', '--all'], { cwd: repoDir, encoding: 'utf8' }).trim()).toBe('0');
  });

  it('lets a clean commit through', () => {
    installLocalHook();
    writeFileSync(join(repoDir, 'clean.js'), 'const total = price * quantity;\n');
    git(['add', 'clean.js']);

    execFileSync('git', ['commit', '-m', 'add clean file'], { cwd: repoDir, encoding: 'utf8', stdio: 'pipe' });

    expect(execFileSync('git', ['log', '--oneline'], { cwd: repoDir, encoding: 'utf8' })).toContain('add clean file');
  });
});

describe('web scanner (e2e)', () => {
  it('blocks a commit that stages mass assignment, and offers no fix for it', async () => {
    writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ dependencies: { next: '16.0.0' } }));
    git(['add', 'package.json']);
    mkdirSync(join(repoDir, 'app', 'api', 'user'), { recursive: true });
    writeFileSync(
      join(repoDir, 'app', 'api', 'user', 'route.ts'),
      [
        'export async function PATCH(req) {',
        '  const session = await auth();',
        '  const body = await req.json();',
        '  return prisma.user.update({ where: { id: session.userId }, data: body });',
        '}',
        ''
      ].join('\n')
    );
    git(['add', 'app/api/user/route.ts']);

    const answers: string[] = [];
    const code = await scanCommand({
      cwd: repoDir,
      noDeps: true,
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
    writeFileSync(
      join(repoDir, 'server.js'),
      ['const app = express();', "app.use(helmet());", "app.get('/', (req, res) => {", "  res.cookie('session', 't');", '  res.end();', '});', ''].join(
        '\n'
      )
    );
    git(['add', 'server.js']);

    const code = await scanCommand({ cwd: repoDir, noDeps: true, prompt: async () => 'y' });

    expect(code).toBe(0);
    const updated = readFileSync(join(repoDir, 'server.js'), 'utf8');
    expect(updated).toContain('httpOnly: true');
    // The fix must be in the index, not just the working tree.
    expect(execFileSync('git', ['diff', '--cached', '--', 'server.js'], { cwd: repoDir, encoding: 'utf8' })).toContain(
      'httpOnly: true'
    );
  });

  it('reports nothing for a route handler that middleware already protects', async () => {
    writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ dependencies: { next: '16.0.0' } }));
    writeFileSync(join(repoDir, 'middleware.ts'), "export const config = { matcher: ['/api/admin/:path*'] };\n");
    git(['add', 'package.json', 'middleware.ts']);
    mkdirSync(join(repoDir, 'app', 'api', 'admin', 'users'), { recursive: true });
    writeFileSync(
      join(repoDir, 'app', 'api', 'admin', 'users', 'route.ts'),
      'export async function POST(req) {\n  return save(await req.json());\n}\n'
    );
    git(['add', 'app/api/admin/users/route.ts']);

    expect(await scanCommand({ cwd: repoDir, noDeps: true, prompt: async () => 'skip' })).toBe(0);
  });

  it('skips Next.js rules entirely in a project that is not Next.js', async () => {
    writeFileSync(join(repoDir, 'package.json'), JSON.stringify({ dependencies: { express: '4.0.0' } }));
    git(['add', 'package.json']);
    writeFileSync(join(repoDir, '.env'), 'NEXT_PUBLIC_API_KEY=abc\n');
    git(['add', '.env']);

    // noSecrets: the secrets scanner blocks any staged .env file by its mere
    // presence, whatever it contains — unrelated to what this test checks,
    // which is that the *web* scanner's Next.js-only rules don't fire here.
    expect(await scanCommand({ cwd: repoDir, noDeps: true, noSecrets: true, prompt: async () => 'skip' })).toBe(0);
  });
});
