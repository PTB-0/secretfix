import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { getStagedFilePaths, getStagedFiles, getStagedAddedLines, restageFile, unstageFile } from '../src/git.js';

let repoDir: string;

function git(args: string[]): void {
  execFileSync('git', args, { cwd: repoDir });
}

beforeEach(() => {
  repoDir = mkdtempSync(join(tmpdir(), 'vibeguard-git-'));
  git(['init']);
  git(['config', 'user.email', 'test@vibeguard.dev']);
  git(['config', 'user.name', 'VibeGuard Test']);
});

afterEach(() => {
  rmSync(repoDir, { recursive: true, force: true });
});

describe('git helpers', () => {
  it('lists staged file paths', () => {
    writeFileSync(join(repoDir, 'a.txt'), 'hello');
    git(['add', 'a.txt']);
    expect(getStagedFilePaths(repoDir)).toEqual(['a.txt']);
  });

  it('reads staged content, not working-tree content', () => {
    writeFileSync(join(repoDir, 'a.txt'), 'staged version');
    git(['add', 'a.txt']);
    writeFileSync(join(repoDir, 'a.txt'), 'unstaged edit');

    const [file] = getStagedFiles(repoDir);
    expect(file.path).toBe('a.txt');
    expect(file.content).toBe('staged version');
  });

  it('restages a file after it is edited on disk', () => {
    writeFileSync(join(repoDir, 'a.txt'), 'v1');
    git(['add', 'a.txt']);
    writeFileSync(join(repoDir, 'a.txt'), 'v2');

    restageFile('a.txt', repoDir);

    const [file] = getStagedFiles(repoDir);
    expect(file.content).toBe('v2');
  });

  it('unstages a file while leaving it on disk', () => {
    writeFileSync(join(repoDir, '.env'), 'SECRET=1\n');
    git(['add', '.env']);
    expect(getStagedFilePaths(repoDir)).toContain('.env');

    unstageFile('.env', repoDir);

    expect(getStagedFilePaths(repoDir)).not.toContain('.env');
    expect(readFileSync(join(repoDir, '.env'), 'utf8')).toBe('SECRET=1\n');
  });

  it('unstages a file that is already tracked in HEAD', () => {
    writeFileSync(join(repoDir, '.env'), 'SECRET=1\n');
    git(['add', '.env']);
    git(['-c', 'user.email=t@t.dev', '-c', 'user.name=T', 'commit', '-m', 'oops']);
    writeFileSync(join(repoDir, '.env'), 'SECRET=2\n');
    git(['add', '.env']);

    unstageFile('.env', repoDir);

    expect(getStagedFilePaths(repoDir)).not.toContain('.env');
    expect(readFileSync(join(repoDir, '.env'), 'utf8')).toBe('SECRET=2\n');
  });

  it('skips binary blobs but still returns text files staged alongside them', () => {
    writeFileSync(join(repoDir, 'logo.png'), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x01, 0x02, 0x03]));
    writeFileSync(join(repoDir, 'a.txt'), 'hello');
    git(['add', 'logo.png', 'a.txt']);

    const paths = getStagedFiles(repoDir).map((f) => f.path);
    expect(paths).toEqual(['a.txt']);
    expect(getStagedFilePaths(repoDir)).toContain('logo.png');
  });

  it('skips files larger than the scan size cap', () => {
    writeFileSync(join(repoDir, 'big.txt'), 'x'.repeat(1_000_001));
    writeFileSync(join(repoDir, 'a.txt'), 'hello');
    git(['add', 'big.txt', 'a.txt']);

    expect(getStagedFiles(repoDir).map((f) => f.path)).toEqual(['a.txt']);
  });

  it('reports only the lines added by the staged diff', () => {
    writeFileSync(join(repoDir, 'a.js'), 'one\ntwo\nthree\n');
    git(['add', 'a.js']);
    git(['-c', 'user.email=t@t.dev', '-c', 'user.name=T', 'commit', '-m', 'init']);

    writeFileSync(join(repoDir, 'a.js'), 'one\ntwo\nthree\nfour\n');
    git(['add', 'a.js']);

    const added = getStagedAddedLines(repoDir);
    expect([...(added.get('a.js') ?? [])]).toEqual([4]);
  });

  it('treats every line of a brand new file as added', () => {
    writeFileSync(join(repoDir, 'new.js'), 'a\nb\nc\n');
    git(['add', 'new.js']);

    expect([...(getStagedAddedLines(repoDir).get('new.js') ?? [])]).toEqual([1, 2, 3]);
  });

  it('reports no added lines for a pure deletion', () => {
    writeFileSync(join(repoDir, 'a.js'), 'one\ntwo\nthree\n');
    git(['add', 'a.js']);
    git(['-c', 'user.email=t@t.dev', '-c', 'user.name=T', 'commit', '-m', 'init']);

    writeFileSync(join(repoDir, 'a.js'), 'one\nthree\n');
    git(['add', 'a.js']);

    expect([...(getStagedAddedLines(repoDir).get('a.js') ?? [])]).toEqual([]);
  });

  it('tracks added lines across several hunks and files', () => {
    writeFileSync(join(repoDir, 'a.js'), 'l1\nl2\nl3\nl4\nl5\nl6\n');
    git(['add', 'a.js']);
    git(['-c', 'user.email=t@t.dev', '-c', 'user.name=T', 'commit', '-m', 'init']);

    writeFileSync(join(repoDir, 'a.js'), 'l1\nNEW\nl2\nl3\nl4\nl5\nl6\nTAIL\n');
    writeFileSync(join(repoDir, 'b.js'), 'only\n');
    git(['add', 'a.js', 'b.js']);

    const added = getStagedAddedLines(repoDir);
    expect([...(added.get('a.js') ?? [])]).toEqual([2, 8]);
    expect([...(added.get('b.js') ?? [])]).toEqual([1]);
  });

  it('handles added lines in a path containing spaces', () => {
    writeFileSync(join(repoDir, 'my file.js'), 'hello\n');
    git(['add', 'my file.js']);

    expect([...(getStagedAddedLines(repoDir).get('my file.js') ?? [])]).toEqual([1]);
  });

  it('reads a path containing spaces', () => {
    writeFileSync(join(repoDir, 'my file.txt'), 'spaced');
    git(['add', 'my file.txt']);

    const [file] = getStagedFiles(repoDir);
    expect(file.content).toBe('spaced');
  });
});
