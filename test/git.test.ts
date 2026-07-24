import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { getStagedFilePaths, getStagedFiles, restageFile } from '../src/git.js';

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

  it('reads a path containing spaces', () => {
    writeFileSync(join(repoDir, 'my file.txt'), 'spaced');
    git(['add', 'my file.txt']);

    const [file] = getStagedFiles(repoDir);
    expect(file.content).toBe('spaced');
  });
});
