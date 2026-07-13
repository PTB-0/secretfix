import { execFileSync } from 'node:child_process';
import type { StagedFile } from './types.js';

function git(args: string[], cwd: string): string {
  return execFileSync('git', args, { cwd, encoding: 'utf8' });
}

export function getStagedFilePaths(cwd: string): string[] {
  const output = git(['diff', '--cached', '--name-only', '--diff-filter=ACM'], cwd);
  return output
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

export function getStagedFiles(cwd: string): StagedFile[] {
  return getStagedFilePaths(cwd).map((path) => ({
    path,
    content: git(['show', `:${path}`], cwd)
  }));
}

export function restageFile(path: string, cwd: string): void {
  git(['add', path], cwd);
}
