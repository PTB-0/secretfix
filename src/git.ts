import { execFileSync } from 'node:child_process';
import type { StagedFile } from './types.js';

/** Files larger than this are skipped — scanning them is slow and never useful. */
const MAX_SCANNED_BYTES = 1_000_000;

function git(args: string[], cwd: string): string {
  return execFileSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
}

function gitBuffer(args: string[], cwd: string): Buffer {
  return execFileSync('git', args, { cwd, maxBuffer: 64 * 1024 * 1024 });
}

/** Git's own heuristic: a NUL byte near the start means binary. */
function isBinary(buffer: Buffer): boolean {
  return buffer.subarray(0, 8000).includes(0);
}

export function getStagedFilePaths(cwd: string): string[] {
  const output = git(['diff', '--cached', '--name-only', '--diff-filter=ACM'], cwd);
  return output
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

/**
 * Staged content for every text file in the index. Binary blobs and very large
 * files are skipped: they produce nothing but false positives (a PNG is one long
 * high-entropy "secret") and would slow the commit down.
 */
export function getStagedFiles(cwd: string): StagedFile[] {
  const files: StagedFile[] = [];

  for (const path of getStagedFilePaths(cwd)) {
    let buffer: Buffer;
    try {
      buffer = gitBuffer(['show', `:${path}`], cwd);
    } catch {
      continue; // deleted between listing and reading, or an unreadable blob
    }

    if (buffer.byteLength > MAX_SCANNED_BYTES || isBinary(buffer)) {
      continue;
    }

    files.push({ path, content: buffer.toString('utf8') });
  }

  return files;
}

export function restageFile(path: string, cwd: string): void {
  git(['add', '--', path], cwd);
}
