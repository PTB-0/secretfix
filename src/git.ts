import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { StagedFile } from './types.js';

/** Files larger than this are skipped — scanning them is slow and never useful. */
const MAX_SCANNED_BYTES = 1_000_000;

/**
 * stderr is piped rather than inherited because several callers (readIndexFile's
 * probe for a file that may not exist, unstageFile's HEAD-less fallback) run git
 * commands that are *expected* to fail. Inherited stderr would print git's own
 * "fatal: ..." on essentially every commit, which reads as tool breakage to
 * something that lives in a hook and must stay silent until there is a real
 * finding to report. Piping still lands the message on the thrown error's
 * `.stderr`, so a caller that wants to log a real failure still can.
 */
function git(args: string[], cwd: string): string {
  return execFileSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
}

function gitBuffer(args: string[], cwd: string): Buffer {
  return execFileSync('git', args, { cwd, maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
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

/**
 * The 1-based line numbers each staged file actually *adds*, parsed from a
 * zero-context diff. Scanning whole files instead means any pre-existing problem
 * in a file you merely touched blocks the commit — which gets the tool uninstalled.
 */
export function getStagedAddedLines(cwd: string): Map<string, Set<number>> {
  // core.quotePath=false keeps non-ASCII paths from arriving octal-escaped.
  const output = git(['-c', 'core.quotePath=false', 'diff', '--cached', '-U0', '--diff-filter=ACM'], cwd);
  const added = new Map<string, Set<number>>();
  let current: Set<number> | undefined;

  for (const line of output.split('\n')) {
    if (line.startsWith('+++ ')) {
      const target = line.slice(4).trimEnd();
      if (target === '/dev/null') {
        current = undefined;
        continue;
      }
      current = new Set<number>();
      added.set(target.startsWith('b/') ? target.slice(2) : target, current);
      continue;
    }

    if (current && line.startsWith('@@')) {
      const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/.exec(line);
      if (!hunk) continue;
      const start = Number(hunk[1]);
      const count = hunk[2] === undefined ? 1 : Number(hunk[2]);
      for (let offset = 0; offset < count; offset += 1) {
        current.add(start + offset);
      }
    }
  }

  return added;
}

export function restageFile(path: string, cwd: string): void {
  git(['add', '--', path], cwd);
}

/** Removes a path from the index, leaving the working-tree copy untouched. */
export function unstageFile(path: string, cwd: string): void {
  try {
    // Fails when the path is not in HEAD (a newly added file), which needs --cached rm.
    git(['restore', '--staged', '--', path], cwd);
  } catch {
    git(['rm', '--cached', '--force', '--quiet', '--', path], cwd);
  }
}

/**
 * Reads a repo file as it will be committed: the index first, then the working
 * tree for a file git does not track. The index is the correct source for a
 * verification read — the question is whether the *committed* code has an auth
 * check, not whether an unstaged edit does.
 */
export function readIndexFile(path: string, cwd: string): string | undefined {
  try {
    const buffer = gitBuffer(['show', `:${path}`], cwd);
    if (buffer.byteLength > MAX_SCANNED_BYTES || isBinary(buffer)) return undefined;
    return buffer.toString('utf8');
  } catch {
    // Not in the index; fall through to the working tree.
  }

  const full = join(cwd, path);
  try {
    return existsSync(full) ? readFileSync(full, 'utf8') : undefined;
  } catch {
    return undefined;
  }
}
