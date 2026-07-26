import { readIndexFile } from '../../git.js';
import { detectFrameworks } from './detect.js';
import type { ScanContext } from './types.js';

/**
 * One context per scan run. Reads are memoised — several heuristic rules ask for
 * the same middleware.ts, and the scan must not shell out to git once per rule.
 * `undefined` results are cached too, so a missing file costs one lookup.
 */
export function createScanContext(cwd: string): ScanContext {
  const cache = new Map<string, string | undefined>();

  const readRepoFile = (path: string): string | undefined => {
    if (cache.has(path)) return cache.get(path);
    const content = readIndexFile(path, cwd);
    cache.set(path, content);
    return content;
  };

  return { cwd, frameworks: detectFrameworks(readRepoFile), readRepoFile };
}
