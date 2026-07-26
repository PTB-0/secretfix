import type { Framework } from './types.js';

/**
 * Anchored patterns, so `express-rate-limit` does not register as Express and
 * `next-auth` does not register as Next.js.
 */
const DEPENDENCY_FRAMEWORKS: ReadonlyArray<readonly [RegExp, Framework]> = [
  [/^next$/, 'nextjs'],
  [/^express$/, 'express'],
  [/^@supabase\//, 'supabase'],
  [/^firebase(?:-admin)?$/, 'firebase']
];

const NEXT_CONFIG_FILES = ['next.config.js', 'next.config.mjs', 'next.config.ts'] as const;

function dependencyNames(raw: string): string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return [];

  const pkg = parsed as { dependencies?: unknown; devDependencies?: unknown };
  const collect = (value: unknown): string[] =>
    typeof value === 'object' && value !== null && !Array.isArray(value) ? Object.keys(value) : [];

  return [...collect(pkg.dependencies), ...collect(pkg.devDependencies)];
}

/**
 * Detection never throws: a missing or malformed package.json degrades to the
 * agnostic rule set rather than failing the commit.
 */
export function detectFrameworks(readRepoFile: (path: string) => string | undefined): Set<Framework> {
  const frameworks = new Set<Framework>(['agnostic']);

  const manifest = readRepoFile('package.json');
  if (manifest !== undefined) {
    for (const name of dependencyNames(manifest)) {
      for (const [pattern, framework] of DEPENDENCY_FRAMEWORKS) {
        if (pattern.test(name)) frameworks.add(framework);
      }
    }
  }

  // A next.config.* is proof of Next.js even where package.json is unreadable.
  if (NEXT_CONFIG_FILES.some((path) => readRepoFile(path) !== undefined)) {
    frameworks.add('nextjs');
  }

  return frameworks;
}
