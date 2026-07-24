import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { Severity } from './types.js';

/** 'added-lines' judges only what this commit introduces; 'whole-file' judges everything. */
export type ScanMode = 'added-lines' | 'whole-file';

export interface SafeShipConfig {
  secrets: boolean;
  owasp: boolean;
  deps: boolean;
  ignoreLines: Record<string, number[]>;
  /** Paths never scanned. User entries are added to the built-in list, not replacing it. */
  excludeFiles: string[];
  scanMode: ScanMode;
  /** Lowest severity that blocks a commit. Anything below is reported as a warning. */
  failOn: Severity;
}

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

const SEVERITIES = Object.keys(SEVERITY_RANK) as Severity[];

/** True when `severity` is at least as serious as the configured threshold. */
export function blocksCommit(config: SafeShipConfig, severity: Severity): boolean {
  return SEVERITY_RANK[severity] <= SEVERITY_RANK[config.failOn];
}

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_RANK[a] - SEVERITY_RANK[b];
}

/**
 * Generated files whose contents are, by construction, indistinguishable from
 * secrets (lockfile integrity hashes, minified bundles). Scanning them means a
 * false positive on essentially every commit that touches them.
 */
const DEFAULT_EXCLUDES: string[] = [
  'node_modules/',
  'vendor/',
  'package-lock.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'bun.lockb',
  'Cargo.lock',
  'Gemfile.lock',
  'composer.lock',
  'poetry.lock',
  'go.sum',
  '.min.js',
  '.min.css',
  '.map',
  '.snap'
];

const DEFAULT_CONFIG: SafeShipConfig = {
  secrets: true,
  owasp: true,
  deps: true,
  ignoreLines: {},
  excludeFiles: DEFAULT_EXCLUDES,
  scanMode: 'added-lines',
  // critical/high block; medium and low are reported but let the commit through.
  // Blocking on every medium (Math.random in an animation, a moderate advisory)
  // trains people to reach for --no-verify, which is worse than not gating at all.
  failOn: 'high'
};

/**
 * Inline suppression marker (see spec "Config"). Either form works:
 *   // safeship-ignore-next-line   -> suppresses findings on the following line
 *   const x = "..."; // safeship-ignore  -> suppresses findings on this line
 */
const IGNORE_MARKER = 'safeship-ignore';
const IGNORE_NEXT_LINE_MARKER = 'safeship-ignore-next-line';

function readBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

function readIgnoreLines(value: unknown): Record<string, number[]> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return {};
  }
  const result: Record<string, number[]> = {};
  for (const [file, lines] of Object.entries(value as Record<string, unknown>)) {
    if (Array.isArray(lines)) {
      result[file] = lines.filter((line): line is number => typeof line === 'number');
    }
  }
  return result;
}

export function loadConfig(cwd: string): SafeShipConfig {
  const configPath = join(cwd, '.safeshiprc.json');
  if (!existsSync(configPath)) {
    return { ...DEFAULT_CONFIG };
  }

  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(configPath, 'utf8'));
  } catch {
    console.warn('safeship: .safeshiprc.json is not valid JSON — using default settings.');
    return { ...DEFAULT_CONFIG };
  }

  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return { ...DEFAULT_CONFIG };
  }

  const parsed = raw as Record<string, unknown>;
  const userExcludes = Array.isArray(parsed.excludeFiles)
    ? parsed.excludeFiles.filter((entry): entry is string => typeof entry === 'string')
    : [];

  return {
    secrets: readBoolean(parsed.secrets, DEFAULT_CONFIG.secrets),
    owasp: readBoolean(parsed.owasp, DEFAULT_CONFIG.owasp),
    deps: readBoolean(parsed.deps, DEFAULT_CONFIG.deps),
    ignoreLines: readIgnoreLines(parsed.ignoreLines),
    excludeFiles: [...DEFAULT_EXCLUDES, ...userExcludes],
    scanMode: parsed.scanMode === 'whole-file' ? 'whole-file' : DEFAULT_CONFIG.scanMode,
    failOn: SEVERITIES.includes(parsed.failOn as Severity) ? (parsed.failOn as Severity) : DEFAULT_CONFIG.failOn
  };
}

/**
 * Matches a repo-relative path against an exclude entry: exact path, bare file
 * name, path suffix (`.min.js`) or directory prefix (`test/fixtures/`).
 */
export function isExcluded(config: SafeShipConfig, path: string): boolean {
  const name = path.split('/').pop() ?? path;
  return config.excludeFiles.some((entry) => {
    // A directory entry matches at any depth, so a monorepo's
    // packages/api/node_modules/ is skipped as well as the root one.
    if (entry.endsWith('/')) {
      return path.startsWith(entry) || path.includes(`/${entry}`);
    }
    return path === entry || name === entry || path.endsWith(entry);
  });
}

export interface CliOverrides {
  noSecrets?: boolean;
  noOwasp?: boolean;
  noDeps?: boolean;
  wholeFile?: boolean;
  failOn?: string;
}

export function applyCliOverrides(config: SafeShipConfig, overrides: CliOverrides): SafeShipConfig {
  return {
    ...config,
    secrets: overrides.noSecrets ? false : config.secrets,
    owasp: overrides.noOwasp ? false : config.owasp,
    deps: overrides.noDeps ? false : config.deps,
    scanMode: overrides.wholeFile ? 'whole-file' : config.scanMode,
    failOn: SEVERITIES.includes(overrides.failOn as Severity) ? (overrides.failOn as Severity) : config.failOn
  };
}

export function isIgnored(config: SafeShipConfig, file: string, line: number): boolean {
  return config.ignoreLines[file]?.includes(line) ?? false;
}

/**
 * True when the given 1-based line of `content` is suppressed by an inline marker,
 * either on the line itself or on the line directly above it.
 */
export function hasIgnoreMarker(content: string, line: number): boolean {
  if (line < 1) return false;
  const lines = content.split('\n');

  const own = lines[line - 1];
  if (own !== undefined && own.includes(IGNORE_MARKER) && !own.includes(IGNORE_NEXT_LINE_MARKER)) {
    return true;
  }

  const previous = lines[line - 2];
  return previous !== undefined && previous.includes(IGNORE_NEXT_LINE_MARKER);
}

export const defaultConfig: SafeShipConfig = DEFAULT_CONFIG;
