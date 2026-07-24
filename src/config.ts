import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

export interface VibeGuardConfig {
  secrets: boolean;
  owasp: boolean;
  deps: boolean;
  ignoreLines: Record<string, number[]>;
}

const DEFAULT_CONFIG: VibeGuardConfig = {
  secrets: true,
  owasp: true,
  deps: true,
  ignoreLines: {}
};

/**
 * Inline suppression marker (see spec "Config"). Either form works:
 *   // vibeguard-ignore-next-line   -> suppresses findings on the following line
 *   const x = "..."; // vibeguard-ignore  -> suppresses findings on this line
 */
const IGNORE_MARKER = 'vibeguard-ignore';
const IGNORE_NEXT_LINE_MARKER = 'vibeguard-ignore-next-line';

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

export function loadConfig(cwd: string): VibeGuardConfig {
  const configPath = join(cwd, '.vibeguardrc.json');
  if (!existsSync(configPath)) {
    return { ...DEFAULT_CONFIG };
  }

  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(configPath, 'utf8'));
  } catch {
    console.warn('vibeguard: .vibeguardrc.json is not valid JSON — using default settings.');
    return { ...DEFAULT_CONFIG };
  }

  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return { ...DEFAULT_CONFIG };
  }

  const parsed = raw as Record<string, unknown>;
  return {
    secrets: readBoolean(parsed.secrets, DEFAULT_CONFIG.secrets),
    owasp: readBoolean(parsed.owasp, DEFAULT_CONFIG.owasp),
    deps: readBoolean(parsed.deps, DEFAULT_CONFIG.deps),
    ignoreLines: readIgnoreLines(parsed.ignoreLines)
  };
}

export interface CliOverrides {
  noSecrets?: boolean;
  noOwasp?: boolean;
  noDeps?: boolean;
}

export function applyCliOverrides(config: VibeGuardConfig, overrides: CliOverrides): VibeGuardConfig {
  return {
    ...config,
    secrets: overrides.noSecrets ? false : config.secrets,
    owasp: overrides.noOwasp ? false : config.owasp,
    deps: overrides.noDeps ? false : config.deps
  };
}

export function isIgnored(config: VibeGuardConfig, file: string, line: number): boolean {
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

export const defaultConfig: VibeGuardConfig = DEFAULT_CONFIG;
