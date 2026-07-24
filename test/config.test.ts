import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadConfig, applyCliOverrides, isIgnored, isExcluded, hasIgnoreMarker, defaultConfig } from '../src/config.js';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'vibeguard-config-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('config', () => {
  it('returns defaults when no config file exists', () => {
    expect(loadConfig(dir)).toEqual(defaultConfig);
  });

  it('merges partial config over defaults', () => {
    writeFileSync(join(dir, '.vibeguardrc.json'), JSON.stringify({ owasp: false }));
    const config = loadConfig(dir);
    expect(config.owasp).toBe(false);
    expect(config.secrets).toBe(true);
  });

  it('applies CLI flag overrides on top of config', () => {
    const config = applyCliOverrides(defaultConfig, { noDeps: true });
    expect(config.deps).toBe(false);
    expect(config.secrets).toBe(true);
  });

  it('checks ignored lines', () => {
    const config = { ...defaultConfig, ignoreLines: { 'a.js': [3, 7] } };
    expect(isIgnored(config, 'a.js', 3)).toBe(true);
    expect(isIgnored(config, 'a.js', 4)).toBe(false);
  });

  it('falls back to defaults when the config file is malformed', () => {
    writeFileSync(join(dir, '.vibeguardrc.json'), '{ not valid json');
    expect(loadConfig(dir)).toEqual(defaultConfig);
  });

  it('ignores non-boolean values in the config file', () => {
    writeFileSync(join(dir, '.vibeguardrc.json'), JSON.stringify({ secrets: 'nope', ignoreLines: 'nope' }));
    const config = loadConfig(dir);
    expect(config.secrets).toBe(true);
    expect(config.ignoreLines).toEqual({});
  });
});

describe('isExcluded', () => {
  it('excludes vendored dependencies at any depth', () => {
    expect(isExcluded(defaultConfig, 'node_modules/left-pad/index.js')).toBe(true);
    expect(isExcluded(defaultConfig, 'packages/api/node_modules/left-pad/index.js')).toBe(true);
  });

  it('excludes lockfiles and minified bundles by default', () => {
    expect(isExcluded(defaultConfig, 'pnpm-lock.yaml')).toBe(true);
    expect(isExcluded(defaultConfig, 'apps/web/package-lock.json')).toBe(true);
    expect(isExcluded(defaultConfig, 'public/app.min.js')).toBe(true);
  });

  it('does not exclude ordinary source files', () => {
    expect(isExcluded(defaultConfig, 'src/index.ts')).toBe(false);
    expect(isExcluded(defaultConfig, 'src/node_modules_helper.ts')).toBe(false);
  });

  it('keeps the built-in excludes when the user adds their own', () => {
    writeFileSync(join(dir, '.vibeguardrc.json'), JSON.stringify({ excludeFiles: ['test/fixtures/'] }));
    const config = loadConfig(dir);

    expect(isExcluded(config, 'test/fixtures/keys.ts')).toBe(true);
    expect(isExcluded(config, 'pnpm-lock.yaml')).toBe(true);
  });
});

describe('hasIgnoreMarker', () => {
  it('suppresses a finding when the previous line carries the marker', () => {
    const content = ['// vibeguard-ignore-next-line', 'const key = "AKIAABCDEFGHIJKLMNOP";'].join('\n');
    expect(hasIgnoreMarker(content, 2)).toBe(true);
  });

  it('suppresses a finding when the marker is a trailing comment on the same line', () => {
    const content = 'const key = "AKIAABCDEFGHIJKLMNOP"; // vibeguard-ignore\n';
    expect(hasIgnoreMarker(content, 1)).toBe(true);
  });

  it('does not suppress an unmarked line', () => {
    const content = ['// just a comment', 'const key = "AKIAABCDEFGHIJKLMNOP";'].join('\n');
    expect(hasIgnoreMarker(content, 2)).toBe(false);
  });

  it('does not suppress a line two below the marker', () => {
    const content = ['// vibeguard-ignore-next-line', 'const a = 1;', 'const key = "AKIAABCDEFGHIJKLMNOP";'].join('\n');
    expect(hasIgnoreMarker(content, 3)).toBe(false);
  });

  it('handles out-of-range line numbers without throwing', () => {
    expect(hasIgnoreMarker('const a = 1;\n', 99)).toBe(false);
    expect(hasIgnoreMarker('const a = 1;\n', 0)).toBe(false);
  });
});
