import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, existsSync, readFileSync, rmSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { initCommand } from '../../src/commands/init.js';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'vibeguard-init-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('initCommand', () => {
  it('installs husky when .husky does not exist yet', () => {
    const installHusky = vi.fn();
    initCommand(dir, { installHusky });
    expect(installHusky).toHaveBeenCalledWith(dir);
  });

  it('writes the pre-commit hook running vibeguard scan', () => {
    initCommand(dir, { installHusky: vi.fn() });
    const hook = readFileSync(join(dir, '.husky', 'pre-commit'), 'utf8');
    expect(hook).toContain('npx vibeguard scan');
  });

  it('writes a default .vibeguardrc.json if none exists', () => {
    initCommand(dir, { installHusky: vi.fn() });
    const config = JSON.parse(readFileSync(join(dir, '.vibeguardrc.json'), 'utf8'));
    expect(config.secrets).toBe(true);
  });

  it('does not overwrite an existing .vibeguardrc.json', () => {
    mkdirSync(join(dir, '.husky'), { recursive: true });
    writeFileSync(join(dir, '.vibeguardrc.json'), JSON.stringify({ secrets: false }));

    initCommand(dir, { installHusky: vi.fn() });

    const config = JSON.parse(readFileSync(join(dir, '.vibeguardrc.json'), 'utf8'));
    expect(config.secrets).toBe(false);
  });

  it('does not call installHusky when .husky already exists', () => {
    mkdirSync(join(dir, '.husky'), { recursive: true });
    const installHusky = vi.fn();

    initCommand(dir, { installHusky });

    expect(installHusky).not.toHaveBeenCalled();
  });

  it('appends to an existing pre-commit hook instead of clobbering it', () => {
    mkdirSync(join(dir, '.husky'), { recursive: true });
    writeFileSync(join(dir, '.husky', 'pre-commit'), '#!/usr/bin/env sh\nnpx lint-staged\n');

    initCommand(dir, { installHusky: vi.fn() });

    const hook = readFileSync(join(dir, '.husky', 'pre-commit'), 'utf8');
    expect(hook).toContain('npx lint-staged');
    expect(hook).toContain('npx vibeguard scan');
  });

  it("replaces husky's npm test placeholder when init installed husky itself", () => {
    const installHusky = vi.fn((target: string) => {
      mkdirSync(join(target, '.husky'), { recursive: true });
      writeFileSync(join(target, '.husky', 'pre-commit'), 'npm test\n');
    });

    initCommand(dir, { installHusky });

    const hook = readFileSync(join(dir, '.husky', 'pre-commit'), 'utf8');
    expect(hook).toContain('npx vibeguard scan');
    expect(hook).not.toContain('npm test');
  });

  it('is idempotent — a second run does not add the invocation twice', () => {
    initCommand(dir, { installHusky: vi.fn() });
    initCommand(dir, { installHusky: vi.fn() });

    const hook = readFileSync(join(dir, '.husky', 'pre-commit'), 'utf8');
    expect(hook.match(/npx vibeguard scan/g)).toHaveLength(1);
  });

  it('falls back to .git/hooks/pre-commit when husky cannot be installed', () => {
    mkdirSync(join(dir, '.git'), { recursive: true });
    const installHusky = vi.fn(() => {
      throw new Error('npx unavailable');
    });

    initCommand(dir, { installHusky });

    expect(existsSync(join(dir, '.husky', 'pre-commit'))).toBe(false);
    expect(readFileSync(join(dir, '.git', 'hooks', 'pre-commit'), 'utf8')).toContain('npx vibeguard scan');
  });

  it('throws a clear error when there is no git repository and husky is unavailable', () => {
    const installHusky = vi.fn(() => {
      throw new Error('npx unavailable');
    });

    expect(() => initCommand(dir, { installHusky })).toThrow(/git repository/i);
  });

  it('reattaches a terminal in the hook so the fix prompts can be answered', () => {
    initCommand(dir, { installHusky: vi.fn() });
    expect(readFileSync(join(dir, '.husky', 'pre-commit'), 'utf8')).toContain('/dev/tty');
  });
});
