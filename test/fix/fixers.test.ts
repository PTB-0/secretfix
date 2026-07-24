import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { applyFix } from '../../src/fix/fixers.js';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'commitguard-fix-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('applyFix', () => {
  it('moves a secret to .env, updates .gitignore, and rewrites the source line', () => {
    writeFileSync(join(dir, 'config.js'), 'const key = "AKIAABCDEFGHIJKLMNOP";\n');

    applyFix(
      { kind: 'move-to-env', file: 'config.js', line: 1, envVarName: 'AWS_KEY', secretValue: 'AKIAABCDEFGHIJKLMNOP' },
      dir
    );

    expect(readFileSync(join(dir, '.env'), 'utf8')).toContain('AWS_KEY=AKIAABCDEFGHIJKLMNOP');
    expect(readFileSync(join(dir, '.gitignore'), 'utf8')).toContain('.env');
    expect(readFileSync(join(dir, 'config.js'), 'utf8')).toContain('process.env.AWS_KEY');
  });

  it('replaces the quoted literal so the result is valid code, not a string', () => {
    writeFileSync(join(dir, 'config.js'), 'const key = "AKIAABCDEFGHIJKLMNOP";\n');

    applyFix(
      { kind: 'move-to-env', file: 'config.js', line: 1, envVarName: 'AWS_KEY', secretValue: 'AKIAABCDEFGHIJKLMNOP' },
      dir
    );

    expect(readFileSync(join(dir, 'config.js'), 'utf8')).toBe('const key = process.env.AWS_KEY;\n');
  });

  it('handles single-quoted secrets', () => {
    writeFileSync(join(dir, 'config.js'), "const key = 'AKIAABCDEFGHIJKLMNOP';\n");

    applyFix(
      { kind: 'move-to-env', file: 'config.js', line: 1, envVarName: 'AWS_KEY', secretValue: 'AKIAABCDEFGHIJKLMNOP' },
      dir
    );

    expect(readFileSync(join(dir, 'config.js'), 'utf8')).toBe('const key = process.env.AWS_KEY;\n');
  });

  it('does not add .env to .gitignore twice', () => {
    writeFileSync(join(dir, 'config.js'), 'const key = "AKIAABCDEFGHIJKLMNOP";\n');
    writeFileSync(join(dir, '.gitignore'), 'node_modules/\n.env\n');

    applyFix(
      { kind: 'move-to-env', file: 'config.js', line: 1, envVarName: 'AWS_KEY', secretValue: 'AKIAABCDEFGHIJKLMNOP' },
      dir
    );

    const gitignore = readFileSync(join(dir, '.gitignore'), 'utf8');
    expect(gitignore.split('\n').filter((l) => l === '.env')).toHaveLength(1);
  });

  it('appends .env on its own line when .gitignore lacks a trailing newline', () => {
    writeFileSync(join(dir, 'config.js'), 'const key = "AKIAABCDEFGHIJKLMNOP";\n');
    writeFileSync(join(dir, '.gitignore'), 'node_modules/');

    applyFix(
      { kind: 'move-to-env', file: 'config.js', line: 1, envVarName: 'AWS_KEY', secretValue: 'AKIAABCDEFGHIJKLMNOP' },
      dir
    );

    expect(readFileSync(join(dir, '.gitignore'), 'utf8')).toBe('node_modules/\n.env\n');
  });

  it('gives a second secret a unique env var name instead of clobbering the first', () => {
    writeFileSync(join(dir, 'a.js'), 'const one = "AAAAAAAAAAAAAAAAAAAA";\nconst two = "BBBBBBBBBBBBBBBBBBBB";\n');

    applyFix(
      { kind: 'move-to-env', file: 'a.js', line: 1, envVarName: 'SUSPECTED_SECRET', secretValue: 'AAAAAAAAAAAAAAAAAAAA' },
      dir
    );
    applyFix(
      { kind: 'move-to-env', file: 'a.js', line: 2, envVarName: 'SUSPECTED_SECRET', secretValue: 'BBBBBBBBBBBBBBBBBBBB' },
      dir
    );

    const env = readFileSync(join(dir, '.env'), 'utf8');
    expect(env).toContain('SUSPECTED_SECRET=AAAAAAAAAAAAAAAAAAAA');
    expect(env).toContain('SUSPECTED_SECRET_2=BBBBBBBBBBBBBBBBBBBB');
    expect(readFileSync(join(dir, 'a.js'), 'utf8')).toContain('process.env.SUSPECTED_SECRET_2');
  });

  it('throws a clear error when the secret is no longer on the target line', () => {
    writeFileSync(join(dir, 'config.js'), 'const key = process.env.AWS_KEY;\n');

    expect(() =>
      applyFix(
        { kind: 'move-to-env', file: 'config.js', line: 1, envVarName: 'AWS_KEY', secretValue: 'AKIAABCDEFGHIJKLMNOP' },
        dir
      )
    ).toThrow(/no longer present/i);
  });

  it('bumps a dependency version in package.json', () => {
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ dependencies: { leftpad: '^1.0.0' } }));

    applyFix({ kind: 'bump-dependency', packageJsonPath: 'package.json', packageName: 'leftpad', targetVersion: '1.0.1' }, dir);

    const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
    expect(pkg.dependencies.leftpad).toBe('^1.0.1');
  });

  it('bumps a devDependency too', () => {
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ devDependencies: { leftpad: '~1.0.0' } }));

    applyFix({ kind: 'bump-dependency', packageJsonPath: 'package.json', packageName: 'leftpad', targetVersion: '1.0.1' }, dir);

    const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
    expect(pkg.devDependencies.leftpad).toBe('^1.0.1');
  });

  it('throws when the dependency to bump is not in package.json', () => {
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ dependencies: {} }));

    expect(() =>
      applyFix({ kind: 'bump-dependency', packageJsonPath: 'package.json', packageName: 'ghost', targetVersion: '1.0.1' }, dir)
    ).toThrow(/ghost/);
  });

  it('replaces a flagged line with a reviewed comment', () => {
    writeFileSync(join(dir, 'a.js'), 'eval(userInput);\n');

    applyFix({ kind: 'replace-line', file: 'a.js', line: 1, replacement: '// reviewed' }, dir);

    expect(readFileSync(join(dir, 'a.js'), 'utf8')).toContain('// reviewed');
  });

  it('throws when the target line is out of range', () => {
    writeFileSync(join(dir, 'a.js'), 'eval(userInput);\n');

    expect(() => applyFix({ kind: 'replace-line', file: 'a.js', line: 99, replacement: '// reviewed' }, dir)).toThrow(
      /line 99/
    );
  });
});
