import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolveFindings } from '../../src/fix/interactive.js';
import { applyFix } from '../../src/fix/fixers.js';
import type { Finding } from '../../src/types.js';

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    scanner: 'secrets',
    severity: 'critical',
    file: 'a.js',
    line: 1,
    message: 'secret found',
    fix: { kind: 'move-to-env', file: 'a.js', line: 1, envVarName: 'X', secretValue: 'y' },
    ...overrides
  };
}

function owaspFinding(line: number, patternName: string, sourceLine: string): Finding {
  return {
    scanner: 'owasp',
    severity: 'high',
    file: 'a.js',
    line,
    message: `${patternName} at a.js:${line}`,
    fix: {
      kind: 'replace-line',
      file: 'a.js',
      line,
      replacement: `// commitguard: review this line manually — ${patternName}\n${sourceLine}`
    }
  };
}

describe('resolveFindings', () => {
  it('applies the fix and restages the file when the user answers y', async () => {
    const applyFixMock = vi.fn();
    const restageMock = vi.fn();
    const prompt = vi.fn().mockResolvedValue('y' as const);

    const result = await resolveFindings([finding()], '/repo', prompt, applyFixMock, restageMock);

    expect(applyFixMock).toHaveBeenCalledWith(finding().fix, '/repo');
    expect(restageMock).toHaveBeenCalledWith('a.js', '/repo');
    expect(result.resolved).toHaveLength(1);
    expect(result.unresolved).toHaveLength(0);
  });

  it('leaves the finding unresolved when the user answers n', async () => {
    const applyFixMock = vi.fn();
    const restageMock = vi.fn();
    const prompt = vi.fn().mockResolvedValue('n' as const);

    const result = await resolveFindings([finding()], '/repo', prompt, applyFixMock, restageMock);

    expect(applyFixMock).not.toHaveBeenCalled();
    expect(result.unresolved).toHaveLength(1);
  });

  it('leaves the finding unresolved when skipped', async () => {
    const prompt = vi.fn().mockResolvedValue('skip' as const);
    const result = await resolveFindings([finding()], '/repo', prompt, vi.fn(), vi.fn());
    expect(result.unresolved).toHaveLength(1);
  });

  it('marks findings with no fix available as unresolved without prompting', async () => {
    const prompt = vi.fn();
    const result = await resolveFindings([finding({ fix: undefined })], '/repo', prompt, vi.fn(), vi.fn());
    expect(prompt).not.toHaveBeenCalled();
    expect(result.unresolved).toHaveLength(1);
  });

  it('prompts in the order findings were reported', async () => {
    const seen: number[] = [];
    const prompt = vi.fn(async (f: Finding) => {
      seen.push(f.line);
      return 'n' as const;
    });

    await resolveFindings([finding({ line: 1 }), finding({ line: 5 }), finding({ line: 9 })], '/repo', prompt, vi.fn(), vi.fn());

    expect(seen).toEqual([1, 5, 9]);
  });

  it('restages each affected file only once', async () => {
    const restageMock = vi.fn();
    const prompt = vi.fn().mockResolvedValue('y' as const);

    await resolveFindings(
      [finding({ line: 1 }), finding({ line: 2, fix: { kind: 'move-to-env', file: 'a.js', line: 2, envVarName: 'X', secretValue: 'y' } })],
      '/repo',
      prompt,
      vi.fn(),
      restageMock
    );

    expect(restageMock).toHaveBeenCalledTimes(1);
  });

  it('leaves a finding unresolved when its fix throws', async () => {
    const applyFixMock = vi.fn(() => {
      throw new Error('file vanished');
    });
    const prompt = vi.fn().mockResolvedValue('y' as const);

    const result = await resolveFindings([finding()], '/repo', prompt, applyFixMock, vi.fn());

    expect(result.resolved).toHaveLength(0);
    expect(result.unresolved).toHaveLength(1);
  });
});

describe('resolveFindings applied against real files', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'commitguard-interactive-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('keeps line numbers valid when a multi-line fix is applied above another finding', async () => {
    writeFileSync(join(dir, 'a.js'), 'eval(one);\nconst safe = 1;\neval(two);\n');
    const prompt = vi.fn().mockResolvedValue('y' as const);

    const result = await resolveFindings(
      [owaspFinding(1, 'eval-usage', 'eval(one);'), owaspFinding(3, 'eval-usage', 'eval(two);')],
      dir,
      prompt,
      applyFix,
      () => {}
    );

    expect(result.unresolved).toHaveLength(0);
    expect(readFileSync(join(dir, 'a.js'), 'utf8')).toBe(
      [
        '// commitguard: review this line manually — eval-usage',
        'eval(one);',
        'const safe = 1;',
        '// commitguard: review this line manually — eval-usage',
        'eval(two);',
        ''
      ].join('\n')
    );
  });

  it('merges two findings on the same line into one annotated line', async () => {
    const source = 'const q = eval("SELECT * FROM t WHERE id = " + id);';
    writeFileSync(join(dir, 'a.js'), `${source}\n`);
    const prompt = vi.fn().mockResolvedValue('y' as const);

    const result = await resolveFindings(
      [owaspFinding(1, 'eval-usage', source), owaspFinding(1, 'sql-string-concat', source)],
      dir,
      prompt,
      applyFix,
      () => {}
    );

    expect(result.resolved).toHaveLength(2);
    expect(readFileSync(join(dir, 'a.js'), 'utf8')).toBe(
      [
        '// commitguard: review this line manually — eval-usage',
        '// commitguard: review this line manually — sql-string-concat',
        source,
        ''
      ].join('\n')
    );
  });

  it('applies two secrets on different lines of the same file correctly', async () => {
    writeFileSync(join(dir, 'a.js'), 'const one = "AKIAAAAAAAAAAAAAAAAA";\nconst two = "AKIABBBBBBBBBBBBBBBB";\n');
    const prompt = vi.fn().mockResolvedValue('y' as const);

    const result = await resolveFindings(
      [
        finding({ line: 1, fix: { kind: 'move-to-env', file: 'a.js', line: 1, envVarName: 'AWS_ACCESS_KEY', secretValue: 'AKIAAAAAAAAAAAAAAAAA' } }),
        finding({ line: 2, fix: { kind: 'move-to-env', file: 'a.js', line: 2, envVarName: 'AWS_ACCESS_KEY', secretValue: 'AKIABBBBBBBBBBBBBBBB' } })
      ],
      dir,
      prompt,
      applyFix,
      () => {}
    );

    expect(result.unresolved).toHaveLength(0);
    expect(readFileSync(join(dir, 'a.js'), 'utf8')).toBe(
      'const one = process.env.AWS_ACCESS_KEY;\nconst two = process.env.AWS_ACCESS_KEY_2;\n'
    );
  });
});
