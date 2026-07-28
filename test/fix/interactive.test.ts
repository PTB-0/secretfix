import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolveFindings } from '../../src/fix/interactive.js';
import { applyFix } from '../../src/fix/fixers.js';
import type { Finding, FixDescriptor } from '../../src/types.js';

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
      replacement: `// secretfix: review this line manually — ${patternName}\n${sourceLine}`
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

  it("keeps a rewrite's line when a suppression marker collides with it", async () => {
    const writes: FixDescriptor[] = [];
    const findings: Finding[] = [
      {
        scanner: 'web',
        severity: 'high',
        file: 'a.ts',
        line: 3,
        message: 'rewrite',
        fix: { kind: 'replace-line', file: 'a.ts', line: 3, replacement: 'FIXED', rewrite: true }
      },
      {
        scanner: 'owasp',
        severity: 'high',
        file: 'a.ts',
        line: 3,
        message: 'marker',
        fix: { kind: 'replace-line', file: 'a.ts', line: 3, replacement: '// marker\nORIGINAL' }
      }
    ];

    const result = await resolveFindings(
      findings,
      '/repo',
      async () => 'y',
      (fix) => {
        writes.push(fix);
        return [];
      },
      () => undefined
    );

    expect(writes).toHaveLength(1);
    expect(writes[0]).toMatchObject({ kind: 'replace-line', replacement: '// marker\nFIXED' });
    expect(result.unresolved).toHaveLength(0);
  });

  it('keeps the rewrite regardless of the order the fixes arrive in', async () => {
    const writes: FixDescriptor[] = [];
    const marker: Finding = {
      scanner: 'owasp',
      severity: 'high',
      file: 'a.ts',
      line: 3,
      message: 'marker',
      fix: { kind: 'replace-line', file: 'a.ts', line: 3, replacement: '// marker\nORIGINAL' }
    };
    const rewrite: Finding = {
      scanner: 'web',
      severity: 'high',
      file: 'a.ts',
      line: 3,
      message: 'rewrite',
      fix: { kind: 'replace-line', file: 'a.ts', line: 3, replacement: 'FIXED', rewrite: true }
    };

    await resolveFindings([marker, rewrite], '/repo', async () => 'y', (fix) => {
      writes.push(fix);
      return [];
    }, () => undefined);

    expect(writes[0]).toMatchObject({ replacement: '// marker\nFIXED' });
  });

  it('applies one of two colliding rewrites and leaves the other unresolved', async () => {
    const writes: FixDescriptor[] = [];
    const rewriteOf = (replacement: string, message: string): Finding => ({
      scanner: 'web',
      severity: 'high',
      file: 'a.ts',
      line: 3,
      message,
      fix: { kind: 'replace-line', file: 'a.ts', line: 3, replacement, rewrite: true }
    });

    const result = await resolveFindings(
      [rewriteOf('FIRST', 'one'), rewriteOf('SECOND', 'two')],
      '/repo',
      async () => 'y',
      (fix) => {
        writes.push(fix);
        return [];
      },
      () => undefined
    );

    expect(writes).toHaveLength(1);
    expect(writes[0]).toMatchObject({ replacement: 'FIRST' });
    expect(result.unresolved.map((finding) => finding.message)).toEqual(['two']);
  });

  // The group key in `coalesce` joins kind/file/line with NUL rather than a
  // printable separator specifically so no two distinct fixes can ever land in
  // the same group. No pair of (kind, file, line) triples can be constructed
  // that a space-joined key would conflate (kind never contains a space, and
  // line is always numeric), so this pins the property the separator protects
  // — different files never merge — rather than a collision the current inputs
  // cannot actually produce.
  it('keeps fixes on different files with the same kind as separate writes', async () => {
    const writes: FixDescriptor[] = [];
    const findings: Finding[] = [
      {
        scanner: 'web',
        severity: 'high',
        file: 'a.ts',
        line: 1,
        message: 'one',
        fix: { kind: 'replace-line', file: 'a.ts', line: 1, replacement: 'ONE' }
      },
      {
        scanner: 'web',
        severity: 'high',
        file: 'b.ts',
        line: 1,
        message: 'two',
        fix: { kind: 'replace-line', file: 'b.ts', line: 1, replacement: 'TWO' }
      }
    ];

    const result = await resolveFindings(
      findings,
      '/repo',
      async () => 'y',
      (fix) => {
        writes.push(fix);
        return [];
      },
      () => undefined
    );

    expect(writes).toHaveLength(2);
    expect(result.resolved).toHaveLength(2);
  });
});

describe('resolveFindings applied against real files', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'secretfix-interactive-'));
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
        '// secretfix: review this line manually — eval-usage',
        'eval(one);',
        'const safe = 1;',
        '// secretfix: review this line manually — eval-usage',
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
        '// secretfix: review this line manually — eval-usage',
        '// secretfix: review this line manually — sql-string-concat',
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

describe('resolveFindings rewrite preview', () => {
  let previewDir: string;

  beforeEach(() => {
    previewDir = mkdtempSync(join(tmpdir(), 'secretfix-interactive-preview-'));
  });

  afterEach(() => {
    rmSync(previewDir, { recursive: true, force: true });
  });

  it('shows a before/after diff before asking about a rewrite', async () => {
    const printed: string[] = [];
    const log = vi.spyOn(console, 'log').mockImplementation((message: unknown) => {
      printed.push(String(message));
    });

    const rewriteFinding: Finding = {
      scanner: 'web',
      severity: 'high',
      file: 'a.ts',
      line: 3,
      message: 'cookie has no flags',
      fix: {
        kind: 'replace-line',
        file: 'a.ts',
        line: 3,
        replacement: "res.cookie('s', t, { httpOnly: true });",
        rewrite: true
      }
    };

    await resolveFindings(
      [rewriteFinding],
      '/repo',
      async () => 'n',
      () => [],
      () => undefined,
      () => "res.cookie('s', t);"
    );

    log.mockRestore();
    expect(printed.join('\n')).toContain("- res.cookie('s', t);");
    expect(printed.join('\n')).toContain("+ res.cookie('s', t, { httpOnly: true });");
  });

  it('shows no diff for a suppression marker', async () => {
    const printed: string[] = [];
    const log = vi.spyOn(console, 'log').mockImplementation((message: unknown) => {
      printed.push(String(message));
    });

    const markerFinding: Finding = {
      scanner: 'owasp',
      severity: 'high',
      file: 'a.ts',
      line: 3,
      message: 'reviewed',
      fix: { kind: 'replace-line', file: 'a.ts', line: 3, replacement: '// marker\nORIGINAL' }
    };

    await resolveFindings([markerFinding], '/repo', async () => 'n', () => [], () => undefined, () => 'ORIGINAL');

    log.mockRestore();
    expect(printed.join('\n')).not.toContain('+ ');
  });

  it('asks without a diff when the original line cannot be read', async () => {
    const answers: string[] = [];
    const rewriteFinding: Finding = {
      scanner: 'web',
      severity: 'high',
      file: 'a.ts',
      line: 3,
      message: 'cookie has no flags',
      fix: { kind: 'replace-line', file: 'a.ts', line: 3, replacement: 'FIXED', rewrite: true }
    };

    const result = await resolveFindings(
      [rewriteFinding],
      '/repo',
      async () => {
        answers.push('asked');
        return 'y';
      },
      () => [],
      () => undefined,
      () => undefined
    );

    expect(answers).toEqual(['asked']);
    expect(result.resolved).toHaveLength(1);
  });

  it('reads the preview line from the real working tree by default', async () => {
    writeFileSync(join(previewDir, 'a.ts'), "line one\nres.cookie('s', t);\nline three\n");
    const printed: string[] = [];
    const log = vi.spyOn(console, 'log').mockImplementation((message: unknown) => {
      printed.push(String(message));
    });

    const rewriteFinding: Finding = {
      scanner: 'web',
      severity: 'high',
      file: 'a.ts',
      line: 2,
      message: 'cookie has no flags',
      fix: {
        kind: 'replace-line',
        file: 'a.ts',
        line: 2,
        replacement: "res.cookie('s', t, { httpOnly: true });",
        rewrite: true
      }
    };

    await resolveFindings([rewriteFinding], previewDir, async () => 'n', () => [], () => undefined);

    log.mockRestore();
    expect(printed.join('\n')).toContain("- res.cookie('s', t);");
  });
});
