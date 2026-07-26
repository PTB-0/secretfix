import { describe, it, expect } from 'vitest';
import { extractBlock, forEachBlock } from '../../../src/scanners/web/block.js';

/** Slices from the first line and returns the body text, or undefined. */
function body(source: string): string | undefined {
  return extractBlock(source.split('\n'), 0)?.text;
}

describe('extractBlock', () => {
  it('slices a single-line block', () => {
    const block = extractBlock(['export function f() { return 1; }'], 0);
    expect(block?.startLine).toBe(1);
    expect(block?.endLine).toBe(1);
  });

  it('slices a multi-line block and reports 1-based bounds', () => {
    const block = extractBlock(['export function f() {', '  return 1;', '}', 'after();'], 0);
    expect(block?.startLine).toBe(1);
    expect(block?.endLine).toBe(3);
    expect(block?.text).toBe('export function f() {\n  return 1;\n}');
  });

  it('balances nested blocks', () => {
    expect(body('function f() {\n  if (x) {\n    g();\n  }\n}\nafter();')).toBe(
      'function f() {\n  if (x) {\n    g();\n  }\n}'
    );
  });

  it('ignores braces inside single- and double-quoted strings', () => {
    expect(body('function f() {\n  const s = "}";\n  const t = \'}\';\n}')).toContain("'}'");
  });

  it('ignores braces inside a template literal, including interpolation', () => {
    expect(body('function f() {\n  const s = `a ${b} }`;\n}')).toContain('${b}');
  });

  it('ignores braces inside a multi-line template literal', () => {
    const source = 'function f() {\n  const s = `\n}\n`;\n  return s;\n}';
    expect(extractBlock(source.split('\n'), 0)?.endLine).toBe(6);
  });

  it('ignores braces inside a line comment', () => {
    expect(extractBlock(['function f() {', '  // }', '  return 1;', '}'], 0)?.endLine).toBe(4);
  });

  it('ignores braces inside a block comment', () => {
    expect(extractBlock(['function f() {', '  /* } */', '  return 1;', '}'], 0)?.endLine).toBe(4);
  });

  it('respects an escaped quote rather than ending the string early', () => {
    expect(extractBlock(['function f() {', '  const s = "a\\" }";', '  return s;', '}'], 0)?.endLine).toBe(4);
  });

  it('returns undefined for an unterminated block', () => {
    expect(extractBlock(['function f() {', '  return 1;'], 0)).toBeUndefined();
  });

  it('returns undefined when there is no brace at all', () => {
    expect(extractBlock(['const x = 1;'], 0)).toBeUndefined();
  });

  it('starts at fromIndex, skipping earlier braces', () => {
    const lines = ['const a = { x: 1 };', 'function f() {', '  return 2;', '}'];
    const block = extractBlock(lines, 1);
    expect(block?.startLine).toBe(2);
    expect(block?.endLine).toBe(4);
  });

  it('ignores braces inside a regex literal', () => {
    expect(extractBlock(['function f() {', '  const closer = /}/;', '  return 1;', '}'], 0)?.endLine).toBe(4);
  });

  it('ignores braces and quotes inside a character class in a regex', () => {
    expect(extractBlock(['function f() {', '  const cls = /[{\'"]]/;', '  return 1;', '}'], 0)?.endLine).toBe(4);
  });

  it('does not mistake division for a regex', () => {
    const lines = ['function f() {', '  const half = total / 2;', '  return half;', '}'];
    expect(extractBlock(lines, 0)?.endLine).toBe(4);
  });

  it('returns undefined for an unterminated regex literal', () => {
    expect(extractBlock(['function f() {', '  const pattern = /unclosed'], 0)).toBeUndefined();
  });
});

describe('forEachBlock', () => {
  it('visits each triggering line with its own block and reports the 1-based line', () => {
    const content = ['function a() {', '  x();', '}', 'const y = 1;', 'function b() {', '  z();', '}'].join('\n');
    const seen: number[] = [];

    forEachBlock({ path: 'a.ts', content }, /function \w+\s*\(/, (_blockText, line) => {
      seen.push(line);
      return undefined;
    });

    expect(seen).toEqual([1, 5]);
  });

  it('passes the regex match through so a rule can read a capture group', () => {
    const content = 'export async function POST(req) {\n  return ok();\n}';
    let method = '';

    forEachBlock({ path: 'route.ts', content }, /function (GET|POST)\b/, (_blockText, _line, match) => {
      method = match[1];
      return undefined;
    });

    expect(method).toBe('POST');
  });

  it('collects only the hits the visitor returns', () => {
    const content = 'function a() {\n  x();\n}\nfunction b() {\n  y();\n}';
    const hits = forEachBlock({ path: 'a.ts', content }, /function (\w+)/, (_blockText, line, match) =>
      match[1] === 'b' ? { line } : undefined
    );

    expect(hits).toEqual([{ line: 4 }]);
  });

  it('skips a triggering line whose block never closes', () => {
    const hits = forEachBlock({ path: 'a.ts', content: 'function a() {\n  x();' }, /function/, (_t, line) => ({ line }));
    expect(hits).toEqual([]);
  });

  it('does not lose matches when the trigger has a global flag', () => {
    const content = 'function a() {\n  x();\n}\nfunction b() {\n  y();\n}';
    const hits = forEachBlock({ path: 'a.ts', content }, /function (\w+)/g, (_blockText, line, match) =>
      match[1] ? { line } : undefined
    );

    expect(hits).toEqual([{ line: 1 }, { line: 4 }]);
  });
});
