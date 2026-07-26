import type { StagedFile } from '../../types.js';
import type { Hit } from './types.js';

export interface Block {
  /** 1-based line holding the opening brace. */
  startLine: number;
  /** 1-based line holding the matching closing brace. */
  endLine: number;
  text: string;
}

/**
 * Slices the brace-delimited region beginning at or after `fromIndex` (0-based
 * line index), balancing braces while ignoring any that sit inside a string,
 * template literal, comment, or regex literal.
 *
 * Returns undefined when the region never closes, when there is no brace at
 * all, or when a regex literal is unterminated. Callers treat that as "no evidence"
 * and skip the rule for that file — an unparseable region must never manufacture
 * a finding.
 */
export function extractBlock(lines: string[], fromIndex: number): Block | undefined {
  let depth = 0;
  let started = false;
  let startLine = 0;

  let inBlockComment = false;
  // Persists across lines: a template literal legitimately spans them.
  let quote: string | undefined;

  for (let i = fromIndex; i < lines.length; i += 1) {
    const line = lines[i];
    let lastSignificant: string | undefined;

    for (let c = 0; c < line.length; c += 1) {
      const ch = line[c];
      const next = line[c + 1];

      if (inBlockComment) {
        if (ch === '*' && next === '/') {
          inBlockComment = false;
          c += 1;
          lastSignificant = '/';
        }
        continue;
      }

      if (quote !== undefined) {
        if (ch === '\\') {
          c += 1;
        } else if (ch === quote) {
          quote = undefined;
        }
        continue;
      }

      if (ch === '/' && next === '/') break; // rest of the line is a comment
      if (ch === '/' && next === '*') {
        inBlockComment = true;
        c += 1;
        continue;
      }

      // Detect regex literal: if this / could start a regex, skip the literal.
      if (ch === '/' && next !== '/' && next !== '*' && isRegexStart(lastSignificant)) {
        const regexEnd = skipRegex(line, c);
        if (regexEnd === undefined) {
          return undefined; // unterminated regex
        }
        c = regexEnd;
        lastSignificant = '/';
        continue;
      }

      if (ch === '"' || ch === "'" || ch === '`') {
        quote = ch;
        continue;
      }

      if (ch === '{') {
        if (!started) {
          started = true;
          startLine = i + 1;
        }
        depth += 1;
      } else if (ch === '}' && started) {
        depth -= 1;
        if (depth === 0) {
          return { startLine, endLine: i + 1, text: lines.slice(fromIndex, i + 1).join('\n') };
        }
      }

      // Track last significant character for regex detection.
      if (!/\s/.test(ch)) {
        lastSignificant = ch;
      }
    }
  }

  return undefined;
}

/**
 * Determines if a `/` at the current position is likely a regex literal start
 * based on the preceding significant character.
 */
function isRegexStart(prev: string | undefined): boolean {
  if (prev === undefined) return true; // `/` at start of line
  return /[({,=:\[\!&|?+\-*%~^{};\s]/.test(prev);
}

/**
 * Scans forward from the first character after `/` to find the closing `/`
 * of a regex literal, respecting escapes and character classes.
 * Returns the index of the closing `/`, or undefined if unterminated.
 */
function skipRegex(line: string, startSlash: number): number | undefined {
  let inClass = false;
  for (let i = startSlash + 1; i < line.length; i += 1) {
    const ch = line[i];
    const prev = line[i - 1];

    if (ch === '\\') {
      i += 1; // skip the escaped character
      continue;
    }

    if (ch === '[' && prev !== '\\') {
      inClass = true;
      continue;
    }

    if (ch === ']' && prev !== '\\' && inClass) {
      inClass = false;
      continue;
    }

    if (ch === '/' && !inClass) {
      return i; // found the closing /
    }
  }

  return undefined; // regex never closed on this line
}

/**
 * Runs `visit` at every line matching `trigger`, handing it that line's
 * brace-delimited block.
 *
 * A line whose block does not resolve is skipped silently. That decision lives
 * here, once, because every block rule depends on it: an unparseable region must
 * never manufacture a finding.
 */
export function forEachBlock(
  file: StagedFile,
  trigger: RegExp,
  visit: (blockText: string, line: number, match: RegExpExecArray) => Hit | undefined
): Hit[] {
  const lines = file.content.split('\n');
  const hits: Hit[] = [];

  // exec() advances lastIndex on a g/y-flagged regex, so a module-level constant
  // would silently skip matches between calls. Strip those flags rather than
  // mutating the caller's regex.
  const scanner =
    trigger.global || trigger.sticky
      ? new RegExp(trigger.source, trigger.flags.replace(/[gy]/g, ''))
      : trigger;

  lines.forEach((line, index) => {
    const match = scanner.exec(line);
    if (match === null) return;

    const block = extractBlock(lines, index);
    if (block === undefined) return;

    const hit = visit(block.text, index + 1, match);
    if (hit !== undefined) hits.push(hit);
  });

  return hits;
}
