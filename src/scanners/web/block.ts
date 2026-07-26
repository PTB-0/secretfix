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
 * A `/` is treated as a regex literal start only after characters that make it
 * unambiguous (operators, start of line). For any `/` after other characters,
 * a divergence check looks ahead for a second `/`. If found and the span between
 * contains `{`, `}`, `'`, `"`, or backtick, the two possible readings (division
 * vs. regex) would produce different brace or quote accounting, so extraction bails.
 *
 * Returns undefined for unterminated blocks, missing braces, or unresolvable
 * ambiguity. Callers treat that as "no evidence" and skip the rule for that
 * file — an unparseable region must never manufacture a finding.
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

      // Detect regex literal vs. division operator.
      if (ch === '/' && next !== '/' && next !== '*') {
        if (startsRegexUnambiguously(lastSignificant)) {
          // Definitely a regex literal.
          const regexEnd = skipRegex(line, c);
          if (regexEnd === undefined) {
            return undefined; // unterminated regex
          }
          c = regexEnd;
          lastSignificant = '/';
          continue;
        }

        // For everything else, check if the two interpretations would produce
        // different brace/quote accounting. If so, we cannot safely proceed.
        const diverges = interpretationsDiverge(line, c);
        if (diverges) {
          return undefined; // unresolvable ambiguity — cannot parse safely
        }
        // Otherwise, continue as division (ordinary source character).
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
 * Determines if a `/` is unambiguously the start of a regex literal based on
 * the preceding significant character. True only when `/` appears at the start
 * of a line or after characters that cannot be followed by division.
 */
function startsRegexUnambiguously(prev: string | undefined): boolean {
  if (prev === undefined) return true; // `/` at start of line is regex

  // Characters that can only be followed by a regex (unambiguous).
  // Note: `>` is safe here because `a > /x/` is unambiguous (no division operator
  // can follow `>`), and `=>` always precedes a regex in arrow functions.
  return /[({,=:\[\!&|?+\-*%~^{}>;]/.test(prev);
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
 * Checks if treating a `/` as division vs. regex would produce different brace
 * or quote accounting. If a `/` appears at position `slashPos` and could be read
 * as either operator, look ahead on the same line for another `/`. If the span
 * between them contains `{`, `}`, `'`, `"`, or backtick, the two readings would
 * diverge and the whole extraction must bail.
 */
function interpretationsDiverge(line: string, slashPos: number): boolean {
  // Look ahead from the character after this slash to find the next unescaped /.
  for (let i = slashPos + 1; i < line.length; i += 1) {
    const ch = line[i];
    const prev = line[i - 1];

    if (ch === '\\') {
      i += 1; // skip the escaped character
      continue;
    }

    if (ch === '/') {
      // Found a potential regex terminator. Check the span between the two slashes.
      const span = line.substring(slashPos + 1, i);
      // If the span contains any of these, the interpretations diverge.
      if (/[{}"'`]/.test(span)) {
        return true;
      }
      return false; // safe to continue as division
    }
  }

  // No terminator found on this line — continue as division (safe).
  return false;
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
