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
 * all, when a regex literal is unterminated, or when an ambiguous `/` has two
 * possible readings (division vs. regex) that would produce different brace or
 * quote accounting. An ambiguous slash whose readings disagree causes the whole
 * extraction to bail. Callers treat that as "no evidence" and skip the rule for
 * that file — an unparseable region must never manufacture a finding.
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
        const classification = classifySlash(lastSignificant);

        if (classification === 'unambiguous') {
          // Definitely a regex literal.
          const regexEnd = skipRegex(line, c);
          if (regexEnd === undefined) {
            return undefined; // unterminated regex
          }
          c = regexEnd;
          lastSignificant = '/';
          continue;
        }

        if (classification === 'ambiguous') {
          // The slash could be division or regex. Look ahead to see if the two
          // interpretations would produce different brace/quote accounting.
          // If they would, we cannot safely proceed — bail.
          const diverges = interpretationsDiverge(line, c);
          if (diverges) {
            return undefined; // ambiguous and divergent — cannot parse safely
          }
          // Otherwise, the interpretations agree on accounting, so treating it as
          // division (not skipping characters) is safe.
        }
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
 *
 * Returns `'unambiguous'` if this is definitely a regex, `'division'` if definitely
 * division, or `'ambiguous'` if it could be either and needs further analysis.
 */
function classifySlash(prev: string | undefined): 'unambiguous' | 'division' | 'ambiguous' {
  if (prev === undefined) return 'unambiguous'; // `/` at start of line is regex

  // Characters that can only be followed by a regex (unambiguous).
  // Note: `>` is safe here because `a > /x/` is unambiguous (no division operator
  // can follow `>`), and `=>` always precedes a regex in arrow functions.
  if (/[({,=:\[\!&|?+\-*%~^{}>;]/.test(prev)) return 'unambiguous';

  // Characters that can definitely only be followed by division (unambiguous).
  // Identifier characters and digits after a number or identifier mean division.
  if (/[\]\w]/.test(prev)) return 'division';

  // `)` is genuinely ambiguous: could be `(a+b) / 2` (division) or
  // `if(cond) /regex/` (regex). Must analyze further.
  if (prev === ')') return 'ambiguous';

  return 'ambiguous'; // default to ambiguous for safety
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
