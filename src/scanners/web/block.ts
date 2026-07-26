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
 * template literal, or comment.
 *
 * Returns undefined when the region never closes, or when there is no brace at
 * all. Callers treat that as "no evidence" and skip the rule for that file —
 * an unparseable region must never manufacture a finding.
 *
 * Known limitation: a regex literal containing an unbalanced brace or a lone
 * quote (`/[{'"]/`) confuses the scan. Rare inside handler bodies, and the
 * failure mode is a skipped rule, not a false positive.
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

    for (let c = 0; c < line.length; c += 1) {
      const ch = line[c];
      const next = line[c + 1];

      if (inBlockComment) {
        if (ch === '*' && next === '/') {
          inBlockComment = false;
          c += 1;
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
    }
  }

  return undefined;
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

  lines.forEach((line, index) => {
    const match = trigger.exec(line);
    if (match === null) return;

    const block = extractBlock(lines, index);
    if (block === undefined) return;

    const hit = visit(block.text, index + 1, match);
    if (hit !== undefined) hits.push(hit);
  });

  return hits;
}
