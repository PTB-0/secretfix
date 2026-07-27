import type { Finding, Scanner, Severity, StagedFile } from '../../types.js';
import type { Hit, ScanContext, WebRule } from './types.js';
import { AGNOSTIC_RULES } from './rules/agnostic.js';
import { NEXTJS_RULES } from './rules/nextjs.js';
import { EXPRESS_RULES } from './rules/express.js';
import { BAAS_RULES } from './rules/baas.js';

export const ALL_RULES: readonly WebRule[] = [
  ...AGNOSTIC_RULES,
  ...NEXTJS_RULES,
  ...EXPRESS_RULES,
  ...BAAS_RULES
];

/**
 * Where an uncorroborated heuristic finding lands. With the default failOn of
 * 'high' this reports without blocking — the point of the confidence split.
 */
const ADVISORY_SEVERITY: Severity = 'medium';

function applies(rule: WebRule, context: ScanContext): boolean {
  return rule.frameworks.some((framework) => context.frameworks.has(framework));
}

/** `--` starts a comment here; in JavaScript it is a decrement operator. */
const SQL_FILE = /\.sql$/i;

/** `#` starts a comment here; in JavaScript it begins a private class member. */
const HASH_COMMENT_FILE = /(?:^|\/)\.env(?:\.[\w.-]+)?$|\.ya?ml$/i;

/**
 * True when `rest` holds nothing but whitespace and block comments.
 *
 * Reasoning about a single close position cannot answer this: the text after the
 * first `*​/` may be another comment, and the text after the last one may be code
 * with a comment on either side. So remove the comments and look at what is left.
 */
function hasNoLiveCode(rest: string): boolean {
  const withoutClosed = rest.replace(/\/\*[\s\S]*?\*\//g, '');
  // An unclosed `/*` runs to the end of the line, so nothing after it is code.
  const open = withoutClosed.indexOf('/*');
  return (open === -1 ? withoutClosed : withoutClosed.slice(0, open)).trim() === '';
}

/**
 * True when the line cannot contain live code.
 *
 * Line rules match a raw line, so without this a commented-out call — or a note
 * to a colleague that happens to quote one — reports at the rule's full severity
 * and blocks the commit. That is the false positive most corrosive to a tool that
 * has to stay quiet to stay installed.
 *
 * Suppressing a *live* line is the worse error, so each marker is honoured only
 * where it genuinely runs to end-of-line: a block comment is checked for a close
 * that hands back to code on the same line, and `--` and `#` are gated to the
 * file types where they start a comment at all.
 *
 * Deliberately narrow beyond that: a trailing comment on a live line
 * (`doThing(); // and req.body here`) still matches, and so does a pattern inside
 * a string literal. Both need real tokenisation to settle.
 */
export function isCommentOnlyLine(line: string, path: string): boolean {
  const trimmed = line.trim();
  if (trimmed === '') return false;

  // `//` runs to end-of-line in every language this scanner reads.
  if (trimmed.startsWith('//')) return true;

  // A continuation line sits inside a block comment, so it is inert unless it
  // closes the comment and hands back to code on the same line.
  if (trimmed.startsWith('*') && !trimmed.startsWith('/*')) {
    const close = trimmed.indexOf('*/');
    return close === -1 || hasNoLiveCode(trimmed.slice(close + 2));
  }

  if (trimmed.startsWith('/*')) {
    return hasNoLiveCode(trimmed);
  }

  if (SQL_FILE.test(path) && trimmed.startsWith('--')) return true;
  if (HASH_COMMENT_FILE.test(path) && trimmed.startsWith('#')) return true;

  return false;
}

function hitsFor(rule: WebRule, file: StagedFile, context: ScanContext): Hit[] {
  if (rule.kind === 'file') {
    // A project-scope rule runs only when its own anchor file is staged.
    // Otherwise it fires on every unrelated commit until someone silences it.
    return rule.appliesTo.test(file.path) ? rule.check(file, context) : [];
  }

  if (rule.kind === 'block') {
    return rule.find(file, context);
  }

  const hits: Hit[] = [];
  file.content.split('\n').forEach((line, index) => {
    if (isCommentOnlyLine(line, file.path)) return;
    if (rule.regex.test(line)) {
      hits.push({ line: index + 1, fix: rule.fix?.(line, index + 1, file) });
    }
  });
  return hits;
}

/**
 * A heuristic rule reaches its declared severity only where its own verification
 * corroborated it. Uncorroborated it drops to an advisory that reports without
 * blocking; contradicted it is discarded. Absence of evidence must never
 * manufacture a blocking finding.
 */
function severityFor(rule: WebRule, hit: Hit): Severity | undefined {
  if (rule.confidence === 'certain') return rule.severity;
  if (hit.resolved === 'drop') return undefined;
  if (hit.resolved === undefined) return ADVISORY_SEVERITY;
  return hit.resolved.severity;
}

export function createWebScanner(context: ScanContext, rules: readonly WebRule[] = ALL_RULES): Scanner {
  const active = rules.filter((rule) => applies(rule, context));

  return {
    name: 'web',
    async scan(stagedFiles: StagedFile[]): Promise<Finding[]> {
      const findings: Finding[] = [];

      for (const rule of active) {
        for (const file of stagedFiles) {
          for (const hit of hitsFor(rule, file, context)) {
            const severity = severityFor(rule, hit);
            if (severity === undefined) continue;

            const detail = hit.detail === undefined ? '' : ` ${hit.detail}`;
            findings.push({
              scanner: 'web',
              severity,
              file: file.path,
              line: hit.line,
              message: `${rule.message}${detail} [${rule.id}] (${file.path}:${hit.line})`,
              fix: hit.fix,
              scope: rule.kind === 'file' ? 'file' : 'line'
            });
          }
        }
      }

      return findings;
    }
  };
}
