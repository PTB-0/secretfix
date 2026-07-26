import type { Finding, Scanner, Severity, StagedFile } from '../../types.js';
import type { Hit, ScanContext, WebRule } from './types.js';
import { AGNOSTIC_RULES } from './rules/agnostic.js';

export const ALL_RULES: readonly WebRule[] = [...AGNOSTIC_RULES];

/**
 * Where an uncorroborated heuristic finding lands. With the default failOn of
 * 'high' this reports without blocking — the point of the confidence split.
 */
const ADVISORY_SEVERITY: Severity = 'medium';

function applies(rule: WebRule, context: ScanContext): boolean {
  return rule.frameworks.some((framework) => context.frameworks.has(framework));
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
