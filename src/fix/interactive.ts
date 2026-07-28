import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Finding, FixDescriptor } from '../types.js';
import { applyFix } from './fixers.js';
import { restageFile } from '../git.js';

export type PromptFn = (finding: Finding) => Promise<'y' | 'n' | 'skip'>;

export interface ResolveResult {
  resolved: Finding[];
  unresolved: Finding[];
}

/** Returns the paths to re-stage; a `void` return falls back to the fix's own target file. */
type ApplyFn = (fix: FixDescriptor, cwd: string) => string[] | void;
type RestageFn = (path: string, cwd: string) => void;

interface AcceptedFix {
  findings: Finding[];
  fix: FixDescriptor;
}

function targetLine(fix: FixDescriptor): number {
  return fix.kind === 'bump-dependency' || fix.kind === 'unstage-file' || fix.kind === 'add-security-headers'
    ? 0
    : fix.line;
}

function targetFile(fix: FixDescriptor): string {
  return fix.kind === 'bump-dependency' ? fix.packageJsonPath : fix.file;
}

type ReadLineFn = (file: string, line: number, cwd: string) => string | undefined;

/** Best-effort: a preview that cannot be produced is simply not shown. */
const readWorkingTreeLine: ReadLineFn = (file, line, cwd) => {
  try {
    return readFileSync(join(cwd, file), 'utf8').split('\n')[line - 1];
  } catch {
    return undefined;
  }
};

/**
 * Prints what the fix will write, for a fix that genuinely changes code.
 * Accepting a suppression marker is low-stakes and self-explanatory; accepting a
 * rewrite is not, so the author sees the new line before saying yes.
 */
function previewRewrite(fix: FixDescriptor, cwd: string, readLine: ReadLineFn): void {
  if (fix.kind !== 'replace-line' || fix.rewrite !== true) return;

  const before = readLine(fix.file, fix.line, cwd);
  if (before === undefined) return;

  const after = fix.replacement.split('\n');
  console.log(`\n  - ${before.trim()}`);
  for (const added of after) {
    console.log(`  + ${added.trim()}`);
  }
  console.log('');
}

type ReplaceLineFix = Extract<FixDescriptor, { kind: 'replace-line' }>;

function isReplaceLine(fix: FixDescriptor): fix is ReplaceLineFix {
  return fix.kind === 'replace-line';
}

/**
 * Several scanners can flag the same line (e.g. `eval()` around a concatenated
 * SQL string). Each carries its own `replace-line` fix: a suppression marker's
 * replacement is "annotation lines + the original line", while a web rule's is
 * a genuine rewrite of the line itself.
 *
 * Applying them one after another would drop every annotation but the last, so
 * they are merged into a single write: all annotations, then one final line.
 * A rewrite always wins that final slot — otherwise a marker merged after it
 * would silently discard the rewrite while both findings were reported fixed.
 */
function mergeReplacements(fixes: readonly ReplaceLineFix[]): string {
  const annotations: string[] = [];
  let keptLine = '';
  let keptFromRewrite = false;

  for (const fix of fixes) {
    const parts = fix.replacement.split('\n');
    const last = parts[parts.length - 1];

    if (fix.rewrite === true) {
      if (!keptFromRewrite) {
        keptLine = last;
        keptFromRewrite = true;
      }
    } else if (!keptFromRewrite) {
      keptLine = last;
    }

    for (const annotation of parts.slice(0, -1)) {
      if (!annotations.includes(annotation)) annotations.push(annotation);
    }
  }

  return [...annotations, keptLine].join('\n');
}

/**
 * Collapses accepted fixes so that at most one write targets any given
 * file:line. Findings whose fix loses a collision are returned separately so
 * the caller can leave them unresolved — reporting them fixed when their change
 * was dropped is the one outcome this tool must never produce.
 */
function coalesce(accepted: { finding: Finding; fix: FixDescriptor }[]): {
  writes: AcceptedFix[];
  conflicted: Finding[];
} {
  const groups = new Map<string, { findings: Finding[]; fixes: FixDescriptor[] }>();

  for (const { finding, fix } of accepted) {
    // The key includes the kind, so every fix in a group shares it — which is
    // what lets the replace-line branch below assume index alignment.
    //
    // NUL separates the parts because it cannot occur in `fix.kind` or in a file
    // path, so two different fixes can never collide into one key. A printable
    // separator would only be safe while every kind starts with a distinct letter
    // and the trailing field stays numeric — an invariant nothing enforces.
    const key = `${fix.kind}\0${targetFile(fix)}\0${targetLine(fix)}`;
    const group = groups.get(key);
    if (group) {
      group.findings.push(finding);
      group.fixes.push(fix);
    } else {
      groups.set(key, { findings: [finding], fixes: [fix] });
    }
  }

  const writes: AcceptedFix[] = [];
  const conflicted: Finding[] = [];

  for (const { findings, fixes } of groups.values()) {
    const [first] = fixes;

    if (!isReplaceLine(first)) {
      writes.push({ findings, fix: first });
      continue;
    }

    const replaceLine = fixes.filter(isReplaceLine);
    const rewrites = replaceLine.filter((fix) => fix.rewrite === true);
    // Two independent rewrites of one line cannot both be right. Apply the
    // first and leave the rest unresolved, so the re-scan still blocks.
    const losing = new Set(rewrites.slice(1));

    const applied: Finding[] = [];
    const usable: ReplaceLineFix[] = [];
    replaceLine.forEach((fix, index) => {
      if (losing.has(fix)) {
        conflicted.push(findings[index]);
        return;
      }
      applied.push(findings[index]);
      usable.push(fix);
    });

    const base = rewrites[0] ?? first;
    writes.push({ findings: applied, fix: { ...base, replacement: mergeReplacements(usable) } });
  }

  return { writes, conflicted };
}

export async function resolveFindings(
  findings: Finding[],
  cwd: string,
  prompt: PromptFn,
  fix: ApplyFn = applyFix,
  restage: RestageFn = restageFile,
  readLine: ReadLineFn = readWorkingTreeLine
): Promise<ResolveResult> {
  const accepted: { finding: Finding; fix: FixDescriptor }[] = [];
  const unresolved: Finding[] = [];

  // Ask in reported order — bottom-up prompting would be disorienting.
  for (const finding of findings) {
    console.log(finding.message);

    if (!finding.fix) {
      unresolved.push(finding);
      continue;
    }

    previewRewrite(finding.fix, cwd, readLine);
    const answer = await prompt(finding);
    if (answer === 'y') {
      accepted.push({ finding, fix: finding.fix });
    } else {
      unresolved.push(finding);
    }
  }

  const { writes: pending, conflicted } = coalesce(accepted);
  unresolved.push(...conflicted);

  // Two write phases. In-place fixes (move-to-env, bump-dependency) never change
  // a file's line count, so they run top-down, which keeps generated env var names
  // in source order. Only replace-line can insert lines, so it runs bottom-up to
  // avoid shifting line numbers that were computed against the original file.
  const writes = pending.sort((a, b) => {
    const phaseA = a.fix.kind === 'replace-line' ? 1 : 0;
    const phaseB = b.fix.kind === 'replace-line' ? 1 : 0;
    if (phaseA !== phaseB) return phaseA - phaseB;
    return phaseA === 0 ? targetLine(a.fix) - targetLine(b.fix) : targetLine(b.fix) - targetLine(a.fix);
  });

  const resolved: Finding[] = [];
  const touchedFiles = new Set<string>();

  for (const write of writes) {
    try {
      const touched = fix(write.fix, cwd) ?? [targetFile(write.fix)];
      resolved.push(...write.findings);
      for (const path of touched) {
        touchedFiles.add(path);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.warn(`secretfix: could not apply fix — ${message}`);
      unresolved.push(...write.findings);
    }
  }

  for (const file of touchedFiles) {
    try {
      restage(file, cwd);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.warn(`secretfix: could not re-stage ${file} — ${message}`);
    }
  }

  return { resolved, unresolved };
}
