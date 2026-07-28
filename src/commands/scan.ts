import { getStagedFiles, getStagedAddedLines } from '../git.js';
import {
  loadConfig,
  applyCliOverrides,
  isIgnored,
  isExcluded,
  hasIgnoreMarker,
  blocksCommit,
  compareSeverity,
  type CliOverrides,
  type SecretFixConfig
} from '../config.js';
import { runScanners } from '../orchestrator.js';
import { secretsScanner } from '../scanners/secrets.js';
import { owaspScanner } from '../scanners/owasp.js';
import { depsScanner } from '../scanners/deps.js';
import { createScanContext } from '../scanners/web/context.js';
import { createWebScanner, ALL_RULES } from '../scanners/web/index.js';
import { resolveFindings, type PromptFn } from '../fix/interactive.js';
import { buildReport } from '../report.js';
import type { Finding, Scanner, StagedFile } from '../types.js';
import type { ScanContext } from '../scanners/web/types.js';

export interface ScanOptions extends CliOverrides {
  cwd?: string;
  prompt: PromptFn;
  json?: boolean;
}

/**
 * Dependency findings describe the dependency set as a whole, not a line someone
 * typed, so diff-scoping them would hide a vulnerable transitive package just
 * because its line was not edited. Only line-anchored scanners are scoped.
 */
const DIFF_SCOPED_SCANNERS: ReadonlySet<Finding['scanner']> = new Set<Finding['scanner']>([
  'secrets',
  'owasp',
  'web'
]);

function selectScanners(config: SecretFixConfig, context: ScanContext): Scanner[] {
  const scanners: Scanner[] = [];
  if (config.secrets) scanners.push(secretsScanner);
  if (config.owasp) scanners.push(owaspScanner);
  if (config.deps) scanners.push(depsScanner);
  if (config.web) {
    scanners.push(createWebScanner(context, ALL_RULES.filter((rule) => config.webRules[rule.id] !== false)));
  }
  return scanners;
}

/** Drops findings the user has silenced, via config or an inline marker. */
function actionableFindings(
  findings: Finding[],
  config: SecretFixConfig,
  files: StagedFile[],
  addedLines: Map<string, Set<number>> | undefined
): Finding[] {
  const contentByPath = new Map(files.map((file) => [file.path, file.content]));

  return findings
    .filter((finding) => {
      if (isIgnored(config, finding.file, finding.line)) return false;

      const content = contentByPath.get(finding.file);
      if (content !== undefined && hasIgnoreMarker(content, finding.line)) return false;

      if (addedLines && finding.scope !== 'file' && DIFF_SCOPED_SCANNERS.has(finding.scanner)) {
        return addedLines.get(finding.file)?.has(finding.line) ?? false;
      }
      return true;
    })
    .sort((a, b) => compareSeverity(a.severity, b.severity) || a.file.localeCompare(b.file) || a.line - b.line);
}

async function collectFindings(
  scanners: Scanner[],
  config: SecretFixConfig,
  cwd: string
): Promise<{ findings: Finding[]; warnings: string[] }> {
  const files = getStagedFiles(cwd).filter((file) => !isExcluded(config, file.path));
  const addedLines = config.scanMode === 'added-lines' ? getStagedAddedLines(cwd) : undefined;
  const { findings, warnings } = await runScanners(scanners, files);
  return { findings: actionableFindings(findings, config, files, addedLines), warnings };
}

function reportAdvisory(findings: Finding[]): void {
  if (findings.length === 0) return;
  console.log(`\nsecretfix: ${findings.length} lower-severity note(s) — not blocking this commit:`);
  for (const finding of findings) {
    console.log(`  [${finding.severity}] ${finding.file}:${finding.line} — ${finding.message}`);
  }
}

export async function scanCommand(options: ScanOptions): Promise<number> {
  const cwd = options.cwd ?? process.cwd();
  const config = applyCliOverrides(loadConfig(cwd), options);
  const scanners = selectScanners(config, createScanContext(cwd));

  const { findings, warnings } = await collectFindings(scanners, config, cwd);

  // Reporting mode: emit the findings and exit cleanly. This is run by hand,
  // not by the hook, so it must never prompt and never block.
  if (options.json === true) {
    console.log(JSON.stringify(buildReport(findings), null, 2));
    return 0;
  }

  for (const warning of warnings) {
    console.warn(`secretfix: warning — ${warning}`);
  }

  const blocking = findings.filter((finding) => blocksCommit(config, finding.severity));
  const advisory = findings.filter((finding) => !blocksCommit(config, finding.severity));

  if (blocking.length === 0) {
    console.log('secretfix: no blocking issues found.');
    reportAdvisory(advisory);
    return 0;
  }

  console.log(`\nsecretfix: ${blocking.length} issue(s) found in your staged changes.\n`);

  const { resolved, unresolved } = await resolveFindings(blocking, cwd, options.prompt);

  if (unresolved.length > 0) {
    console.error(
      `\nsecretfix: ${unresolved.length} unresolved issue(s). Commit blocked.\n` +
        'Fix them, or silence a line with "// secretfix-ignore-next-line", or run "git commit --no-verify" to bypass.\n' +
        'Working with an AI coding agent? Run "secretfix scan --json > .secretfix-report.json"\n' +
        'and tell it: "fix everything in this report".'
    );
    return 1;
  }

  // The spec requires re-scanning the updated index before letting the commit
  // through, so a fix that did not actually remove the problem still blocks.
  if (resolved.length > 0) {
    const verification = await collectFindings(scanners, config, cwd);
    const stillBlocking = verification.findings.filter((finding) => blocksCommit(config, finding.severity));
    if (stillBlocking.length > 0) {
      console.error(`\nsecretfix: ${stillBlocking.length} issue(s) still present after fixing. Commit blocked.`);
      for (const finding of stillBlocking) {
        console.error(`  ${finding.file}:${finding.line} — ${finding.message}`);
      }
      return 1;
    }
  }

  console.log('\nsecretfix: all issues resolved.');
  reportAdvisory(advisory);
  return 0;
}
