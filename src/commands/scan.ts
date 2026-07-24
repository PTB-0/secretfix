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
  type SafeShipConfig
} from '../config.js';
import { runScanners } from '../orchestrator.js';
import { secretsScanner } from '../scanners/secrets.js';
import { owaspScanner } from '../scanners/owasp.js';
import { depsScanner } from '../scanners/deps.js';
import { resolveFindings, type PromptFn } from '../fix/interactive.js';
import type { Finding, Scanner, StagedFile } from '../types.js';

export interface ScanOptions extends CliOverrides {
  cwd?: string;
  prompt: PromptFn;
}

/**
 * Dependency findings describe the dependency set as a whole, not a line someone
 * typed, so diff-scoping them would hide a vulnerable transitive package just
 * because its line was not edited. Only line-anchored scanners are scoped.
 */
const DIFF_SCOPED_SCANNERS: ReadonlySet<Finding['scanner']> = new Set<Finding['scanner']>(['secrets', 'owasp']);

function selectScanners(config: SafeShipConfig): Scanner[] {
  const scanners: Scanner[] = [];
  if (config.secrets) scanners.push(secretsScanner);
  if (config.owasp) scanners.push(owaspScanner);
  if (config.deps) scanners.push(depsScanner);
  return scanners;
}

/** Drops findings the user has silenced, via config or an inline marker. */
function actionableFindings(
  findings: Finding[],
  config: SafeShipConfig,
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
  config: SafeShipConfig,
  cwd: string
): Promise<{ findings: Finding[]; warnings: string[] }> {
  const files = getStagedFiles(cwd).filter((file) => !isExcluded(config, file.path));
  const addedLines = config.scanMode === 'added-lines' ? getStagedAddedLines(cwd) : undefined;
  const { findings, warnings } = await runScanners(scanners, files);
  return { findings: actionableFindings(findings, config, files, addedLines), warnings };
}

function reportAdvisory(findings: Finding[]): void {
  if (findings.length === 0) return;
  console.log(`\nsafeship: ${findings.length} lower-severity note(s) — not blocking this commit:`);
  for (const finding of findings) {
    console.log(`  [${finding.severity}] ${finding.file}:${finding.line} — ${finding.message}`);
  }
}

export async function scanCommand(options: ScanOptions): Promise<number> {
  const cwd = options.cwd ?? process.cwd();
  const config = applyCliOverrides(loadConfig(cwd), options);
  const scanners = selectScanners(config);

  const { findings, warnings } = await collectFindings(scanners, config, cwd);

  for (const warning of warnings) {
    console.warn(`safeship: warning — ${warning}`);
  }

  const blocking = findings.filter((finding) => blocksCommit(config, finding.severity));
  const advisory = findings.filter((finding) => !blocksCommit(config, finding.severity));

  if (blocking.length === 0) {
    console.log('safeship: no blocking issues found.');
    reportAdvisory(advisory);
    return 0;
  }

  console.log(`\nsafeship: ${blocking.length} issue(s) found in your staged changes.\n`);

  const { resolved, unresolved } = await resolveFindings(blocking, cwd, options.prompt);

  if (unresolved.length > 0) {
    console.error(
      `\nsafeship: ${unresolved.length} unresolved issue(s). Commit blocked.\n` +
        'Fix them, or silence a line with "// safeship-ignore-next-line", or run "git commit --no-verify" to bypass.'
    );
    return 1;
  }

  // The spec requires re-scanning the updated index before letting the commit
  // through, so a fix that did not actually remove the problem still blocks.
  if (resolved.length > 0) {
    const verification = await collectFindings(scanners, config, cwd);
    const stillBlocking = verification.findings.filter((finding) => blocksCommit(config, finding.severity));
    if (stillBlocking.length > 0) {
      console.error(`\nsafeship: ${stillBlocking.length} issue(s) still present after fixing. Commit blocked.`);
      for (const finding of stillBlocking) {
        console.error(`  ${finding.file}:${finding.line} — ${finding.message}`);
      }
      return 1;
    }
  }

  console.log('\nsafeship: all issues resolved.');
  reportAdvisory(advisory);
  return 0;
}
