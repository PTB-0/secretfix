import type { Finding } from './types.js';

export interface ReportFinding {
  /** The web scanner's rule id, where the message carries one. */
  rule: string | undefined;
  scanner: string;
  severity: string;
  file: string;
  line: number;
  message: string;
  hasAutomaticFix: boolean;
}

export interface Report {
  /** Bumped whenever the shape changes, so a consumer can notice. */
  version: 1;
  findings: ReportFinding[];
}

/**
 * A machine-readable view of the findings, for handing to a coding agent that
 * already has the whole repository in context. No timestamp: identical staged
 * content must produce identical bytes so the file can be committed or diffed.
 */
export function buildReport(findings: Finding[]): Report {
  return {
    version: 1,
    findings: findings.map((finding) => ({
      rule: /\[([a-z]+\/[a-z0-9-]+)\]/.exec(finding.message)?.[1],
      scanner: finding.scanner,
      severity: finding.severity,
      file: finding.file,
      line: finding.line,
      message: finding.message,
      hasAutomaticFix: finding.fix !== undefined
    }))
  };
}
