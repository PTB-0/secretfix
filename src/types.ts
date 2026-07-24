export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type FixDescriptor =
  | { kind: 'move-to-env'; file: string; line: number; envVarName: string; secretValue: string }
  | { kind: 'bump-dependency'; packageJsonPath: string; packageName: string; targetVersion: string }
  | { kind: 'replace-line'; file: string; line: number; replacement: string }
  /** Drops a file from the index and gitignores it, without touching the copy on disk. */
  | { kind: 'unstage-file'; file: string };

export interface Finding {
  scanner: 'secrets' | 'owasp' | 'deps';
  severity: Severity;
  file: string;
  line: number;
  message: string;
  fix?: FixDescriptor;
  /**
   * 'file' marks a finding about the file itself rather than a line someone typed
   * (a staged .env). Those are never limited to the diff — staging the file at all
   * is the problem, whichever lines changed. Defaults to 'line'.
   */
  scope?: 'line' | 'file';
}

export interface StagedFile {
  path: string;
  content: string;
}

export interface Scanner {
  name: string;
  scan(stagedFiles: StagedFile[]): Promise<Finding[]>;
}
