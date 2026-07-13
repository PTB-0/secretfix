export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type FixDescriptor =
  | { kind: 'move-to-env'; file: string; line: number; envVarName: string; secretValue: string }
  | { kind: 'bump-dependency'; packageJsonPath: string; packageName: string; targetVersion: string }
  | { kind: 'replace-line'; file: string; line: number; replacement: string };

export interface Finding {
  scanner: 'secrets' | 'owasp' | 'deps';
  severity: Severity;
  file: string;
  line: number;
  message: string;
  fix?: FixDescriptor;
}

export interface StagedFile {
  path: string;
  content: string;
}

export interface Scanner {
  name: string;
  scan(stagedFiles: StagedFile[]): Promise<Finding[]>;
}
