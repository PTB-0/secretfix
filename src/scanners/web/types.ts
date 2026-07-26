import type { FixDescriptor, Severity, StagedFile } from '../../types.js';

export type Framework = 'agnostic' | 'nextjs' | 'express' | 'supabase' | 'firebase';

export interface ScanContext {
  cwd: string;
  frameworks: ReadonlySet<Framework>;
  /**
   * Reads a repo file that may not be staged (middleware.ts, next.config.js).
   * Cached per run. Returns undefined when the file does not exist.
   */
  readRepoFile(path: string): string | undefined;
}

/** 'certain' rules report at their declared severity; 'heuristic' rules must corroborate first. */
export type Confidence = 'certain' | 'heuristic';

/** A heuristic rule's own verdict: discard the hit, or report it at this severity. */
export type Resolution = 'drop' | { severity: Severity };

/** One match, anchored to the line the finding is reported against. */
export interface Hit {
  line: number;
  /** Appended to the rule's message when a match needs naming (a route path, a field). */
  detail?: string;
  /** Present only when a deterministic rewrite exists for this match. */
  fix?: FixDescriptor;
  /** Set by a heuristic rule's verification. Absent means "uncorroborated". */
  resolved?: Resolution;
}

export type RuleGroup = 'injection' | 'auth' | 'exposure' | 'hardening';

interface RuleBase {
  /** Namespaced, stable, public: appears in findings and in webRules config. */
  id: string;
  group: RuleGroup;
  frameworks: readonly Framework[];
  severity: Severity;
  confidence: Confidence;
  message: string;
}

export interface LineRule extends RuleBase {
  kind: 'line';
  regex: RegExp;
  fix?: (line: string, lineNumber: number, file: StagedFile) => FixDescriptor | undefined;
}

export interface BlockRule extends RuleBase {
  kind: 'block';
  find: (file: StagedFile, context: ScanContext) => Hit[];
}

export interface FileRule extends RuleBase {
  kind: 'file';
  /** Matched against the staged path. A rule whose anchor is not staged never runs. */
  appliesTo: RegExp;
  check: (file: StagedFile, context: ScanContext) => Hit[];
}

export type WebRule = LineRule | BlockRule | FileRule;
