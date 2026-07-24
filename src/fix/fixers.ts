import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { FixDescriptor } from '../types.js';

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Reads a file, or returns '' if it does not exist yet. */
function readOrEmpty(path: string): string {
  return existsSync(path) ? readFileSync(path, 'utf8') : '';
}

/** Appends `line` to a text file, inserting a separating newline when needed. */
function appendLine(path: string, line: string): void {
  const existing = readOrEmpty(path);
  const separator = existing === '' || existing.endsWith('\n') ? '' : '\n';
  writeFileSync(path, `${existing}${separator}${line}\n`);
}

/** .env values only need quoting when they contain whitespace or a comment marker. */
function formatEnvValue(value: string): string {
  return /[\s#"']/.test(value) ? `"${value.replace(/(["\\])/g, '\\$1')}"` : value;
}

/**
 * Picks a name that is not already defined in .env, so a second secret does not
 * silently overwrite the first (common with the generic SUSPECTED_SECRET name).
 */
function uniqueEnvVarName(envContent: string, preferred: string): string {
  const defined = new Set(
    envContent
      .split('\n')
      .map((line) => line.split('=')[0]?.trim())
      .filter((name): name is string => Boolean(name))
  );

  if (!defined.has(preferred)) return preferred;

  let suffix = 2;
  while (defined.has(`${preferred}_${suffix}`)) suffix += 1;
  return `${preferred}_${suffix}`;
}

function readLines(path: string, file: string, line: number): string[] {
  if (!existsSync(path)) {
    throw new Error(`cannot fix ${file}: file not found`);
  }
  const lines = readFileSync(path, 'utf8').split('\n');
  if (line < 1 || line > lines.length) {
    throw new Error(`cannot fix ${file}: line ${line} is out of range`);
  }
  return lines;
}

/**
 * Applies a fix and returns the repo-relative paths that should be re-staged.
 * `.env` is deliberately never returned — it holds the secret and must stay out
 * of the commit.
 */
export function applyFix(fix: FixDescriptor, cwd: string): string[] {
  switch (fix.kind) {
    case 'move-to-env': {
      const filePath = join(cwd, fix.file);
      const lines = readLines(filePath, fix.file, fix.line);
      const original = lines[fix.line - 1];

      if (!original.includes(fix.secretValue)) {
        throw new Error(`cannot fix ${fix.file}:${fix.line}: the secret is no longer present on that line`);
      }

      const envPath = join(cwd, '.env');
      const envVarName = uniqueEnvVarName(readOrEmpty(envPath), fix.envVarName);

      // Swap the whole quoted literal — replacing only the inner value would leave
      // the identifier inside quotes (`"process.env.X"`), which is a string, not the value.
      const quoted = new RegExp(`(["'\`])${escapeRegExp(fix.secretValue)}\\1`);
      lines[fix.line - 1] = quoted.test(original)
        ? original.replace(quoted, `process.env.${envVarName}`)
        : original.replace(fix.secretValue, `process.env.${envVarName}`);

      appendLine(envPath, `${envVarName}=${formatEnvValue(fix.secretValue)}`);

      const restage = [fix.file];
      const gitignorePath = join(cwd, '.gitignore');
      if (!readOrEmpty(gitignorePath).split('\n').some((entry) => entry.trim() === '.env')) {
        appendLine(gitignorePath, '.env');
        restage.push('.gitignore');
      }

      writeFileSync(filePath, lines.join('\n'));
      return restage;
    }
    case 'bump-dependency': {
      const filePath = join(cwd, fix.packageJsonPath);
      if (!existsSync(filePath)) {
        throw new Error(`cannot bump ${fix.packageName}: ${fix.packageJsonPath} not found`);
      }
      const pkg = JSON.parse(readFileSync(filePath, 'utf8')) as {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
      };

      let bumped = false;
      if (pkg.dependencies?.[fix.packageName]) {
        pkg.dependencies[fix.packageName] = `^${fix.targetVersion}`;
        bumped = true;
      }
      if (pkg.devDependencies?.[fix.packageName]) {
        pkg.devDependencies[fix.packageName] = `^${fix.targetVersion}`;
        bumped = true;
      }
      if (!bumped) {
        throw new Error(`cannot bump ${fix.packageName}: not listed in ${fix.packageJsonPath}`);
      }

      writeFileSync(filePath, `${JSON.stringify(pkg, null, 2)}\n`);
      return [fix.packageJsonPath];
    }
    case 'replace-line': {
      const filePath = join(cwd, fix.file);
      const lines = readLines(filePath, fix.file, fix.line);
      lines[fix.line - 1] = fix.replacement;
      writeFileSync(filePath, lines.join('\n'));
      return [fix.file];
    }
  }
}
