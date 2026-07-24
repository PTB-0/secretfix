import { existsSync, mkdirSync, writeFileSync, readFileSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { execSync } from 'node:child_process';
import { defaultConfig } from '../config.js';

export interface InitDeps {
  installHusky: (cwd: string) => void;
}

function defaultInstallHusky(cwd: string): void {
  // Run through a shell deliberately. On Windows `npx` is a .cmd shim, and since
  // the CVE-2024-27980 fix Node refuses to spawn .cmd/.bat directly (EINVAL).
  // execSync takes one static string, so there is nothing to escape — never build
  // this command from user input.
  execSync('npx husky init', { cwd, stdio: 'ignore' });
}

const HOOK_INVOCATION = 'npx commitguard scan';

/**
 * git runs hooks without a terminal, so the interactive fix prompts need one
 * reattached — otherwise every finding falls through to "skip".
 *
 * The probe runs in a subshell on purpose. `/dev/tty` can exist and pass `-r`
 * while still failing to open (CI, GUI git clients, no controlling terminal),
 * and a failed redirect on a bare `exec` kills a non-interactive shell outright
 * — which would make the hook abort before commitguard ever ran, blocking every
 * commit, clean ones included. A subshell absorbs that failure.
 */
export function buildHookScript(invocation: string): string {
  return `if (exec < /dev/tty) 2>/dev/null; then
  commitguard_stdin=/dev/tty
else
  commitguard_stdin=/dev/null
fi
${invocation} < "$commitguard_stdin"
`;
}

const HOOK_CONTENT = `#!/usr/bin/env sh
# Installed by \`commitguard init\`. Delete this file to remove the hook.
${buildHookScript(HOOK_INVOCATION)}`;

const APPENDED_HOOK = `
# --- commitguard ---
${buildHookScript(HOOK_INVOCATION)}`;

/**
 * Writes the hook without discarding one the project already had. `replace` is
 * set when this run installed husky itself: the only thing that can be in the
 * hook then is husky's own `npm test` placeholder, which would fail every commit
 * in a project without a test script.
 */
function writeHook(hookPath: string, replace: boolean): 'created' | 'appended' | 'unchanged' {
  if (replace || !existsSync(hookPath)) {
    writeFileSync(hookPath, HOOK_CONTENT);
    chmodSync(hookPath, 0o755);
    return 'created';
  }

  const existing = readFileSync(hookPath, 'utf8');
  if (existing.includes(HOOK_INVOCATION)) {
    return 'unchanged';
  }

  const separator = existing.endsWith('\n') ? '' : '\n';
  writeFileSync(hookPath, `${existing}${separator}${APPENDED_HOOK}`);
  chmodSync(hookPath, 0o755);
  return 'appended';
}

export function initCommand(cwd: string, deps: InitDeps = { installHusky: defaultInstallHusky }): void {
  const huskyDir = join(cwd, '.husky');
  let hookDir = huskyDir;
  let huskyInstalledNow = false;

  if (!existsSync(huskyDir)) {
    try {
      deps.installHusky(cwd);
      huskyInstalledNow = true;
    } catch {
      // husky needs network on first run and a git repo; fall back to the plain
      // git hook rather than leaving the project with no protection at all.
      const gitHooksDir = join(cwd, '.git', 'hooks');
      if (!existsSync(join(cwd, '.git'))) {
        throw new Error('commitguard init: not a git repository, and husky could not be installed. Run "git init" first.');
      }
      hookDir = gitHooksDir;
      console.warn('commitguard: husky is unavailable — installing a plain .git/hooks/pre-commit hook instead.');
    }
  }

  mkdirSync(hookDir, { recursive: true });
  const outcome = writeHook(join(hookDir, 'pre-commit'), huskyInstalledNow);

  const configPath = join(cwd, '.commitguardrc.json');
  if (!existsSync(configPath)) {
    const template = {
      secrets: defaultConfig.secrets,
      owasp: defaultConfig.owasp,
      deps: defaultConfig.deps,
      ignoreLines: {},
      // Added to commitguard's built-in exclude list (lockfiles, minified bundles).
      excludeFiles: []
    };
    writeFileSync(configPath, `${JSON.stringify(template, null, 2)}\n`);
  }

  const relativeHook = hookDir === huskyDir ? '.husky/pre-commit' : '.git/hooks/pre-commit';
  const message =
    outcome === 'unchanged'
      ? `commitguard: pre-commit hook already present at ${relativeHook}`
      : `commitguard: pre-commit hook ${outcome === 'appended' ? 'appended to' : 'installed at'} ${relativeHook}`;
  console.log(message);
}
