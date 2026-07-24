import { existsSync, mkdirSync, writeFileSync, readFileSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { defaultConfig } from '../config.js';

export interface InitDeps {
  installHusky: (cwd: string) => void;
}

function defaultInstallHusky(cwd: string): void {
  // On Windows `npx` is a .cmd shim, which execFile cannot spawn by bare name.
  const npx = process.platform === 'win32' ? 'npx.cmd' : 'npx';
  execFileSync(npx, ['husky', 'init'], { cwd, stdio: 'ignore' });
}

const HOOK_INVOCATION = 'npx vibeguard scan';

// git runs hooks without a terminal, so reattach one when it is available —
// otherwise the interactive fix prompts cannot be answered and every finding
// falls through to "skip", blocking the commit.
const TTY_REATTACH = 'if [ -r /dev/tty ]; then exec < /dev/tty; fi';

const HOOK_CONTENT = `#!/usr/bin/env sh
# Installed by \`vibeguard init\`. Delete this file to remove the hook.
${TTY_REATTACH}
${HOOK_INVOCATION}
`;

const APPENDED_HOOK = `
# --- vibeguard ---
${TTY_REATTACH}
${HOOK_INVOCATION}
`;

/** Writes the hook without discarding one the project already had. */
function writeHook(hookPath: string): 'created' | 'appended' | 'unchanged' {
  if (!existsSync(hookPath)) {
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

  if (!existsSync(huskyDir)) {
    try {
      deps.installHusky(cwd);
    } catch {
      // husky needs network on first run and a git repo; fall back to the plain
      // git hook rather than leaving the project with no protection at all.
      const gitHooksDir = join(cwd, '.git', 'hooks');
      if (!existsSync(join(cwd, '.git'))) {
        throw new Error('vibeguard init: not a git repository, and husky could not be installed. Run "git init" first.');
      }
      hookDir = gitHooksDir;
      console.warn('vibeguard: husky is unavailable — installing a plain .git/hooks/pre-commit hook instead.');
    }
  }

  mkdirSync(hookDir, { recursive: true });
  const outcome = writeHook(join(hookDir, 'pre-commit'));

  const configPath = join(cwd, '.vibeguardrc.json');
  if (!existsSync(configPath)) {
    const template = {
      secrets: defaultConfig.secrets,
      owasp: defaultConfig.owasp,
      deps: defaultConfig.deps,
      ignoreLines: {},
      // Added to vibeguard's built-in exclude list (lockfiles, minified bundles).
      excludeFiles: []
    };
    writeFileSync(configPath, `${JSON.stringify(template, null, 2)}\n`);
  }

  const relativeHook = hookDir === huskyDir ? '.husky/pre-commit' : '.git/hooks/pre-commit';
  const message =
    outcome === 'unchanged'
      ? `vibeguard: pre-commit hook already present at ${relativeHook}`
      : `vibeguard: pre-commit hook ${outcome === 'appended' ? 'appended to' : 'installed at'} ${relativeHook}`;
  console.log(message);
}
