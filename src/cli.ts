import { createRequire } from 'node:module';
import { Command } from 'commander';
import promptsLib from 'prompts';
import { scanCommand } from './commands/scan.js';
import type { Finding } from './types.js';
import type { PromptFn } from './fix/interactive.js';

const { version } = createRequire(import.meta.url)('../package.json') as { version: string };

const SEVERITY_LABEL: Record<Finding['severity'], string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW'
};

/**
 * Falls back to 'skip' whenever the answer cannot be read — a hook running without
 * a usable stdin must block the commit, never wave it through.
 */
const realPrompt: PromptFn = async (finding: Finding) => {
  const response = await promptsLib({
    type: 'text',
    name: 'answer',
    message: `[${SEVERITY_LABEL[finding.severity]}] Fix this now? (${finding.file}:${finding.line}) [y/n/skip]`
  });
  const answer = (response.answer ?? 'skip').toString().trim().toLowerCase();
  if (answer === 'y' || answer === 'yes') return 'y';
  if (answer === 'n' || answer === 'no') return 'n';
  return 'skip';
};

export function buildProgram(): Command {
  const program = new Command();
  program
    .name('vibeguard')
    .description('Pre-commit security guardrail for vibe coders')
    .version(version, '-v, --version', 'print the vibeguard version');

  program
    .command('scan')
    .description('Scan staged changes for secrets, unsafe patterns, and vulnerable dependencies')
    .option('--no-secrets', 'disable the secrets scanner')
    .option('--no-owasp', 'disable the OWASP pattern scanner')
    .option('--no-deps', 'disable the dependency CVE scanner')
    .action(async (opts: { secrets: boolean; owasp: boolean; deps: boolean }) => {
      const exitCode = await scanCommand({
        noSecrets: !opts.secrets,
        noOwasp: !opts.owasp,
        noDeps: !opts.deps,
        prompt: realPrompt
      });
      process.exitCode = exitCode;
    });

  program
    .command('init')
    .description('Install the VibeGuard pre-commit hook in this repository');

  return program;
}

export function run(argv: string[]): void {
  buildProgram()
    .parseAsync(argv)
    .catch((err: unknown) => {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`vibeguard: ${message}`);
      process.exitCode = 1;
    });
}
