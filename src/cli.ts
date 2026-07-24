import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { Command } from 'commander';
import promptsLib from 'prompts';
import { scanCommand } from './commands/scan.js';
import { initCommand } from './commands/init.js';
import type { Finding } from './types.js';
import type { PromptFn } from './fix/interactive.js';

const { version } = createRequire(import.meta.url)('../package.json') as { version: string };

const SEVERITY_LABEL: Record<Finding['severity'], string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW'
};

function normalizeAnswer(raw: string | undefined): 'y' | 'n' | 'skip' {
  const answer = (raw ?? 'skip').trim().toLowerCase();
  if (answer === 'y' || answer === 'yes') return 'y';
  if (answer === 'n' || answer === 'no') return 'n';
  return 'skip';
}

const interactivePrompt: PromptFn = async (finding: Finding) => {
  const response = await promptsLib({
    type: 'text',
    name: 'answer',
    message: `[${SEVERITY_LABEL[finding.severity]}] Fix this now? (${finding.file}:${finding.line}) [y/n/skip]`
  });
  return normalizeAnswer(response.answer === undefined ? undefined : String(response.answer));
};

/**
 * Without a terminal, `prompts` renders its question and then never settles once
 * stdin hits EOF — which used to let the process fall off the end of the event
 * loop and exit 0, silently waving a leaked secret into the commit.
 *
 * So when stdin is not a TTY it is drained up front instead: piped answers are
 * consumed in order, and an empty stdin (a hook launched from a GUI client, CI,
 * `git commit < /dev/null`) yields 'skip' for every finding, which blocks.
 */
function createScriptedPrompt(): PromptFn {
  let answers: string[] | undefined;
  let index = 0;

  return async (finding: Finding) => {
    if (answers === undefined) {
      try {
        answers = readFileSync(0, 'utf8').split('\n');
      } catch {
        answers = [];
      }
    }
    const answer = normalizeAnswer(answers[index]);
    index += 1;
    console.log(`[${SEVERITY_LABEL[finding.severity]}] ${finding.file}:${finding.line} — answered "${answer}"`);
    return answer;
  };
}

function createPrompt(): PromptFn {
  return process.stdin.isTTY === true ? interactivePrompt : createScriptedPrompt();
}

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
      // Fail closed: anything that ends this process before the scan reports a
      // clean result — a crash, an unsettled promise — must block the commit.
      process.exitCode = 1;
      process.exitCode = await scanCommand({
        noSecrets: !opts.secrets,
        noOwasp: !opts.owasp,
        noDeps: !opts.deps,
        prompt: createPrompt()
      });
    });

  program
    .command('init')
    .description('Install the VibeGuard pre-commit hook in this repository')
    .action(() => {
      initCommand(process.cwd());
    });

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
