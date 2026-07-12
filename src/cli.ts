import { Command } from 'commander';

export function buildProgram(): Command {
  const program = new Command();
  program
    .name('vibeguard')
    .description('Pre-commit security guardrail for vibe coders');

  program
    .command('scan')
    .description('Scan staged changes for secrets, unsafe patterns, and vulnerable dependencies');

  program
    .command('init')
    .description('Install the VibeGuard pre-commit hook in this repository');

  return program;
}

export function run(argv: string[]): void {
  buildProgram().parse(argv);
}
