import { describe, it, expect } from 'vitest';
import { buildProgram } from '../src/cli.js';

describe('cli', () => {
  it('registers the scan and init commands', () => {
    const program = buildProgram();
    const names = program.commands.map((c) => c.name());
    expect(names).toEqual(['scan', 'init']);
  });

  it('sets the program name to commitguard', () => {
    expect(buildProgram().name()).toBe('commitguard');
  });
});
