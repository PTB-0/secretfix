import { describe, it, expect } from 'vitest';
import { secretsScanner } from '../../src/scanners/secrets.js';

describe('secretsScanner', () => {
  it('flags a known AWS access key pattern', async () => {
    const findings = await secretsScanner.scan([
      { path: 'config.js', content: 'const key = "AKIAABCDEFGHIJKLMNOP";' }
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].message).toContain('AWS Access Key');
  });

  it('flags a generic assigned secret', async () => {
    const findings = await secretsScanner.scan([
      { path: 'server.js', content: 'const apiKey = "thisIsASecretValue123";' }
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('Generic assigned secret');
  });

  it('flags a high-entropy quoted token with no known pattern match', async () => {
    const findings = await secretsScanner.scan([
      { path: 'notes.js', content: 'const x = "aZ8kQ2mN7pR4vT9xB1cD6fH3jL0";' }
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('high');
  });

  it('does not flag ordinary code', async () => {
    const findings = await secretsScanner.scan([
      { path: 'app.js', content: 'function add(a, b) { return a + b; }' }
    ]);
    expect(findings).toHaveLength(0);
  });

  it('captures only the secret value in the fix, not the whole assignment', async () => {
    const findings = await secretsScanner.scan([
      { path: 'server.js', content: 'const apiKey = "thisIsASecretValue123";' }
    ]);
    expect(findings[0].fix).toEqual({
      kind: 'move-to-env',
      file: 'server.js',
      line: 1,
      envVarName: 'API_KEY',
      secretValue: 'thisIsASecretValue123'
    });
  });

  it('names the env var after the known pattern when there is no identifier', async () => {
    const findings = await secretsScanner.scan([
      { path: 'config.js', content: 'const key = "AKIAABCDEFGHIJKLMNOP";' }
    ]);
    expect(findings[0].fix).toMatchObject({
      envVarName: 'AWS_ACCESS_KEY',
      secretValue: 'AKIAABCDEFGHIJKLMNOP'
    });
  });

  it('reports the correct line number for a secret further down the file', async () => {
    const findings = await secretsScanner.scan([
      { path: 'config.js', content: '// header\n\nconst key = "AKIAABCDEFGHIJKLMNOP";\n' }
    ]);
    expect(findings[0].line).toBe(3);
  });
});
