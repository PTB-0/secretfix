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
});
