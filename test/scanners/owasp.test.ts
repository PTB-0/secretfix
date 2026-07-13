import { describe, it, expect } from 'vitest';
import { owaspScanner } from '../../src/scanners/owasp.js';

describe('owaspScanner', () => {
  it('flags eval usage', async () => {
    const findings = await owaspScanner.scan([{ path: 'a.js', content: 'eval(userInput);' }]);
    expect(findings.some((f) => f.message.includes('eval'))).toBe(true);
  });

  it('flags SQL string concatenation', async () => {
    const findings = await owaspScanner.scan([
      { path: 'db.js', content: 'const q = "SELECT * FROM users WHERE id = " + userId;' }
    ]);
    expect(findings.some((f) => f.severity === 'critical')).toBe(true);
  });

  it('flags hardcoded password literal', async () => {
    const findings = await owaspScanner.scan([{ path: 'auth.js', content: 'password = "hunter2";' }]);
    expect(findings.some((f) => f.message.includes('Hardcoded'))).toBe(true);
  });

  it('flags Math.random usage', async () => {
    const findings = await owaspScanner.scan([
      { path: 'token.js', content: 'const sessionId = Math.random().toString(36);' }
    ]);
    expect(findings.some((f) => f.severity === 'medium')).toBe(true);
  });

  it('does not flag safe code', async () => {
    const findings = await owaspScanner.scan([{ path: 'safe.js', content: 'const total = price * quantity;' }]);
    expect(findings).toHaveLength(0);
  });
});
