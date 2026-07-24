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

  it.each([
    ['command injection via concatenation', 'exec("rm -rf " + userPath);', 'critical'],
    ['command injection via template literal', 'execSync(`git checkout ${branch}`);', 'critical'],
    ['innerHTML assignment', 'el.innerHTML = userInput;', 'high'],
    ['dangerouslySetInnerHTML', 'return <div dangerouslySetInnerHTML={{ __html: body }} />;', 'high'],
    ['disabled TLS verification', 'const agent = new https.Agent({ rejectUnauthorized: false });', 'critical'],
    ['md5 password hashing', 'const h = crypto.createHash("md5").update(pw).digest("hex");', 'high']
  ])('flags %s', async (_label, content, severity) => {
    const findings = await owaspScanner.scan([{ path: 'a.js', content }]);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe(severity);
  });

  it.each([
    ['a comparison, not an assignment', 'if (el.innerHTML === expected) return;'],
    ['execFile with an argument array', 'execFile("git", ["checkout", branch]);'],
    ['sha256 hashing', 'const h = crypto.createHash("sha256").update(data).digest("hex");'],
    ['rejectUnauthorized left on', 'const agent = new https.Agent({ rejectUnauthorized: true });']
  ])('does not flag %s', async (_label, content) => {
    expect(await owaspScanner.scan([{ path: 'a.js', content }])).toHaveLength(0);
  });

  it('does not flag safe code', async () => {
    const findings = await owaspScanner.scan([{ path: 'safe.js', content: 'const total = price * quantity;' }]);
    expect(findings).toHaveLength(0);
  });
});
