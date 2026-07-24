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

  it.each([
    ['GitHub Token', 'const t = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";', 'GITHUB_TOKEN'],
    ['Slack Token', 'const s = "xoxb-123456789012-abcdefghijklmnopqrstuvwx";', 'SLACK_TOKEN'],
    ['Google API Key', 'const k = "AIzaSyD-1234567890abcdefghijklmnopqrstu";', 'GOOGLE_API_KEY'],
    ['Anthropic API Key', 'const k = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234";', 'ANTHROPIC_API_KEY'],
    ['Private Key Block', '-----BEGIN RSA PRIVATE KEY-----', 'PRIVATE_KEY_BLOCK']
  ])('identifies %s by name rather than as a generic high-entropy string', async (label, content, envVar) => {
    const [finding] = await secretsScanner.scan([{ path: 'a.js', content }]);

    expect(finding.severity).toBe('critical');
    expect(finding.message).toContain(label);
    expect(finding.fix).toMatchObject({ envVarName: envVar });
  });

  it('flags a password embedded in a connection string', async () => {
    const [finding] = await secretsScanner.scan([
      { path: 'db.js', content: 'const url = "postgres://admin:s3cretpw@10.0.0.1:5432/app";' }
    ]);

    expect(finding.message).toContain('Credentials in connection string');
    expect(finding.fix).toMatchObject({ secretValue: 's3cretpw' });
  });

  it('does not flag a connection string without a password', async () => {
    const findings = await secretsScanner.scan([{ path: 'db.js', content: 'const url = "https://example.com/api";' }]);
    expect(findings).toHaveLength(0);
  });

  it.each([
    ['.env', 'environment file'],
    ['.env.production', 'environment file'],
    ['config/id_rsa', 'SSH private key'],
    ['certs/server.pem', 'private key / keystore'],
    ['credentials.json', 'cloud credentials file'],
    ['.npmrc', 'npm credentials file']
  ])('flags %s as a file that should never be staged', async (path, label) => {
    const findings = await secretsScanner.scan([{ path, content: 'anything at all\n' }]);

    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].message).toContain(label);
    expect(findings[0].scope).toBe('file');
    expect(findings[0].fix).toEqual({ kind: 'unstage-file', file: path });
  });

  it.each(['.env.example', '.env.sample', 'config.template'])(
    'does not flag %s, which is documentation',
    async (path) => {
      const findings = await secretsScanner.scan([{ path, content: 'DATABASE_URL=\n' }]);
      expect(findings).toHaveLength(0);
    }
  );

  it('reports a sensitive file once, without also scanning its contents', async () => {
    const findings = await secretsScanner.scan([
      { path: '.env', content: 'AWS=AKIAABCDEFGHIJKLMNOP\nSTRIPE=sk_live_abcdefghijklmnopqrstuvwx\n' }
    ]);
    expect(findings).toHaveLength(1);
  });

  it('reports the correct line number for a secret further down the file', async () => {
    const findings = await secretsScanner.scan([
      { path: 'config.js', content: '// header\n\nconst key = "AKIAABCDEFGHIJKLMNOP";\n' }
    ]);
    expect(findings[0].line).toBe(3);
  });
});
