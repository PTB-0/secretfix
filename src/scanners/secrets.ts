import type { Finding, Scanner, StagedFile } from '../types.js';

interface SecretPattern {
  name: string;
  regex: RegExp;
  /** Capture group holding only the secret itself. Defaults to the whole match. */
  valueGroup?: number;
  /** Capture group holding the identifier the secret is assigned to, used to name the env var. */
  nameGroup?: number;
}

const KNOWN_PATTERNS: SecretPattern[] = [
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g },
  { name: 'Stripe Live Key', regex: /sk_live_[0-9a-zA-Z]{24,}/g },
  { name: 'GitHub Token', regex: /gh[pousr]_[A-Za-z0-9]{36,}/g },
  { name: 'Slack Token', regex: /xox[baprs]-[A-Za-z0-9-]{10,}/g },
  { name: 'Google API Key', regex: /AIza[0-9A-Za-z_-]{35}/g },
  { name: 'Anthropic API Key', regex: /sk-ant-[A-Za-z0-9-]{20,}/g },
  { name: 'OpenAI API Key', regex: /sk-(?:proj-)?[a-zA-Z0-9]{32,}/g },
  { name: 'Private Key Block', regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g },
  {
    // A password embedded in a connection URI: postgres://user:pass@host/db
    name: 'Credentials in connection string',
    regex: /[a-z][a-z0-9+.-]*:\/\/[^:@/\s]+:([^@/\s]{4,})@[^\s"'`]+/gi,
    valueGroup: 1
  },
  {
    name: 'Generic assigned secret',
    regex: /((?:api[_-]?key|secret|token|password)\w*)\s*[:=]\s*["']([^"'\s]{12,})["']/gi,
    nameGroup: 1,
    valueGroup: 2
  }
];

/**
 * Files that are a leak simply by being staged, whatever is inside them. Content
 * scanning misses these: a .env is `KEY=value` with no quotes, which matches no
 * assignment pattern and often not the entropy check either.
 */
const SENSITIVE_FILES: { pattern: RegExp; label: string }[] = [
  { pattern: /(^|\/)\.env(\.[\w-]+)?$/, label: 'environment file' },
  { pattern: /(^|\/)id_(rsa|dsa|ecdsa|ed25519)$/, label: 'SSH private key' },
  { pattern: /\.(pem|pfx|p12|key|keystore|jks)$/i, label: 'private key / keystore' },
  { pattern: /(^|\/)(credentials|service-account.*|gcp-key)\.json$/i, label: 'cloud credentials file' },
  { pattern: /(^|\/)\.npmrc$/, label: 'npm credentials file' },
  { pattern: /(^|\/)\.pypirc$/, label: 'PyPI credentials file' },
  { pattern: /(^|\/)\.aws\/credentials$/, label: 'AWS credentials file' }
];

function sensitiveFileLabel(path: string): string | undefined {
  // .env.example and friends are documentation, meant to be committed.
  if (/\.(example|sample|template|dist)$/i.test(path)) return undefined;
  return SENSITIVE_FILES.find((entry) => entry.pattern.test(path))?.label;
}

/**
 * `apiKey` -> `API_KEY`, `AWS Access Key` -> `AWS_ACCESS_KEY`.
 *
 * The camelCase split only applies to identifiers. Pattern labels are prose and
 * already word-separated, and splitting them mangles internal capitals —
 * "GitHub Token" would become GIT_HUB_TOKEN.
 */
function toEnvVarName(raw: string): string {
  const separated = raw.includes(' ') ? raw : raw.replace(/([a-z0-9])([A-Z])/g, '$1_$2');
  return separated
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
}

const HIGH_ENTROPY_TOKEN = /["'][A-Za-z0-9+/_=-]{20,}["']/g;
const ENTROPY_THRESHOLD = 4.0;

function shannonEntropy(value: string): number {
  const counts = new Map<string, number>();
  for (const char of value) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export const secretsScanner: Scanner = {
  name: 'secrets',
  async scan(stagedFiles: StagedFile[]): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const file of stagedFiles) {
      const sensitive = sensitiveFileLabel(file.path);
      if (sensitive) {
        findings.push({
          scanner: 'secrets',
          severity: 'critical',
          file: file.path,
          line: 1,
          message: `${file.path} is a ${sensitive} and should never be committed. SecretFix can remove it from this commit and add it to .gitignore — the file stays on your disk.`,
          fix: { kind: 'unstage-file', file: file.path },
          scope: 'file'
        });
        continue;
      }

      const lines = file.content.split('\n');
      lines.forEach((line, index) => {
        for (const pattern of KNOWN_PATTERNS) {
          pattern.regex.lastIndex = 0;
          const match = pattern.regex.exec(line);
          if (match) {
            // Only the secret itself may go into .env — capturing the surrounding
            // assignment would write `API_KEY=apiKey = "..."` and mangle the source line.
            const secretValue = pattern.valueGroup ? match[pattern.valueGroup] : match[0];
            const identifier = pattern.nameGroup ? match[pattern.nameGroup] : pattern.name;

            findings.push({
              scanner: 'secrets',
              severity: 'critical',
              file: file.path,
              line: index + 1,
              message: `Possible ${pattern.name} found in ${file.path}:${index + 1}. Move this value to an environment variable instead of committing it.`,
              fix: {
                kind: 'move-to-env',
                file: file.path,
                line: index + 1,
                envVarName: toEnvVarName(identifier),
                secretValue
              }
            });
            return;
          }
        }

        HIGH_ENTROPY_TOKEN.lastIndex = 0;
        const entropyMatch = HIGH_ENTROPY_TOKEN.exec(line);
        if (entropyMatch) {
          const token = entropyMatch[0].slice(1, -1);
          if (shannonEntropy(token) >= ENTROPY_THRESHOLD) {
            findings.push({
              scanner: 'secrets',
              severity: 'high',
              file: file.path,
              line: index + 1,
              message: `High-entropy string in ${file.path}:${index + 1} looks like it could be a secret. Move it to an environment variable if it is.`,
              fix: {
                kind: 'move-to-env',
                file: file.path,
                line: index + 1,
                envVarName: 'SUSPECTED_SECRET',
                secretValue: token
              }
            });
          }
        }
      });
    }

    return findings;
  }
};
