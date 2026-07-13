import type { Finding, Scanner, StagedFile } from '../types.js';

interface SecretPattern {
  name: string;
  regex: RegExp;
}

const KNOWN_PATTERNS: SecretPattern[] = [
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g },
  { name: 'Stripe Live Key', regex: /sk_live_[0-9a-zA-Z]{24,}/g },
  { name: 'OpenAI API Key', regex: /sk-[a-zA-Z0-9]{32,}/g },
  {
    name: 'Generic assigned secret',
    regex: /(?:api[_-]?key|secret|token|password)\s*[:=]\s*["'][^"'\s]{12,}["']/gi
  }
];

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
      const lines = file.content.split('\n');
      lines.forEach((line, index) => {
        for (const pattern of KNOWN_PATTERNS) {
          pattern.regex.lastIndex = 0;
          const match = pattern.regex.exec(line);
          if (match) {
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
                envVarName: pattern.name.toUpperCase().replace(/[^A-Z0-9]+/g, '_'),
                secretValue: match[0]
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
