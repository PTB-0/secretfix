import type { Finding, Scanner, StagedFile } from '../types.js';

interface OwaspPattern {
  name: string;
  regex: RegExp;
  severity: Finding['severity'];
  message: string;
}

const PATTERNS: OwaspPattern[] = [
  {
    name: 'eval-usage',
    regex: /\beval\s*\(|\bnew\s+Function\s*\(/,
    severity: 'high',
    message: 'Use of eval()/Function() constructor can execute arbitrary code. Avoid dynamic code execution.'
  },
  {
    name: 'sql-string-concat',
    regex: /(SELECT|INSERT|UPDATE|DELETE)[^;]*(\+|\$\{)/i,
    severity: 'critical',
    message:
      'SQL query appears to be built with string concatenation/interpolation. Use parameterized queries to avoid SQL injection.'
  },
  {
    name: 'hardcoded-credential',
    regex: /\bpassword\s*[:=]\s*["'][^"'\s]+["']/i,
    severity: 'high',
    message: 'Hardcoded password literal found. Load credentials from environment variables or a secrets manager instead.'
  },
  {
    name: 'insecure-randomness',
    regex: /Math\.random\s*\(\)/,
    severity: 'medium',
    message:
      'Math.random() is not cryptographically secure. If this value is used for tokens, session IDs, or passwords, use crypto.randomBytes() instead.'
  }
];

export const owaspScanner: Scanner = {
  name: 'owasp',
  async scan(stagedFiles: StagedFile[]): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const file of stagedFiles) {
      const lines = file.content.split('\n');
      lines.forEach((line, index) => {
        for (const pattern of PATTERNS) {
          if (pattern.regex.test(line)) {
            findings.push({
              scanner: 'owasp',
              severity: pattern.severity,
              file: file.path,
              line: index + 1,
              message: `${pattern.message} (${file.path}:${index + 1})`,
              fix: {
                kind: 'replace-line',
                file: file.path,
                line: index + 1,
                replacement: `// vibeguard: review this line manually — ${pattern.name}\n${line}`
              }
            });
          }
        }
      });
    }

    return findings;
  }
};
