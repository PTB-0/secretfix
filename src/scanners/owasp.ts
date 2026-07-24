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
  },
  {
    name: 'command-injection',
    regex: /\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(\s*(?:[`"'][^`"']*[`"']\s*\+|`[^`]*\$\{)/,
    severity: 'critical',
    message:
      'A shell command is being built by joining strings. Anything a user controls can add their own command. Pass arguments as an array (execFile) instead of interpolating them.'
  },
  {
    name: 'xss-sink',
    regex: /\.innerHTML\s*=(?!=)|\bdangerouslySetInnerHTML\b|\.outerHTML\s*=(?!=)|document\.write\s*\(/,
    severity: 'high',
    message:
      'Assigning HTML directly renders any script tag it contains. Use textContent, or sanitise the value first, unless you are certain the content is trusted.'
  },
  {
    name: 'tls-verification-disabled',
    regex: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|verify\s*=\s*False\b/,
    severity: 'critical',
    message:
      'TLS certificate verification is turned off, which makes the connection trivially interceptable. Fix the certificate rather than skipping the check.'
  },
  {
    name: 'weak-password-hash',
    regex: /createHash\s*\(\s*["'](?:md5|sha1)["']\s*\)|hashlib\.(?:md5|sha1)\s*\(/i,
    severity: 'high',
    message:
      'MD5 and SHA-1 are far too fast to hash passwords with and are broken for signatures. Use bcrypt, scrypt or argon2 for passwords, SHA-256+ elsewhere.'
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
                // The marker is what makes accepting this fix meaningful: the line
                // itself is unchanged (only a human can rewrite it safely), so
                // without a suppression the re-scan would block the commit forever.
                replacement: `// safeship-ignore-next-line — reviewed: ${pattern.name}\n${line}`
              }
            });
          }
        }
      });
    }

    return findings;
  }
};
