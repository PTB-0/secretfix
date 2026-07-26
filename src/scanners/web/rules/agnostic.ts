import type { WebRule } from '../types.js';

/**
 * Rules that hold on any JS/TS file, whatever the framework.
 *
 * Every regex matches a *single* line, because scanning is line-by-line. Where
 * the evidence can legitimately span lines the rule is a BlockRule instead (5,
 * 10, 11) — or, as with insecure-cookie, the regex demands the call's closing
 * parenthesis on the same line, so a multi-line form is skipped rather than
 * mis-reported.
 */
export const AGNOSTIC_RULES: readonly WebRule[] = [
  {
    kind: 'line',
    id: 'agnostic/path-traversal',
    group: 'injection',
    frameworks: ['agnostic'],
    severity: 'critical',
    confidence: 'certain',
    regex: /\bfs(?:\.promises)?\.[a-zA-Z]+\s*\([^)]*\breq(?:uest)?\.(?:params|query|body)\b/,
    message:
      'A file path is built from request input, so a caller can walk out of the intended directory with "../" and read anything the process can. Resolve the path and check it stays inside the directory you meant.'
  },
  {
    kind: 'line',
    id: 'agnostic/ssrf',
    group: 'injection',
    frameworks: ['agnostic'],
    severity: 'high',
    confidence: 'certain',
    regex:
      /\b(?:fetch|got|axios(?:\.(?:get|post|put|patch|delete|request))?)\s*\(\s*[^)]*\breq(?:uest)?\.(?:params|query|body)\b/,
    message:
      'The server fetches a URL the caller chose. That lets them point it at your internal network or cloud metadata endpoint. Accept an identifier instead and map it to a URL you control, or check the host against an allowlist.'
  },
  {
    kind: 'line',
    id: 'agnostic/nosql-injection',
    group: 'injection',
    frameworks: ['agnostic'],
    severity: 'critical',
    confidence: 'certain',
    regex:
      /\$where\b|\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|deleteOne|deleteMany|updateOne|updateMany)\s*\(\s*(?:await\s+)?req(?:uest)?\.(?:body|query)\b/,
    message:
      'A request object is used as the database query itself, so a caller can send operators like {"$ne": null} and change what the query means. Read the specific fields you need instead of passing the whole object.'
  },
  {
    kind: 'line',
    id: 'agnostic/open-redirect',
    group: 'exposure',
    frameworks: ['agnostic'],
    severity: 'medium',
    confidence: 'certain',
    regex: /\bredirect\s*\(\s*[^)]*(?:\breq(?:uest)?\.(?:query|params|body)\.|searchParams\.get\s*\()/i,
    message:
      'The redirect target comes from the request, so this URL can bounce someone to an attacker-controlled site that looks like yours. Allow only relative paths, or check the destination against a list you control.'
  },
  {
    kind: 'line',
    id: 'agnostic/plaintext-password-compare',
    group: 'auth',
    frameworks: ['agnostic'],
    severity: 'critical',
    confidence: 'certain',
    regex:
      /\b\w+\.(?:password|passwd|password_hash)\s*={2,3}\s*(?:password|passwd|pwd|(?:req(?:uest)?\.)?body\.password)\b|\b(?:password|passwd|pwd|(?:req(?:uest)?\.)?body\.password)\s*={2,3}\s*\w+\.(?:password|passwd|password_hash)\b/i,
    message:
      "A stored password is compared directly against the one that was typed, which means passwords are stored in plain text. Hash them with bcrypt, scrypt or argon2 at signup and compare with that library's own compare function."
  },
  {
    kind: 'line',
    id: 'agnostic/jwt-unverified',
    group: 'auth',
    frameworks: ['agnostic'],
    severity: 'critical',
    confidence: 'certain',
    regex: /\bjwt\.decode\s*\(|\bjsonwebtoken\.decode\s*\(|algorithms\s*:\s*\[\s*['"]none['"]/i,
    message:
      'This reads a token without checking its signature, so anyone can hand you a token they wrote themselves and claim to be any user. Use jwt.verify() with your signing secret, and never allow the "none" algorithm.'
  },
  {
    kind: 'line',
    id: 'agnostic/insecure-cookie',
    group: 'auth',
    frameworks: ['agnostic'],
    severity: 'high',
    confidence: 'certain',
    regex: /\b(?:res\.cookie|cookies\(\)\.set|cookies\.set|response\.cookies\.set)\s*\((?![^)]*\bhttpOnly\b)[^)]*\)/,
    message:
      'This cookie has no httpOnly flag, so any script on the page can read it — including one injected through an XSS bug. Set httpOnly: true, secure: true and sameSite for anything that identifies a session.'
  },
  {
    kind: 'line',
    id: 'agnostic/error-stack-to-client',
    group: 'exposure',
    frameworks: ['agnostic'],
    severity: 'medium',
    confidence: 'certain',
    regex:
      /\.(?:send|json)\s*\([^)]*\b(?:err|error|e)\.stack\b|\.json\s*\(\s*\{\s*(?:error|message)\s*:\s*(?:err|error|e)\s*[,\}]/,
    message:
      'The raw error is sent to the caller. Stack traces and driver errors leak file paths, query shapes and library versions that make the next attack easier. Log the error server-side and return a generic message.'
  }
];
