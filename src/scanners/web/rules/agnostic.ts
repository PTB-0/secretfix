import { forEachBlock } from '../block.js';
import { requestBoundLocals } from '../verify.js';
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

const ORM_WRITE = /\b\w+(?:\.\w+)*\.(?:create|createMany|update|updateMany|upsert)\s*\(/;

/**
 * `data: req.body` / `data: await req.json()` first, so the identifier alternative
 * cannot swallow `req` out of a dotted expression and then dismiss it for not being
 * a request-bound local. The identifier alternative requires the name to end there,
 * so `data: body.name` — an explicit single field, which is safe — does not match.
 * (Shorthand `data` alone, i.e. `{ where, data }`, is a real shape but out of scope
 * here: the regex requires a literal colon, so it is a known gap, not a claim.)
 */
const DATA_ASSIGNMENT =
  /\bdata\s*:\s*(?:await\s+)?req(?:uest)?\s*\.\s*(?:body\b|json\s*\(\s*\))|\bdata\s*:\s*(?:\{\s*\.{3}\s*)?([A-Za-z_$][\w$]*)\s*(?=[,}\s])/;

const CORS_TRIGGER = /\bcors\s*\(|Access-Control-Allow-Origin/;
const WILDCARD_ORIGIN = /(?:origin|Access-Control-Allow-Origin)\s*[:=]\s*['"`]\*['"`]/;
const CREDENTIALS_ON = /credentials\s*:\s*true|Access-Control-Allow-Credentials\s*[:=]\s*['"`]?true/;

const AUTH_ENDPOINT = /(?:^|\/)(?:login|signin|sign-in|register|signup|sign-up|auth|token|password|reset)(?:\/|$)/i;
const AUTH_HANDLER = /\b(?:export\s+(?:async\s+)?function\s+(?:POST|PUT)|export\s+const\s+(?:POST|PUT)\s*=|app\.post\s*\()/;
const RATE_LIMIT_EVIDENCE = /\b(?:rate[-_]?limit\w*|ratelimit\w*|limiter|Ratelimit|throttle|slowDown|Bottleneck)\b/i;

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
  },
  {
    kind: 'block',
    id: 'agnostic/mass-assignment',
    group: 'injection',
    frameworks: ['agnostic'],
    severity: 'critical',
    confidence: 'certain',
    message:
      'The whole request body is handed to the database write, so a caller can set any column — including ones you never meant to expose, like isAdmin or credits. List the fields you actually accept.',
    find: (file) => {
      const bound = requestBoundLocals(file.content);
      return forEachBlock(file, ORM_WRITE, (blockText, line) => {
        const match = DATA_ASSIGNMENT.exec(blockText);
        if (match === null) return undefined;
        // A named local counts only when it was bound to the request body;
        // `data: computedValues` is the server's own object and is fine.
        const identifier = match[1];
        if (identifier !== undefined && !bound.has(identifier)) return undefined;
        return { line };
      });
    }
  },
  {
    kind: 'block',
    id: 'agnostic/cors-wildcard-credentials',
    group: 'hardening',
    frameworks: ['agnostic'],
    severity: 'high',
    confidence: 'certain',
    message:
      'CORS allows every origin and also allows credentials, so any site can make authenticated requests as your logged-in users. Name the origins you trust, or drop credentials.',
    find: (file) =>
      forEachBlock(file, CORS_TRIGGER, (blockText, line) =>
        WILDCARD_ORIGIN.test(blockText) && CREDENTIALS_ON.test(blockText) ? { line } : undefined
      )
  },
  {
    kind: 'block',
    id: 'agnostic/no-rate-limit-on-auth',
    group: 'auth',
    frameworks: ['agnostic'],
    severity: 'medium',
    confidence: 'heuristic',
    message:
      'This looks like a sign-in or sign-up handler with no rate limiting, which leaves passwords open to being guessed in bulk. Add a per-IP and per-account limit.',
    find: (file) => {
      if (!AUTH_ENDPOINT.test(file.path)) return [];
      return forEachBlock(file, AUTH_HANDLER, (blockText, line) =>
        RATE_LIMIT_EVIDENCE.test(blockText) || RATE_LIMIT_EVIDENCE.test(file.content)
          ? { line, resolved: 'drop' }
          : { line, resolved: { severity: 'medium' } }
      );
    }
  }
];
