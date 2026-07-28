import { forEachBlock } from '../block.js';
import { resolveAuth } from '../verify.js';
import type { WebRule } from '../types.js';

const STATIC_PROJECT_ROOT =
  /express\.static\s*\(\s*(?:__dirname\s*\)|process\.cwd\s*\(\s*\)\s*\)|['"]\.\/?['"]|path\.(?:join|resolve)\s*\(\s*__dirname\s*,\s*['"]\.\.)/;

/** Conventional app-entry filenames; the helmet rule anchors to these. */
const APP_ENTRY = /(?:^|\/)(?:app|server|index)\.[cm]?[jt]s$/;
const EXPRESS_APP = /\bexpress\s*\(\s*\)/;
const HELMET = /\bhelmet\b/;

const STATE_CHANGING_ROUTE = /\b(?:app|router)\.(post|put|patch|delete)\s*\(/;
const GLOBAL_AUTH_MIDDLEWARE =
  /\b(?:app|router)\.use\s*\(\s*[^)]*(?:requireAuth|requireUser|ensureLoggedIn|isAuthenticated|passport\.authenticate|authMiddleware|authenticate)\b/i;

const COOKIE_SESSION = /\b(?:express-session|cookie-session|cookieParser|cookie-parser)\b/;
const CSRF_EVIDENCE = /\b(?:csurf|csrf|doubleCsrf|csrfProtection|csrfSync|lusca)\b/i;

export const EXPRESS_RULES: readonly WebRule[] = [
  {
    kind: 'line',
    id: 'express/static-serves-project-root',
    group: 'exposure',
    frameworks: ['express'],
    severity: 'critical',
    confidence: 'certain',
    regex: STATIC_PROJECT_ROOT,
    message:
      'This serves your entire project directory as static files, so anyone can fetch /.env, /package.json or your source. Serve a dedicated directory such as "public" instead.',
    fix: (line, lineNumber, file) => {
      const replacement = line
        .replace(/express\.static\s*\(\s*path\.(join|resolve)\s*\(\s*__dirname\s*,\s*['"]\.\.['"]\s*\)/, (match) =>
          match.replace(/['"]\.\.['"]/, "'public'")
        )
        .replace(/express\.static\s*\(\s*(?:__dirname|process\.cwd\s*\(\s*\)|['"]\.\/?['"])\s*\)/, "express.static('public')");

      return replacement === line
        ? undefined
        : { kind: 'replace-line', file: file.path, line: lineNumber, replacement, rewrite: true };
    }
  },
  {
    kind: 'file',
    id: 'express/no-helmet',
    group: 'hardening',
    frameworks: ['express'],
    severity: 'medium',
    confidence: 'certain',
    appliesTo: APP_ENTRY,
    message:
      'This app sets no security headers. Install helmet ("pnpm add helmet") and mount it with app.use(helmet()) before your routes — it sets Content-Security-Policy, HSTS, X-Frame-Options and several others in one line.',
    check: (file) => (EXPRESS_APP.test(file.content) && !HELMET.test(file.content) ? [{ line: 1 }] : [])
  },
  {
    kind: 'block',
    id: 'express/route-no-auth',
    group: 'auth',
    frameworks: ['express'],
    severity: 'high',
    confidence: 'heuristic',
    message:
      'This route changes state and has no auth check, and no auth middleware is mounted on the app. Anyone who knows the URL can call it.',
    find: (file, context) => {
      // A global auth middleware protects every route below it, so one
      // app.use(requireAuth) is evidence for the whole file.
      if (GLOBAL_AUTH_MIDDLEWARE.test(file.content)) return [];

      return forEachBlock(file, STATE_CHANGING_ROUTE, (blockText, line, match) => ({
        line,
        detail: `— ${match[1].toUpperCase()}`,
        resolved: resolveAuth(blockText, file.path, context, match[1])
      }));
    }
  },
  {
    kind: 'block',
    id: 'express/csrf-missing',
    group: 'auth',
    frameworks: ['express'],
    severity: 'medium',
    confidence: 'heuristic',
    message:
      'This app authenticates with cookies and has state-changing routes but no CSRF protection, so another site can make your logged-in users submit requests without knowing it. Add a CSRF token check, or use SameSite=Strict cookies plus an origin check.',
    find: (file) => {
      // Only cookie-authenticated apps are vulnerable; a bearer-token API is not.
      if (!COOKIE_SESSION.test(file.content)) return [];
      if (CSRF_EVIDENCE.test(file.content)) return [];

      return forEachBlock(file, STATE_CHANGING_ROUTE, (_blockText, line, match) => ({
        line,
        detail: `— ${match[1].toUpperCase()}`,
        resolved: { severity: 'medium' as const }
      }));
    }
  }
];
