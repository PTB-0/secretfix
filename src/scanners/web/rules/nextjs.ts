import { forEachBlock } from '../block.js';
import { matcherCovers, matcherPatterns, resolveAuth, routePathFor } from '../verify.js';
import type { Hit, ScanContext, WebRule } from '../types.js';

/**
 * A NEXT_PUBLIC_ variable whose name reads like a credential. The negative
 * lookahead spares the keys that are *designed* to be public — a Stripe
 * publishable key, a Supabase anon key, an OAuth client id — because flagging
 * those is the fastest way to teach people to ignore this rule.
 */
const PUBLIC_ENV_SECRET =
  /\bNEXT_PUBLIC_(?!\w*(?:PUBLISHABLE|ANON|CLIENT_ID))\w*(?:SECRET|_KEY|TOKEN|PASSWORD|PASSWD|PRIVATE|CREDENTIAL)\w*/i;

const SERVICE_ROLE_KEY = /service_role|SERVICE_ROLE_KEY|supabaseAdmin|SUPABASE_SECRET/i;
const USE_CLIENT = /^\s*['"]use client['"]/m;
const USE_SERVER = /^\s*['"]use server['"]/m;

const ROUTE_FILE = /(?:^|\/)route\.[cm]?[jt]sx?$/;
const ROUTE_HANDLER = /export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b|export\s+const\s+(GET|POST|PUT|PATCH|DELETE)\s*=/;
const EXPORTED_ASYNC_FUNCTION = /export\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/;

const DOMAINS_ARRAY = /(domains\s*:\s*)\[([^\]]*)\]/;
/** A comma-separated list of plain quoted strings, optionally with a trailing comma. */
const SIMPLE_STRING_LIST = /^\s*(?:(?:'[^']*'|"[^"]*")\s*,\s*)*(?:'[^']*'|"[^"]*")?\s*$/;

/**
 * Removes just the wildcard entry from a `domains: [...]` array, leaving
 * every other host in place. Declines (returns undefined) unless every
 * entry in the array is a plain quoted string — a spread, an expression,
 * or a `process.env.X` reference is not something this can safely
 * re-serialize on one line — and also when the array turns out to hold no
 * wildcard entry after all.
 */
function domainsWildcardFix(line: string): string | undefined {
  const match = DOMAINS_ARRAY.exec(line);
  if (match === null) return undefined;

  const inner = match[2];
  if (!SIMPLE_STRING_LIST.test(inner)) return undefined;

  const entries = inner.match(/'[^']*'|"[^"]*"/g) ?? [];
  const kept = entries.filter((entry) => entry !== "'*'" && entry !== '"*"');
  if (kept.length === entries.length) return undefined;

  const rebuilt = `[${kept.join(', ')}]`;
  return `${line.slice(0, match.index)}${match[1]}${rebuilt}${line.slice(match.index + match[0].length)}`;
}

const NEXT_CONFIG = /(?:^|\/)next\.config\.[cm]?[jt]s$/;
const MIDDLEWARE_FILE = /(?:^|\/)middleware\.[cm]?[jt]s$/;
const HEADERS_BLOCK = /\bheaders\s*\(\s*\)|\bheaders\s*:\s*(?:async\s*)?\(/;

/** Conventional locations for an admin surface, used by the matcher-gap rule. */
const ADMIN_ROUTE_FILES: ReadonlyArray<readonly [string, string]> = [
  ['app/admin/page.tsx', '/admin'],
  ['src/app/admin/page.tsx', '/admin'],
  ['app/api/admin/route.ts', '/api/admin'],
  ['src/app/api/admin/route.ts', '/api/admin'],
  ['pages/admin/index.tsx', '/admin']
];

export const NEXTJS_RULES: readonly WebRule[] = [
  {
    kind: 'line',
    id: 'nextjs/public-env-secret',
    group: 'exposure',
    frameworks: ['nextjs'],
    severity: 'critical',
    confidence: 'certain',
    regex: PUBLIC_ENV_SECRET,
    message:
      'NEXT_PUBLIC_ variables are compiled into the browser bundle, so anyone who opens the site can read this value. Drop the NEXT_PUBLIC_ prefix and read it server-side only, then rotate the key — assume the current one is burned.'
  },
  {
    kind: 'block',
    id: 'nextjs/service-role-key-in-client',
    group: 'exposure',
    frameworks: ['nextjs', 'supabase'],
    severity: 'critical',
    confidence: 'certain',
    message:
      'This file runs in the browser and references a service-role key, which bypasses every row-level security policy you have. Move the call to a server component, route handler or server action.',
    find: (file) => {
      if (!USE_CLIENT.test(file.content)) return [];
      const hits: Hit[] = [];
      file.content.split('\n').forEach((line, index) => {
        if (SERVICE_ROLE_KEY.test(line)) hits.push({ line: index + 1 });
      });
      return hits;
    }
  },
  {
    kind: 'block',
    id: 'nextjs/route-handler-no-auth',
    group: 'auth',
    frameworks: ['nextjs'],
    severity: 'high',
    confidence: 'heuristic',
    message:
      'This route handler has no auth check, and none of your middleware covers its path. Anyone who knows the URL can call it. If it is meant to be public, silence this line.',
    find: (file, context: ScanContext) => {
      if (!ROUTE_FILE.test(file.path)) return [];
      return forEachBlock(file, ROUTE_HANDLER, (blockText, line, match) => ({
        line,
        detail: `— ${match[1] ?? match[2]} ${routePathFor(file.path)}`,
        resolved: resolveAuth(blockText, file.path, context, match[1] ?? match[2])
      }));
    }
  },
  {
    kind: 'block',
    id: 'nextjs/server-action-no-auth',
    group: 'auth',
    frameworks: ['nextjs'],
    severity: 'high',
    confidence: 'heuristic',
    message:
      'A server action is a public endpoint: the client can call it directly, whatever the UI shows. This one has no auth check, so add one inside the action itself.',
    find: (file, context: ScanContext) => {
      if (!USE_SERVER.test(file.content)) return [];
      return forEachBlock(file, EXPORTED_ASYNC_FUNCTION, (blockText, line, match) => ({
        line,
        detail: `— ${match[1]}()`,
        // A server action is always a POST, so treat it as state-changing.
        resolved: resolveAuth(blockText, file.path, context, 'POST')
      }));
    }
  },
  {
    kind: 'file',
    id: 'nextjs/missing-security-headers',
    group: 'hardening',
    frameworks: ['nextjs'],
    severity: 'high',
    confidence: 'certain',
    appliesTo: NEXT_CONFIG,
    message:
      'No security headers are configured. Without a Content-Security-Policy your site has no defence-in-depth against injected scripts, and without Strict-Transport-Security and X-Frame-Options it can be downgraded or framed.',
    check: (file) =>
      HEADERS_BLOCK.test(file.content)
        ? []
        : [{ line: 1, fix: { kind: 'add-security-headers', file: file.path } }]
  },
  {
    kind: 'file',
    id: 'nextjs/middleware-matcher-gap',
    group: 'auth',
    frameworks: ['nextjs'],
    severity: 'high',
    confidence: 'heuristic',
    appliesTo: MIDDLEWARE_FILE,
    message:
      'Your middleware matcher does not cover an admin route that exists in this project, so whatever the middleware enforces is simply not applied there.',
    check: (file, context) => {
      const patterns = matcherPatterns(file.content);
      // No matcher means the middleware runs everywhere — nothing to leave uncovered.
      if (patterns === undefined || patterns.length === 0) return [];

      const uncovered = ADMIN_ROUTE_FILES.filter(
        ([path, url]) => context.readRepoFile(path) !== undefined && !matcherCovers(patterns, url)
      );
      if (uncovered.length === 0) return [];

      return [
        {
          line: 1,
          detail: `— ${uncovered.map(([, url]) => url).join(', ')} not matched`,
          resolved: { severity: 'high' as const }
        }
      ];
    }
  },
  {
    kind: 'line',
    id: 'nextjs/images-wildcard',
    group: 'hardening',
    frameworks: ['nextjs'],
    severity: 'medium',
    confidence: 'certain',
    regex: /domains\s*:\s*\[[^\]]*['"]\*['"]|hostname\s*:\s*['"]\*\*?['"]/,
    message:
      'The image optimiser will fetch from any host, which turns your server into an open image proxy others can run their bandwidth through. List the hosts you actually serve images from.',
    fix: (line, lineNumber, file) => {
      // Only the domains-array form has an unambiguous rewrite at all;
      // pruning one entry from remotePatterns is not a line edit.
      const replacement = domainsWildcardFix(line);
      return replacement === undefined
        ? undefined
        : { kind: 'replace-line', file: file.path, line: lineNumber, replacement, rewrite: true };
    }
  },
  {
    kind: 'line',
    id: 'nextjs/dangerous-rewrite',
    group: 'hardening',
    frameworks: ['nextjs'],
    severity: 'high',
    confidence: 'certain',
    regex: /destination\s*:\s*['"`]https?:\/\/(?::\w+|\$\{)/,
    message:
      'The rewrite destination host comes from the incoming request, so this route is an open proxy: anyone can make your server fetch arbitrary URLs, including ones inside your own network. Hard-code the host.'
  }
];
