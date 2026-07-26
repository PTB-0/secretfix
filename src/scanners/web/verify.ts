import type { Resolution, ScanContext } from './types.js';

/**
 * Calls that constitute proof somebody checked who is asking. Deliberately
 * generous: a false "auth is present" costs us a missed finding, while a false
 * "auth is absent" costs a blocked commit on correct code — and that is what
 * gets the tool uninstalled.
 */
const AUTH_CALLS =
  /\b(?:auth|getServerSession|getSession|requireAuth|requireUser|requireSession|currentUser|getCurrentUser|verifyToken|verifyJwt|getToken|authorize|isAuthenticated)\s*\(|\bsession\s*\??\.\s*user\b|\bsupabase\s*\.\s*auth\s*\.\s*getUser\b|\bclerkClient\b/;

/** `export const POST = withAuth(...)` and friends. */
const AUTH_WRAPPER = /=\s*(?:with[A-Z]\w*|require[A-Z]\w*|protected?|authed?|guard\w*)\s*\(/;

/** A write is a risk signal: an unauthenticated read is bad, an unauthenticated write is worse. */
const WRITE_CALLS =
  /\.(?:create|createMany|update|updateMany|updateOne|upsert|delete|deleteMany|deleteOne|insert|insertOne|save|destroy)\s*\(|\b(?:INSERT\s+INTO|UPDATE\s+\w|DELETE\s+FROM)/i;

const STATE_CHANGING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

const MIDDLEWARE_FILES = ['middleware.ts', 'middleware.js', 'src/middleware.ts', 'src/middleware.js'] as const;

/**
 * Derives the URL path a route file serves.
 *   app/api/admin/users/route.ts  -> /api/admin/users
 *   app/(dash)/api/billing/route.ts -> /api/billing   (route groups are not URL segments)
 *   app/api/posts/[id]/route.ts   -> /api/posts/*     (dynamic segments become wildcards)
 *   pages/api/login.ts            -> /api/login
 */
export function routePathFor(filePath: string): string {
  let path = filePath.replace(/\\/g, '/');
  path = path.replace(/^src\//, '');
  path = path.replace(/^(?:app|pages)\//, '');
  path = path.replace(/\/route\.[cm]?[jt]sx?$/, '');
  path = path.replace(/\.[cm]?[jt]sx?$/, '');
  path = path.replace(/\((?:[^/)]*)\)\//g, ''); // route groups
  path = path.replace(/\[\[?(?:\.{3})?\w+\]?\]/g, '*'); // [id], [...slug], [[...slug]]
  path = path.replace(/\/index$/, '');
  return `/${path}`.replace(/\/{2,}/g, '/');
}

/** Path-to-regexp style uses only these; anything else means the author wrote a regex. */
const PATH_STYLE_MATCHER = /^[\w\-./:*]*$/;

/**
 * Stands in for a wildcard until the very end. Emitting `.*` mid-chain lets a
 * later step re-expand its `*`, which is how `/admin/:path*` used to compile to
 * `^/admin/..*$` and stop covering `/admin` at all.
 */
const WILDCARD = '\0';

/**
 * Next.js accepts two matcher dialects: path-to-regexp (`/api/admin/:path*`) and a
 * literal regex string (`/((?!api|_next/static).*)`, its own default). Escaping the
 * second dialect would make it match nothing, and a matcher that matches nothing
 * reads as "middleware protects no routes" — which turns an advisory into a blocked
 * commit on correctly authenticated code.
 */
function matcherToRegex(matcher: string): RegExp {
  if (!PATH_STYLE_MATCHER.test(matcher)) {
    try {
      return new RegExp(`^${matcher}$`);
    } catch {
      // An unparseable matcher is not evidence of anything. Cover everything, so
      // the finding is dropped rather than raised on a guess.
      return /.*/;
    }
  }

  const escaped = matcher
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\\\[[^\]]*\\\]/g, '[^/]+')
    // `/:param*` is zero or more segments, so the slash is optional: this pattern
    // has to cover the bare prefix (`/admin`) as well as `/admin/a/b`.
    .replace(/\/:\w+\*/g, `(?:/${WILDCARD})?`)
    .replace(/:\w+\*/g, WILDCARD)
    .replace(/:\w+/g, '[^/]+')
    .replace(/\*/g, WILDCARD)
    .split(WILDCARD)
    .join('.*');
  return new RegExp(`^${escaped}$`);
}

/**
 * Extracts the string literals inside a `matcher: [...]` or `matcher: '...'` config
 * block from raw file content. Exported because two callers need it: middleware
 * coverage here, and the standalone matcher-gap rule, which reads the same shape
 * out of the staged middleware file rather than a file `readRepoFile` fetches.
 * Undefined means no matcher config was found at all — distinct from an empty
 * array — which callers read as "runs on every request."
 */
export function matcherPatterns(content: string): string[] | undefined {
  const matcherBlock = /matcher\s*:\s*(\[[^\]]*\]|['"][^'"]*['"])/.exec(content);
  if (matcherBlock === null) return undefined;
  return [...matcherBlock[1].matchAll(/['"]([^'"]+)['"]/g)].map((match) => match[1]);
}

/**
 * True when any matcher pattern — in either Next.js dialect, see matcherToRegex
 * above — matches `path`. Exported alongside matcherPatterns so a rule outside
 * this module never has to re-implement matcher semantics to answer "does this
 * middleware cover that route."
 */
export function matcherCovers(patterns: readonly string[], path: string): boolean {
  return patterns.some((pattern) => matcherToRegex(pattern).test(path));
}

function middlewareCovers(routePath: string, context: ScanContext): boolean {
  for (const file of MIDDLEWARE_FILES) {
    const content = context.readRepoFile(file);
    if (content === undefined) continue;

    const patterns = matcherPatterns(content);
    // Middleware with no matcher runs on every request, so it covers this route.
    if (patterns === undefined) return true;

    if (matcherCovers(patterns, routePath)) return true;
  }
  return false;
}

export function hasAuthEvidence(blockText: string, filePath: string, context: ScanContext): boolean {
  if (AUTH_CALLS.test(blockText) || AUTH_WRAPPER.test(blockText)) return true;
  return middlewareCovers(routePathFor(filePath), context);
}

export function hasRiskSignal(blockText: string, filePath: string, method?: string): boolean {
  if (/(^|\/)(?:admin|internal|_admin)(\/|$)/.test(routePathFor(filePath))) return true;
  if (method !== undefined && STATE_CHANGING_METHODS.has(method.toUpperCase())) return true;
  return WRITE_CALLS.test(blockText);
}

/**
 * The three-way outcome for an auth heuristic. Evidence wins outright; without
 * it, a risk signal is what separates "block this" from "mention this".
 */
export function resolveAuth(
  blockText: string,
  filePath: string,
  context: ScanContext,
  method?: string
): Resolution {
  if (hasAuthEvidence(blockText, filePath, context)) return 'drop';
  return hasRiskSignal(blockText, filePath, method) ? { severity: 'high' } : { severity: 'medium' };
}

/**
 * Locals bound to the whole request body — `const body = await req.json()`.
 * A destructured read (`const { name } = await req.json()`) is deliberately not
 * collected: naming the fields is the safe pattern we want people to use.
 */
export function requestBoundLocals(content: string): Set<string> {
  const names = new Set<string>();
  const pattern =
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?req(?:uest)?\s*\.\s*(?:body\b|json\s*\(\s*\))/g;

  for (const match of content.matchAll(pattern)) {
    names.add(match[1]);
  }
  return names;
}
