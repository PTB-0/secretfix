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
const AUTH_WRAPPER = /=\s*(?:with[A-Z]\w*|require[A-Z]\w*|protected?|authed?|guard)\s*\(/;

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
  path = path.replace(/\[\[?\.{3}?\w+\]?\]/g, '*'); // [id], [...slug], [[...slug]]
  path = path.replace(/\/index$/, '');
  return `/${path}`.replace(/\/{2,}/g, '/');
}

/** Turns a Next.js middleware matcher into a regex over URL paths. */
function matcherToRegex(matcher: string): RegExp {
  const escaped = matcher
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\\\[[^\]]*\\\]/g, '[^/]+')
    .replace(/:\w+\*/g, '.*')
    .replace(/:\w+/g, '[^/]+')
    .replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`);
}

function middlewareCovers(routePath: string, context: ScanContext): boolean {
  for (const file of MIDDLEWARE_FILES) {
    const content = context.readRepoFile(file);
    if (content === undefined) continue;

    const matcherBlock = /matcher\s*:\s*(\[[^\]]*\]|['"][^'"]*['"])/.exec(content);
    if (matcherBlock === null) {
      // Middleware with no matcher runs on every request, so it covers this route.
      return true;
    }

    const patterns = [...matcherBlock[1].matchAll(/['"]([^'"]+)['"]/g)].map((match) => match[1]);
    if (patterns.some((pattern) => matcherToRegex(pattern).test(routePath))) return true;
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
