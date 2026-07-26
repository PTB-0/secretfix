import { describe, it, expect } from 'vitest';
import {
  hasAuthEvidence,
  hasRiskSignal,
  matcherCovers,
  requestBoundLocals,
  resolveAuth,
  routePathFor
} from '../../../src/scanners/web/verify.js';
import type { ScanContext } from '../../../src/scanners/web/types.js';

function contextWith(files: Record<string, string> = {}): ScanContext {
  return { cwd: '/repo', frameworks: new Set(['agnostic', 'nextjs']), readRepoFile: (path) => files[path] };
}

describe('routePathFor', () => {
  it.each([
    ['app/api/admin/users/route.ts', '/api/admin/users'],
    ['src/app/api/posts/route.ts', '/api/posts'],
    ['app/(dashboard)/api/billing/route.ts', '/api/billing'],
    ['app/api/posts/[id]/route.ts', '/api/posts/*'],
    ['app/api/posts/[...slug]/route.ts', '/api/posts/*'],
    ['app/api/posts/[[...slug]]/route.ts', '/api/posts/*'],
    ['pages/api/login.ts', '/api/login']
  ])('maps %s to %s', (filePath, expected) => {
    expect(routePathFor(filePath)).toBe(expected);
  });
});

describe('hasAuthEvidence', () => {
  it.each([
    ['a session lookup', 'const session = await getServerSession(authOptions);'],
    ['an auth() call', 'const { userId } = await auth();'],
    ['a requireUser helper', 'const user = requireUser(req);'],
    ['a supabase user lookup', 'const { data } = await supabase.auth.getUser();'],
    ['a session.user read', 'if (!session.user) return unauthorized();'],
    ['a wrapped handler', 'export const POST = withAuth(async (req) => { return ok(); });']
  ])('accepts %s', (_label, blockText) => {
    expect(hasAuthEvidence(blockText, 'app/api/x/route.ts', contextWith())).toBe(true);
  });

  it('rejects a handler with no auth call at all', () => {
    const block = 'export async function POST(req) {\n  const body = await req.json();\n  return ok(body);\n}';
    expect(hasAuthEvidence(block, 'app/api/x/route.ts', contextWith())).toBe(false);
  });

  it('accepts a route a middleware matcher covers', () => {
    const middleware = "export const config = { matcher: ['/api/admin/:path*'] };";
    const context = contextWith({ 'middleware.ts': middleware });
    expect(hasAuthEvidence('return ok();', 'app/api/admin/users/route.ts', context)).toBe(true);
  });

  it('rejects a route the middleware matcher misses', () => {
    const middleware = "export const config = { matcher: ['/dashboard/:path*'] };";
    const context = contextWith({ 'middleware.ts': middleware });
    expect(hasAuthEvidence('return ok();', 'app/api/admin/users/route.ts', context)).toBe(false);
  });

  it('rejects when there is no middleware file', () => {
    expect(hasAuthEvidence('return ok();', 'app/api/admin/users/route.ts', contextWith())).toBe(false);
  });

  describe('middleware matcher dialects', () => {
    // Next.js accepts a literal-regex matcher as well as path-to-regexp. Escaping
    // it like a path-to-regexp string would mangle it into matching nothing, which
    // silently turns every route it actually covers into a blocked commit.
    it("covers a route under Next.js's own default regex-dialect matcher, and rejects the prefix it excludes", () => {
      const middleware =
        "export const config = { matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'] };";
      const context = contextWith({ 'middleware.ts': middleware });
      expect(hasAuthEvidence('return ok();', 'app/dashboard/route.ts', context)).toBe(true);
      expect(hasAuthEvidence('return ok();', 'app/api/admin/users/route.ts', context)).toBe(false);
    });

    it('covers routes under an alternation regex-dialect matcher, and rejects a path outside the alternation', () => {
      const middleware = "export const config = { matcher: ['/(api|trpc)(.*)'] };";
      const context = contextWith({ 'middleware.ts': middleware });
      expect(hasAuthEvidence('return ok();', 'app/api/foo/route.ts', context)).toBe(true);
      expect(hasAuthEvidence('return ok();', 'app/trpc/bar/route.ts', context)).toBe(true);
      expect(hasAuthEvidence('return ok();', 'app/dashboard/route.ts', context)).toBe(false);
    });

    it('still handles the path-to-regexp dialect: a single dynamic segment', () => {
      const middleware = "export const config = { matcher: ['/api/admin/:id'] };";
      const context = contextWith({ 'middleware.ts': middleware });
      expect(hasAuthEvidence('return ok();', 'app/api/admin/users/route.ts', context)).toBe(true);
    });

    it('still handles the path-to-regexp dialect: a wildcard segment', () => {
      const middleware = "export const config = { matcher: ['/api/admin/:path*'] };";
      const context = contextWith({ 'middleware.ts': middleware });
      expect(hasAuthEvidence('return ok();', 'app/api/admin/users/route.ts', context)).toBe(true);
    });

    it('still handles the path-to-regexp dialect: a plain literal path', () => {
      const middleware = "export const config = { matcher: ['/dashboard'] };";
      const context = contextWith({ 'middleware.ts': middleware });
      expect(hasAuthEvidence('return ok();', 'app/dashboard/route.ts', context)).toBe(true);
    });

    it('still handles the path-to-regexp dialect: the root path matches only the root, not every path', () => {
      const middleware = "export const config = { matcher: ['/'] };";
      const context = contextWith({ 'middleware.ts': middleware });
      expect(hasAuthEvidence('return ok();', 'app/dashboard/route.ts', context)).toBe(false);
      expect(hasAuthEvidence('return ok();', 'app/api/admin/users/route.ts', context)).toBe(false);
    });

    it('treats a syntactically invalid regex-dialect matcher as covering everything, rather than throwing', () => {
      const middleware = "export const config = { matcher: ['/[unclosed'] };";
      const context = contextWith({ 'middleware.ts': middleware });
      expect(() => hasAuthEvidence('return ok();', 'app/api/admin/users/route.ts', context)).not.toThrow();
      expect(hasAuthEvidence('return ok();', 'app/api/admin/users/route.ts', context)).toBe(true);
    });
  });
});

describe('matcherCovers', () => {
  // `:path*` is zero-or-more segments in path-to-regexp, so the segment and its
  // leading slash are both optional — a bare prefix must count as covered, not
  // just prefix-plus-something. Every prior assertion paired `:path*` with a route
  // that had a subpath, so this exact gap slipped through Task 5 untested.
  it('a wildcard segment covers the bare prefix as well as a subpath', () => {
    expect(matcherCovers(['/admin/:path*'], '/admin')).toBe(true);
    expect(matcherCovers(['/admin/:path*'], '/admin/users')).toBe(true);
  });

  it('a wildcard segment covers the bare prefix and a subpath, and still excludes an unrelated path', () => {
    expect(matcherCovers(['/api/admin/:path*'], '/api/admin')).toBe(true);
    expect(matcherCovers(['/api/admin/:path*'], '/api/admin/users')).toBe(true);
    expect(matcherCovers(['/api/admin/:path*'], '/dashboard')).toBe(false);
  });

  it('a single dynamic segment is exactly one segment, not zero-or-more, so it does not cover the bare prefix', () => {
    expect(matcherCovers(['/api/admin/:id'], '/api/admin')).toBe(false);
  });
});

describe('hasRiskSignal', () => {
  it('flags an admin path', () => {
    expect(hasRiskSignal('return ok();', 'app/api/admin/users/route.ts')).toBe(true);
  });

  it('flags a state-changing method', () => {
    expect(hasRiskSignal('return ok();', 'app/api/notes/route.ts', 'DELETE')).toBe(true);
  });

  it('flags a database write in the body', () => {
    expect(hasRiskSignal('await prisma.note.delete({ where: { id } });', 'app/api/notes/route.ts', 'GET')).toBe(true);
  });

  it('does not flag a read-only GET on an ordinary path', () => {
    expect(hasRiskSignal('const notes = await prisma.note.findMany();', 'app/api/notes/route.ts', 'GET')).toBe(false);
  });
});

describe('resolveAuth', () => {
  it('drops the finding when auth evidence exists', () => {
    expect(resolveAuth('const { userId } = await auth();', 'app/api/x/route.ts', contextWith(), 'POST')).toBe('drop');
  });

  it('blocks when there is no evidence and the route is risky', () => {
    expect(resolveAuth('return ok();', 'app/api/admin/x/route.ts', contextWith(), 'POST')).toEqual({ severity: 'high' });
  });

  it('advises when there is neither evidence nor a risk signal', () => {
    expect(resolveAuth('return ok();', 'app/api/x/route.ts', contextWith(), 'GET')).toEqual({ severity: 'medium' });
  });
});

describe('requestBoundLocals', () => {
  it.each([
    ['const body = await req.json();', 'body'],
    ['const payload = request.body;', 'payload'],
    ['let input = await request.json();', 'input']
  ])('binds %s', (source, name) => {
    expect(requestBoundLocals(source).has(name)).toBe(true);
  });

  it('does not bind a destructured read, which names its fields explicitly', () => {
    expect(requestBoundLocals('const { name, bio } = await req.json();').size).toBe(0);
  });

  it('does not bind an unrelated local', () => {
    expect(requestBoundLocals('const total = price * qty;').size).toBe(0);
  });
});
