import { describe, it, expect } from 'vitest';
import {
  hasAuthEvidence,
  hasRiskSignal,
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
