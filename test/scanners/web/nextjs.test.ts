import { describe, it, expect } from 'vitest';
import { createWebScanner } from '../../../src/scanners/web/index.js';
import { NEXTJS_RULES } from '../../../src/scanners/web/rules/nextjs.js';
import type { ScanContext } from '../../../src/scanners/web/types.js';

function contextWith(files: Record<string, string> = {}): ScanContext {
  return { cwd: '/repo', frameworks: new Set(['agnostic', 'nextjs']), readRepoFile: (path) => files[path] };
}

/** Only the Next.js rules, so agnostic hits do not muddy the assertions. */
async function findings(content: string, path: string, files?: Record<string, string>) {
  return createWebScanner(contextWith(files), NEXTJS_RULES).scan([{ path, content }]);
}

async function ids(content: string, path: string, files?: Record<string, string>): Promise<string[]> {
  return (await findings(content, path, files)).map((f) => f.message.match(/\[([^\]]+)\]/)?.[1] ?? '');
}

describe('Next.js web rules', () => {
  it.each([
    ['a secret-shaped public env var', 'NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_x', '.env.local'],
    ['a public API key', 'NEXT_PUBLIC_API_KEY=abc', '.env'],
    ['a public token', 'const t = process.env.NEXT_PUBLIC_ADMIN_TOKEN;', 'lib/api.ts']
  ])('flags %s', async (_label, content, path) => {
    expect(await ids(content, path)).toContain('nextjs/public-env-secret');
  });

  it.each([
    ['a Stripe publishable key', 'NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_x'],
    ['a Supabase anon key', 'NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGci'],
    ['an OAuth client id', 'NEXT_PUBLIC_GOOGLE_CLIENT_ID=123.apps.googleusercontent.com'],
    ['a plain public var', 'NEXT_PUBLIC_SITE_URL=https://example.com']
  ])('does not flag %s', async (_label, content) => {
    expect(await ids(content, '.env')).not.toContain('nextjs/public-env-secret');
  });

  it('flags a service-role key used in a client component', async () => {
    const content = "'use client';\nconst admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);";
    expect(await ids(content, 'app/admin/page.tsx')).toContain('nextjs/service-role-key-in-client');
  });

  it('does not flag a service-role key in a server file', async () => {
    const content = 'const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);';
    expect(await ids(content, 'lib/admin.ts')).not.toContain('nextjs/service-role-key-in-client');
  });

  it('blocks an admin route handler with no auth check', async () => {
    const content = 'export async function POST(req) {\n  const body = await req.json();\n  return save(body);\n}';
    const [finding] = await findings(content, 'app/api/admin/users/route.ts');
    expect(finding.severity).toBe('high');
  });

  it('advises a plain GET route handler with no auth check', async () => {
    const content = 'export async function GET() {\n  return list();\n}';
    const [finding] = await findings(content, 'app/api/posts/route.ts');
    expect(finding.severity).toBe('medium');
  });

  it('reports nothing when the handler checks auth itself', async () => {
    const content =
      'export async function POST(req) {\n  const { userId } = await auth();\n  if (!userId) return unauthorized();\n  return save(await req.json());\n}';
    expect(await ids(content, 'app/api/admin/users/route.ts')).not.toContain('nextjs/route-handler-no-auth');
  });

  it('reports nothing when middleware covers the route', async () => {
    const content = 'export async function POST(req) {\n  return save(await req.json());\n}';
    const files = { 'middleware.ts': "export const config = { matcher: ['/api/admin/:path*'] };" };
    expect(await ids(content, 'app/api/admin/users/route.ts', files)).not.toContain('nextjs/route-handler-no-auth');
  });

  it('blocks a server action with no auth check', async () => {
    const content = "'use server';\nexport async function deletePost(id) {\n  await prisma.post.delete({ where: { id } });\n}";
    const [finding] = await findings(content, 'app/actions.ts');
    expect(finding.severity).toBe('high');
  });

  it('reports nothing for a server action that checks auth', async () => {
    const content =
      "'use server';\nexport async function deletePost(id) {\n  const session = await getServerSession();\n  if (!session.user) throw new Error('no');\n  await prisma.post.delete({ where: { id } });\n}";
    expect(await ids(content, 'app/actions.ts')).not.toContain('nextjs/server-action-no-auth');
  });

  it('flags a next config with no security headers', async () => {
    expect(await ids('export default { reactStrictMode: true };', 'next.config.mjs')).toContain(
      'nextjs/missing-security-headers'
    );
  });

  it('attaches an add-security-headers fix to a config with no headers', async () => {
    const [finding] = await findings('export default { reactStrictMode: true };', 'next.config.mjs');
    expect(finding.fix).toEqual({ kind: 'add-security-headers', file: 'next.config.mjs' });
  });

  it('does not flag a next config that already sets headers', async () => {
    const content = 'export default {\n  async headers() {\n    return [];\n  },\n};';
    expect(await ids(content, 'next.config.mjs')).not.toContain('nextjs/missing-security-headers');
  });

  it('does not run the headers rule when the config is not staged', async () => {
    expect(await ids('export default {};', 'lib/other.ts')).not.toContain('nextjs/missing-security-headers');
  });

  it('flags a middleware matcher that leaves an existing admin route uncovered', async () => {
    const content = "export const config = { matcher: ['/dashboard/:path*'] };";
    const files = { 'app/admin/page.tsx': 'export default function Page() { return null; }' };
    expect(await ids(content, 'middleware.ts', files)).toContain('nextjs/middleware-matcher-gap');
  });

  it('does not flag a middleware matcher that covers the admin route', async () => {
    const content = "export const config = { matcher: ['/admin/:path*'] };";
    const files = { 'app/admin/page.tsx': 'export default function Page() { return null; }' };
    expect(await ids(content, 'middleware.ts', files)).not.toContain('nextjs/middleware-matcher-gap');
  });

  it('does not flag a middleware matcher when the project has no admin route', async () => {
    const content = "export const config = { matcher: ['/dashboard/:path*'] };";
    expect(await ids(content, 'middleware.ts')).not.toContain('nextjs/middleware-matcher-gap');
  });

  it.each([
    ['a wildcard image domain', "export default { images: { domains: ['*'] } };", 'nextjs/images-wildcard'],
    ['a wildcard remote pattern', "export default { images: { remotePatterns: [{ hostname: '**' }] } };", 'nextjs/images-wildcard'],
    ['a proxying rewrite', "destination: 'https://:host/:path*',", 'nextjs/dangerous-rewrite']
  ])('flags %s', async (_label, content, id) => {
    expect(await ids(content, 'next.config.mjs')).toContain(id);
  });

  it.each([
    ['a named image domain', "export default { images: { domains: ['cdn.example.com'] } };"],
    ['a fixed rewrite destination', "destination: 'https://api.example.com/v1/:path*',"]
  ])('does not flag %s', async (_label, content) => {
    const reported = await ids(content, 'next.config.mjs');
    expect(reported).not.toContain('nextjs/images-wildcard');
    expect(reported).not.toContain('nextjs/dangerous-rewrite');
  });
});
