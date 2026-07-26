import { describe, it, expect } from 'vitest';
import { createWebScanner } from '../../../src/scanners/web/index.js';
import { BAAS_RULES } from '../../../src/scanners/web/rules/baas.js';
import type { ScanContext } from '../../../src/scanners/web/types.js';

const context: ScanContext = {
  cwd: '/repo',
  frameworks: new Set(['agnostic', 'supabase', 'firebase']),
  readRepoFile: () => undefined
};

async function ids(content: string, path: string): Promise<string[]> {
  const findings = await createWebScanner(context, BAAS_RULES).scan([{ path, content }]);
  return findings.map((f) => f.message.match(/\[([^\]]+)\]/)?.[1] ?? '');
}

describe('BaaS web rules', () => {
  it.each([
    ['a fully open rule', 'allow read, write: if true;'],
    ['an open write', 'allow write: if true;'],
    ['an open rule with spacing', 'allow  read , write :  if  true ;']
  ])('flags %s', async (_label, content) => {
    expect(await ids(content, 'firestore.rules')).toContain('baas/firebase-rules-open');
  });

  it.each([
    ['an authenticated rule', 'allow read, write: if request.auth != null;'],
    ['an owner-scoped rule', 'allow write: if request.auth.uid == userId;']
  ])('does not flag %s', async (_label, content) => {
    expect(await ids(content, 'firestore.rules')).not.toContain('baas/firebase-rules-open');
  });

  it('flags a migration that disables row level security', async () => {
    expect(await ids('ALTER TABLE profiles DISABLE ROW LEVEL SECURITY;', 'supabase/migrations/001.sql')).toContain(
      'baas/supabase-rls-disabled'
    );
  });

  it('does not flag a migration that enables row level security', async () => {
    expect(await ids('ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;', 'supabase/migrations/001.sql')).not.toContain(
      'baas/supabase-rls-disabled'
    );
  });

  it.each([
    ['a public-prefixed service role key', 'NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=eyJ', '.env'],
    ['a Vite-prefixed service role key', 'VITE_SUPABASE_SERVICE_ROLE_KEY=eyJ', '.env'],
    ['a service role key inside a served directory', 'const key = "service_role_abc";', 'public/config.js']
  ])('flags %s', async (_label, content, path) => {
    expect(await ids(content, path)).toContain('baas/service-role-key-exposed');
  });

  it('does not flag a server-side service role key', async () => {
    expect(await ids('SUPABASE_SERVICE_ROLE_KEY=eyJ', '.env')).not.toContain('baas/service-role-key-exposed');
  });

  it('leaves a client component to the Next.js rule, so it is reported once', async () => {
    const content = "'use client';\nconst k = process.env.SUPABASE_SERVICE_ROLE_KEY;";
    expect(await ids(content, 'app/page.tsx')).not.toContain('baas/service-role-key-exposed');
  });
});
