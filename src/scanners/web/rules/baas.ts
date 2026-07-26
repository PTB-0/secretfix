import type { Hit, WebRule } from '../types.js';

const OPEN_FIREBASE_RULE = /allow\s+[\w\s,]*:\s*if\s+true\b/i;
const RLS_DISABLED = /\bDISABLE\s+ROW\s+LEVEL\s+SECURITY\b/i;

const PUBLIC_PREFIXED_SERVICE_ROLE = /\b(?:NEXT_PUBLIC|VITE|PUBLIC|REACT_APP|EXPO_PUBLIC)_\w*SERVICE_ROLE\w*/i;
const SERVICE_ROLE = /service_role/i;
/** Directories whose contents are shipped to the browser verbatim. */
const SERVED_DIRECTORY = /^(?:public|static|dist|build)\//;
const USE_CLIENT = /^\s*['"]use client['"]/m;

export const BAAS_RULES: readonly WebRule[] = [
  {
    kind: 'line',
    id: 'baas/firebase-rules-open',
    group: 'auth',
    // Firestore rules syntax appears nowhere else, so this needs no framework
    // detection — and a project whose only Firebase artifact is a .rules file
    // would otherwise never be scanned.
    frameworks: ['agnostic'],
    severity: 'critical',
    confidence: 'certain',
    regex: OPEN_FIREBASE_RULE,
    message:
      'This security rule allows the operation for everyone, with no condition at all — any visitor can read or overwrite the data straight from the browser. Require request.auth and scope the rule to the owning user.'
  },
  {
    kind: 'line',
    id: 'baas/supabase-rls-disabled',
    group: 'auth',
    frameworks: ['agnostic'],
    severity: 'critical',
    confidence: 'certain',
    regex: RLS_DISABLED,
    message:
      'Row level security is being turned off, which means the anon key can read and write every row in this table directly from the browser. Keep RLS enabled and write a policy for the access you need.'
  },
  {
    kind: 'block',
    id: 'baas/service-role-key-exposed',
    group: 'exposure',
    frameworks: ['agnostic'],
    severity: 'critical',
    confidence: 'certain',
    message:
      'A service-role key is exposed to the browser. That key bypasses every row level security policy, so whoever reads it owns your database. Move it server-side and rotate it — assume the current one is burned.',
    find: (file) => {
      // A 'use client' file is reported by nextjs/service-role-key-in-client, so
      // skipping it here keeps one problem to one finding.
      if (USE_CLIENT.test(file.content)) return [];

      const inServedDirectory = SERVED_DIRECTORY.test(file.path);
      const hits: Hit[] = [];

      file.content.split('\n').forEach((line, index) => {
        const exposed = PUBLIC_PREFIXED_SERVICE_ROLE.test(line) || (inServedDirectory && SERVICE_ROLE.test(line));
        if (exposed) hits.push({ line: index + 1 });
      });

      return hits;
    }
  }
];
