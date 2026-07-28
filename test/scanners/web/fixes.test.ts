import { describe, it, expect } from 'vitest';
import { createWebScanner } from '../../../src/scanners/web/index.js';
import type { ScanContext } from '../../../src/scanners/web/types.js';

const context: ScanContext = {
  cwd: '/repo',
  frameworks: new Set(['agnostic', 'nextjs', 'express']),
  readRepoFile: () => undefined
};

/** The replacement text of the first fix offered for `content`, or undefined. */
async function replacement(content: string, path = 'app.ts'): Promise<string | undefined> {
  const findings = await createWebScanner(context).scan([{ path, content }]);
  const fix = findings.map((finding) => finding.fix).find((candidate) => candidate !== undefined);
  return fix !== undefined && fix.kind === 'replace-line' ? fix.replacement : undefined;
}

async function fixes(content: string, path = 'app.ts') {
  const findings = await createWebScanner(context).scan([{ path, content }]);
  return findings.map((finding) => finding.fix).filter((fix) => fix !== undefined);
}

describe('deterministic web fixes', () => {
  it('adds cookie flags to a call that has no options object', async () => {
    expect(await replacement("res.cookie('session', token);")).toBe(
      "res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'lax' });"
    );
  });

  it('adds cookie flags into an existing options object', async () => {
    expect(await replacement("cookies().set('session', token, { path: '/' });")).toBe(
      "cookies().set('session', token, { httpOnly: true, secure: true, sameSite: 'lax', path: '/' });"
    );
  });

  it('marks every web fix as a rewrite so it wins a merge collision', async () => {
    const [fix] = await fixes("res.cookie('session', token);");
    expect(fix).toMatchObject({ kind: 'replace-line', rewrite: true });
  });

  it('removes credentials from a wildcard CORS config and anchors on that line', async () => {
    const content = ['app.use(cors({', "  origin: '*',", '  credentials: true,', '}));'].join('\n');
    const findings = await createWebScanner(context).scan([{ path: 'server.js', content }]);
    const cors = findings.find((finding) => finding.message.includes('agnostic/cors-wildcard-credentials'));

    expect(cors?.line).toBe(3);
    expect(cors?.fix).toMatchObject({ kind: 'replace-line', line: 3, replacement: '', rewrite: true });
  });

  it('empties a wildcard image domain list', async () => {
    const content = "export default { images: { domains: ['*'] } };";
    expect(await replacement(content, 'next.config.mjs')).toBe('export default { images: { domains: [] } };');
  });

  it('offers no fix for a wildcard remote pattern', async () => {
    const content = "export default { images: { remotePatterns: [{ hostname: '**' }] } };";
    expect(await fixes(content, 'next.config.mjs')).toHaveLength(0);
  });

  it.each([
    ['app.use(express.static(__dirname));', "app.use(express.static('public'));"],
    ["app.use(express.static('.'));", "app.use(express.static('public'));"],
    ['app.use(express.static(process.cwd()));', "app.use(express.static('public'));"],
    ["app.use(express.static(path.join(__dirname, '..')));", "app.use(express.static(path.join(__dirname, 'public')));"]
  ])('rewrites %s', async (content, expected) => {
    expect(await replacement(content, 'server.js')).toBe(expected);
  });
});
