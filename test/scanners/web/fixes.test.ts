import { describe, it, expect } from 'vitest';
import { createWebScanner } from '../../../src/scanners/web/index.js';
import type { ScanContext } from '../../../src/scanners/web/types.js';

const context: ScanContext = {
  cwd: '/repo',
  frameworks: new Set(['agnostic', 'nextjs', 'express']),
  readRepoFile: () => undefined
};

/** The replacement text of the first `replace-line` fix offered for `content`, or undefined. */
async function replacement(content: string, path = 'app.ts'): Promise<string | undefined> {
  const findings = await createWebScanner(context).scan([{ path, content }]);
  const fix = findings
    .map((finding) => finding.fix)
    .find((candidate): candidate is Extract<typeof candidate, { kind: 'replace-line' }> => candidate?.kind === 'replace-line');
  return fix?.replacement;
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

  it.each([
    ["res.cookie('session', token);", 'app.ts'],
    [['app.use(cors({', "  origin: '*',", '  credentials: true,', '}));'].join('\n'), 'server.js'],
    ["export default { async headers() { return []; }, images: { domains: ['*'] } };", 'next.config.mjs'],
    ['app.use(express.static(__dirname));', 'server.js']
  ])('marks the fix from each of the four rules as a rewrite (%#)', async (content, path) => {
    const [fix] = await fixes(content, path);
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
    const content =
      "export default { async headers() { return []; }, images: { remotePatterns: [{ hostname: '**' }] } };";
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

  describe('cookie fix declines rather than guessing', () => {
    it.each([
      ["res.cookie('session', token); logger.info('set');", 'a second statement on the line'],
      ["if (ok) res.cookie('session', token); else res.clearCookie('session');", 'a second statement gated by if/else'],
      ["res.cookie('session', signToken(user), {", "a call whose own closing paren isn't on this line"],
      ["res.cookie('session', token, { sameSite: 'none', secure: false });", 'an options object that already sets secure/sameSite'],
      ["res.cookie('session', token, { ...opts });", 'a spread in the options object']
    ])('offers no fix for %s', async (content) => {
      expect(await replacement(content)).toBeUndefined();
    });

    it('does not splice flags into a nested call that is the cookie value, not its options', async () => {
      // The naive "last `)` on the line" approach used to hand the flags to
      // JSON.stringify's own argument list, corrupting the cookie payload.
      // With only two real arguments, the safe rewrite is to append a third.
      expect(await replacement("res.cookie('cart', JSON.stringify({ id: 1 }));")).toBe(
        "res.cookie('cart', JSON.stringify({ id: 1 }), { httpOnly: true, secure: true, sameSite: 'lax' });"
      );
    });

    it('rewrites the call and leaves a trailing comment on the same line untouched', async () => {
      expect(await replacement("res.cookie('session', token); // see res.cookie(docs)")).toBe(
        "res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'lax' }); // see res.cookie(docs)"
      );
    });
  });

  describe('CORS fix declines rather than deleting code', () => {
    it('reports the finding but offers no fix for a single-line cors() call', async () => {
      const content = "app.use(cors({ origin: '*', credentials: true }));";
      const findings = await createWebScanner(context).scan([{ path: 'server.js', content }]);
      const cors = findings.find((finding) => finding.message.includes('agnostic/cors-wildcard-credentials'));
      expect(cors).toBeDefined();
      expect(cors?.fix).toBeUndefined();
    });

    it('offers no fix when a second statement shares the single-line cors() call', async () => {
      const content = "app.use(cors({ origin: '*', credentials: true })); app.use(express.json());";
      expect(await fixes(content, 'server.js')).toHaveLength(0);
    });

    it('offers no fix when credentials and its value are split across lines with unrelated code after the block', async () => {
      const content = [
        'app.use(cors({',
        "  origin: '*',",
        '  credentials:',
        '    true,',
        '}));',
        '',
        'const other = { credentials: true };'
      ].join('\n');
      const findings = await createWebScanner(context).scan([{ path: 'server.js', content }]);
      const cors = findings.find((finding) => finding.message.includes('agnostic/cors-wildcard-credentials'));
      expect(cors).toBeDefined();
      expect(cors?.fix).toBeUndefined();
    });
  });

  describe('images-wildcard fix only removes the wildcard entry', () => {
    it('keeps every other host and removes only the wildcard entry', async () => {
      const content =
        "export default { images: { domains: ['images.example.com', 'cdn.example.com', '*'] } };";
      expect(await replacement(content, 'next.config.mjs')).toBe(
        "export default { images: { domains: ['images.example.com', 'cdn.example.com'] } };"
      );
    });

    it('offers no fix when an array entry is not a plain string literal', async () => {
      const content = "export default { images: { domains: [process.env.HOST, '*'] } };";
      const findings = await createWebScanner(context).scan([{ path: 'next.config.mjs', content }]);
      const wildcard = findings.find((finding) => finding.message.includes('nextjs/images-wildcard'));
      expect(wildcard).toBeDefined();
      expect(wildcard?.fix).toBeUndefined();
    });
  });
});
