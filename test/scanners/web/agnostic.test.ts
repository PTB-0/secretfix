import { describe, it, expect } from 'vitest';
import { createWebScanner } from '../../../src/scanners/web/index.js';
import type { ScanContext } from '../../../src/scanners/web/types.js';

/** Every framework on, so framework gating never hides the rule under test. */
const context: ScanContext = {
  cwd: '/repo',
  frameworks: new Set(['agnostic', 'nextjs', 'express', 'supabase', 'firebase']),
  readRepoFile: () => undefined
};

async function scan(content: string, path = 'app.ts') {
  return createWebScanner(context).scan([{ path, content }]);
}

/** The rule ids reported for `content`. */
async function ids(content: string): Promise<string[]> {
  return (await scan(content)).map((finding) => finding.message.match(/\[([^\]]+)\]/)?.[1] ?? '');
}

describe('agnostic web rules', () => {
  it.each([
    ['path traversal', 'fs.readFile(path.join(dir, req.query.file), cb);', 'agnostic/path-traversal'],
    ['SSRF', 'const r = await fetch(req.query.url);', 'agnostic/ssrf'],
    ['NoSQL injection via body', "db.collection('u').find(req.body);", 'agnostic/nosql-injection'],
    ['NoSQL injection via $where', 'User.findOne({ $where: input });', 'agnostic/nosql-injection'],
    ['open redirect', 'res.redirect(req.query.next);', 'agnostic/open-redirect'],
    ['plaintext password compare', 'if (user.password === password) return ok();', 'agnostic/plaintext-password-compare'],
    ['reversed password compare', 'if (password === user.password) return ok();', 'agnostic/plaintext-password-compare'],
    ['unverified jwt', 'const payload = jwt.decode(token);', 'agnostic/jwt-unverified'],
    ['jwt alg none', "jwt.verify(t, s, { algorithms: ['none'] });", 'agnostic/jwt-unverified'],
    ['cookie without flags', "res.cookie('session', token);", 'agnostic/insecure-cookie'],
    ['next cookie without flags', "cookies().set('session', token);", 'agnostic/insecure-cookie'],
    ['error stack to client', 'res.status(500).json({ error: err.stack });', 'agnostic/error-stack-to-client'],
    ['raw error object to client', 'return NextResponse.json({ error: err });', 'agnostic/error-stack-to-client']
  ])('flags %s', async (_label, content, id) => {
    expect(await ids(content)).toContain(id);
  });

  it.each([
    ['a filesystem read with no request input', "fs.readFileSync(join(__dirname, 'config.json'));"],
    ['a fetch to a fixed host', "await fetch('https://api.stripe.com/v1/charges');"],
    ['a scoped Mongo filter', 'User.findOne({ email: req.body.email });'],
    ['a redirect to a fixed path', "res.redirect('/dashboard');"],
    ['a password confirmation check', 'if (password === confirmPassword) return ok();'],
    ['a bcrypt comparison', 'if (await bcrypt.compare(password, user.password)) return ok();'],
    ['a hash comparison against a derived value', 'if (user.password === hashedInput) return ok();'],
    ['a verified jwt', 'jwt.verify(token, process.env.JWT_SECRET);'],
    ['a cookie with all flags set', "res.cookie('s', t, { httpOnly: true, secure: true, sameSite: 'lax' });"],
    ['the opening line of a multi-line cookie call', "cookies().set('session', token, {"],
    ['a generic error message', "res.status(500).json({ error: 'Internal server error' });"],
    ['an error message without the stack', 'res.json({ error: err.message });']
  ])('does not flag %s', async (_label, content) => {
    expect(await scan(content)).toHaveLength(0);
  });

  it('reports the 1-based line the match sits on', async () => {
    const findings = await scan('const a = 1;\nconst b = 2;\nres.redirect(req.query.next);');
    expect(findings[0].line).toBe(3);
  });

  it('tags findings with the web scanner', async () => {
    const findings = await scan('const r = await fetch(req.query.url);');
    expect(findings[0].scanner).toBe('web');
  });
});
