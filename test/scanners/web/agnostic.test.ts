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
async function ids(content: string, path?: string): Promise<string[]> {
  return (await scan(content, path)).map((finding) => finding.message.match(/\[([^\]]+)\]/)?.[1] ?? '');
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

  it('flags a request body passed straight into an ORM write', async () => {
    const content = [
      'export async function PATCH(req) {',
      '  const body = await req.json();',
      '  return prisma.user.update({',
      '    where: { id },',
      '    data: body,',
      '  });',
      '}'
    ].join('\n');

    expect(await ids(content)).toContain('agnostic/mass-assignment');
  });

  it('flags a spread of the request body into an ORM write', async () => {
    const content = 'const body = await req.json();\nawait prisma.user.update({ data: { ...body } });';
    expect(await ids(content)).toContain('agnostic/mass-assignment');
  });

  it('does not flag an ORM write with an explicit field list', async () => {
    const content = [
      'const body = await req.json();',
      'await prisma.user.update({',
      '  where: { id },',
      '  data: { name: body.name, bio: body.bio },',
      '});'
    ].join('\n');

    expect(await ids(content)).not.toContain('agnostic/mass-assignment');
  });

  it.each([
    ['data: req.body', 'await prisma.user.update({ data: req.body });'],
    ['data: await req.json()', 'await prisma.user.update({ data: await req.json() });'],
    ['data: request.body', 'await prisma.user.update({ data: request.body });']
  ])('flags the request body passed directly as %s, with no intermediate local', async (_label, content) => {
    expect(await ids(content)).toContain('agnostic/mass-assignment');
  });

  it('does not flag an explicit single field read off the request body', async () => {
    const content = 'const body = await req.json();\nawait prisma.user.update({ data: body.name });';
    expect(await ids(content)).not.toContain('agnostic/mass-assignment');
  });

  it('does not flag an ORM write whose data comes from a value the server computed', async () => {
    const content = 'const data = buildUpdate(input);\nawait prisma.user.update({ data });';
    expect(await ids(content)).not.toContain('agnostic/mass-assignment');
  });

  it('flags a multi-line CORS config that pairs a wildcard origin with credentials', async () => {
    const content = ["app.use(cors({", "  origin: '*',", '  credentials: true,', '}));'].join('\n');
    expect(await ids(content)).toContain('agnostic/cors-wildcard-credentials');
  });

  it('does not flag a wildcard origin without credentials', async () => {
    const content = ["app.use(cors({", "  origin: '*',", '}));'].join('\n');
    expect(await ids(content)).not.toContain('agnostic/cors-wildcard-credentials');
  });

  it('does not flag credentials with an explicit origin', async () => {
    const content = ['app.use(cors({', "  origin: 'https://app.example.com',", '  credentials: true,', '}));'].join('\n');
    expect(await ids(content)).not.toContain('agnostic/cors-wildcard-credentials');
  });

  it('advises when a login handler has no rate limiting', async () => {
    const content = 'export async function POST(req) {\n  const body = await req.json();\n  return signIn(body);\n}';
    const findings = await scan(content, 'app/api/login/route.ts');
    const rateLimit = findings.find((finding) => finding.message.includes('agnostic/no-rate-limit-on-auth'));
    expect(rateLimit?.severity).toBe('medium');
  });

  it('does not flag a login handler that rate limits', async () => {
    const content =
      'export async function POST(req) {\n  await limiter.check(req);\n  const body = await req.json();\n  return signIn(body);\n}';
    expect(await ids(content, 'app/api/login/route.ts')).not.toContain('agnostic/no-rate-limit-on-auth');
  });
});
