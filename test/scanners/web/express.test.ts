import { describe, it, expect } from 'vitest';
import { createWebScanner } from '../../../src/scanners/web/index.js';
import { EXPRESS_RULES } from '../../../src/scanners/web/rules/express.js';
import type { ScanContext } from '../../../src/scanners/web/types.js';

const context: ScanContext = {
  cwd: '/repo',
  frameworks: new Set(['agnostic', 'express']),
  readRepoFile: () => undefined
};

async function findings(content: string, path = 'server.js') {
  return createWebScanner(context, EXPRESS_RULES).scan([{ path, content }]);
}

async function ids(content: string, path?: string): Promise<string[]> {
  return (await findings(content, path)).map((f) => f.message.match(/\[([^\]]+)\]/)?.[1] ?? '');
}

describe('Express web rules', () => {
  it.each([
    ['__dirname', 'app.use(express.static(__dirname));'],
    ['the current directory', "app.use(express.static('.'));"],
    ['process.cwd()', 'app.use(express.static(process.cwd()));'],
    ['a parent of __dirname', "app.use(express.static(path.join(__dirname, '..')));"]
  ])('flags static serving of %s', async (_label, content) => {
    expect(await ids(content)).toContain('express/static-serves-project-root');
  });

  it.each([
    ['a public directory', "app.use(express.static('public'));"],
    ['a joined public directory', "app.use(express.static(path.join(__dirname, 'public')));"]
  ])('does not flag static serving of %s', async (_label, content) => {
    expect(await ids(content)).not.toContain('express/static-serves-project-root');
  });

  it('flags an app entry with no helmet', async () => {
    expect(await ids('const app = express();\napp.listen(3000);', 'server.js')).toContain('express/no-helmet');
  });

  it('does not flag an app entry that uses helmet', async () => {
    const content = "const app = express();\napp.use(helmet());\napp.listen(3000);";
    expect(await ids(content, 'server.js')).not.toContain('express/no-helmet');
  });

  it('does not run the helmet rule on a file that is not an app entry', async () => {
    expect(await ids('const app = express();', 'routes/users.js')).not.toContain('express/no-helmet');
  });

  it('offers no automatic fix for the helmet finding', async () => {
    const [finding] = (await findings('const app = express();', 'server.js')).filter((f) =>
      f.message.includes('express/no-helmet')
    );
    expect(finding.fix).toBeUndefined();
  });

  it('blocks a state-changing route with no auth', async () => {
    const content = "app.delete('/api/notes/:id', async (req, res) => {\n  await db.notes.delete(req.params.id);\n  res.end();\n});";
    const [finding] = (await findings(content)).filter((f) => f.message.includes('express/route-no-auth'));
    expect(finding.severity).toBe('high');
  });

  it('reports nothing when the route checks auth inline', async () => {
    const content =
      "app.post('/api/notes', async (req, res) => {\n  const user = requireUser(req);\n  res.json(await save(user, req.body));\n});";
    expect(await ids(content)).not.toContain('express/route-no-auth');
  });

  it('reports nothing when a global auth middleware is mounted', async () => {
    const content =
      "app.use(requireAuth);\napp.post('/api/notes', async (req, res) => {\n  res.json(await save(req.body));\n});";
    expect(await ids(content)).not.toContain('express/route-no-auth');
  });

  // The global-middleware check is file-wide rather than positional, so a route
  // registered above app.use(requireAuth) is suppressed here even though Express
  // itself would not have protected it yet at that point in the file. That is the
  // same "absence of evidence must not manufacture a blocking finding" direction
  // this whole rule set deliberately favors, so the behaviour is being pinned, not
  // fixed — this test documents a known limitation rather than a bug.
  it('does not flag a route mounted before its auth middleware (known limitation: the check is file-wide, not positional)', async () => {
    const content =
      "app.post('/api/notes', async (req, res) => {\n  res.json(await save(req.body));\n});\napp.use(requireAuth);";
    expect(await ids(content)).not.toContain('express/route-no-auth');
  });

  it('advises a cookie-session app with a state-changing route and no CSRF protection', async () => {
    const content = [
      "const session = require('express-session');",
      'app.use(session({ secret: s }));',
      "app.post('/transfer', (req, res) => {",
      '  transfer(req.body);',
      '  res.end();',
      '});'
    ].join('\n');
    const [finding] = (await findings(content)).filter((f) => f.message.includes('express/csrf-missing'));
    expect(finding.severity).toBe('medium');
  });

  it('reports nothing when CSRF protection is present', async () => {
    const content = [
      "const session = require('express-session');",
      "const csrf = require('csurf');",
      'app.use(session({ secret: s }));',
      'app.use(csrf());',
      "app.post('/transfer', (req, res) => {",
      '  transfer(req.body);',
      '  res.end();',
      '});'
    ].join('\n');
    expect(await ids(content)).not.toContain('express/csrf-missing');
  });

  it('reports nothing about CSRF for a token-authenticated API with no cookie session', async () => {
    const content = "app.post('/api/notes', (req, res) => {\n  res.json(save(req.body));\n});";
    expect(await ids(content)).not.toContain('express/csrf-missing');
  });
});
