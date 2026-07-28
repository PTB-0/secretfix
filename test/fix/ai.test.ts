import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { proposeFixes } from '../../src/fix/ai.js';
import type { Finding } from '../../src/types.js';

let dir: string;
let finding: Finding;

function reply(text: string) {
  return async () => ({ content: [{ type: 'text', text }] });
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'secretfix-ai-'));
  mkdirSync(join(dir, 'app', 'api', 'user'), { recursive: true });
  writeFileSync(
    join(dir, 'app', 'api', 'user', 'route.ts'),
    'export async function POST(req) {\n  const body = await req.json();\n  await db.user.create({ data: body });\n}\n'
  );
  finding = {
    scanner: 'web',
    severity: 'critical',
    file: 'app/api/user/route.ts',
    line: 2,
    message: 'mass assignment [agnostic/mass-assignment] (app/api/user/route.ts:2)'
  };
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('proposeFixes', () => {
  it('turns a schema-valid patch into a rewrite fix', async () => {
    const patch = JSON.stringify({
      file: 'app/api/user/route.ts',
      line: 2,
      replacement: '  data: { name: body.name },',
      explanation: 'Only the name field is accepted.'
    });

    const [result] = await proposeFixes([finding], dir, reply(patch));

    expect(result.fix).toMatchObject({
      kind: 'replace-line',
      file: 'app/api/user/route.ts',
      line: 2,
      replacement: '  data: { name: body.name },',
      rewrite: true
    });
  });

  it('leaves the finding untouched when the model refuses', async () => {
    const send = async () => ({ stop_reason: 'refusal', content: [] });
    const [result] = await proposeFixes([finding], dir, send);
    expect(result.fix).toBeUndefined();
  });

  it('leaves the finding untouched when there are no credentials', async () => {
    const [result] = await proposeFixes([finding], dir, async () => undefined);
    expect(result.fix).toBeUndefined();
  });

  it('leaves the finding untouched when the source file cannot be read', async () => {
    const missing: Finding = { ...finding, file: 'does/not/exist.ts' };
    const send = vi.fn(reply('{}'));
    const [result] = await proposeFixes([missing], dir, send);
    expect(result.fix).toBeUndefined();
    expect(send).not.toHaveBeenCalled();
  });

  it('rejects a patch that points at a different file', async () => {
    const patch = JSON.stringify({ file: 'other.ts', line: 2, replacement: 'x', explanation: 'y' });
    const [result] = await proposeFixes([finding], dir, reply(patch));
    expect(result.fix).toBeUndefined();
  });

  it('rejects a patch that points at a different line', async () => {
    const patch = JSON.stringify({ file: 'app/api/user/route.ts', line: 9, replacement: 'x', explanation: 'y' });
    const [result] = await proposeFixes([finding], dir, reply(patch));
    expect(result.fix).toBeUndefined();
  });

  it('rejects unparseable output rather than throwing', async () => {
    const [result] = await proposeFixes([finding], dir, reply('sorry, no idea'));
    expect(result.fix).toBeUndefined();
  });

  it('never asks about a finding that already has a deterministic fix', async () => {
    const send = vi.fn(reply('{}'));
    const fixable: Finding = {
      ...finding,
      fix: { kind: 'replace-line', file: 'a.ts', line: 1, replacement: 'x', rewrite: true }
    };

    await proposeFixes([fixable], dir, send);

    expect(send).not.toHaveBeenCalled();
  });
});
