import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type AnthropicSdk from '@anthropic-ai/sdk';
import type { Finding, FixDescriptor } from '../types.js';

const MODEL = 'claude-opus-5';

/** Lines of surrounding code sent with each finding. */
const CONTEXT_RADIUS = 12;

const SYSTEM_PROMPT = `You fix security defects in web application code.
You are given one finding and the lines around it. Reply with a JSON object and nothing else:
{"file": string, "line": number, "replacement": string, "explanation": string}
"replacement" replaces exactly that one line, preserving its indentation.
"file" and "line" must repeat the values you were given.
If a single-line replacement cannot fix the defect correctly, reply {"file":"","line":0,"replacement":"","explanation":"reason"}.`;

const PATCH_SCHEMA = {
  type: 'object',
  properties: {
    file: { type: 'string' },
    line: { type: 'integer' },
    replacement: { type: 'string' },
    explanation: { type: 'string' }
  },
  required: ['file', 'line', 'replacement', 'explanation'],
  additionalProperties: false
} as const;

export interface AiMessage {
  stop_reason?: string;
  content: { type: string; text?: string }[];
}

/** Returns undefined when there is no SDK or no credentials — not an error. */
export type SendFn = (prompt: string, system: string) => Promise<AiMessage | undefined>;

interface AiPatch {
  file: string;
  line: number;
  replacement: string;
  explanation: string;
}

/**
 * Sends one request per finding.
 *
 * `fallbacks: 'default'` matters here specifically: Claude Opus 5 runs
 * cybersecurity classifiers, and this tool's whole job is to send vulnerable
 * code and ask for a security fix — exactly the shape that gets declined. With
 * fallbacks on, a cyber-category refusal is retried server-side on another model
 * inside the same call. `stop_reason` is still checked before `content`, because
 * a refusal returns HTTP 200 with an empty content array.
 */
const defaultSend: SendFn = async (prompt, system) => {
  let Anthropic: typeof AnthropicSdk;
  try {
    ({ default: Anthropic } = await import('@anthropic-ai/sdk'));
  } catch {
    console.warn('secretfix: --ai needs @anthropic-ai/sdk — run "pnpm add -O @anthropic-ai/sdk".');
    return undefined;
  }

  // The SDK resolves credentials itself: ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN,
  // then an `ant auth login` profile on disk. An unset env var does not mean
  // there are no credentials, so construct the client and let it decide.
  const client = new Anthropic();

  try {
    // `fallbacks` and `output_config.format` are beta fields the SDK's typings
    // lag behind, so the request object is asserted rather than inferred. Keep
    // this the only assertion in the file, and drop it once the types land.
    const request = {
      model: MODEL,
      max_tokens: 2048,
      betas: ['server-side-fallback-2026-07-01'],
      fallbacks: 'default',
      output_config: { effort: 'low', format: { type: 'json_schema', schema: PATCH_SCHEMA } },
      system: [{ type: 'text', text: system, cache_control: { type: 'ephemeral' } }],
      messages: [{ role: 'user', content: prompt }]
    } as unknown as Parameters<typeof client.beta.messages.create>[0];

    return (await client.beta.messages.create(request)) as AiMessage;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.warn(`secretfix: --ai request failed — ${message}`);
    return undefined;
  }
};

function snippet(file: string, line: number, cwd: string): string | undefined {
  try {
    const lines = readFileSync(join(cwd, file), 'utf8').split('\n');
    const from = Math.max(0, line - 1 - CONTEXT_RADIUS);
    const to = Math.min(lines.length, line + CONTEXT_RADIUS);
    return lines
      .slice(from, to)
      .map((text, index) => `${from + index + 1}: ${text}`)
      .join('\n');
  } catch {
    return undefined;
  }
}

function parsePatch(message: AiMessage): AiPatch | undefined {
  // A refusal is HTTP 200 with an empty content array, so check this first —
  // reading content[0] unconditionally would throw.
  if (message.stop_reason === 'refusal') return undefined;

  const text = message.content.find((block) => block.type === 'text')?.text;
  if (text === undefined) return undefined;

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (typeof parsed !== 'object' || parsed === null) return undefined;

  const patch = parsed as Partial<AiPatch>;
  if (
    typeof patch.file !== 'string' ||
    typeof patch.line !== 'number' ||
    typeof patch.replacement !== 'string' ||
    typeof patch.explanation !== 'string'
  ) {
    return undefined;
  }
  return { file: patch.file, line: patch.line, replacement: patch.replacement, explanation: patch.explanation };
}

/**
 * Attaches an AI-proposed fix to findings that have no deterministic one.
 * Findings that already carry a fix are never sent anywhere.
 */
export async function proposeFixes(
  findings: Finding[],
  cwd: string,
  send: SendFn = defaultSend
): Promise<Finding[]> {
  const result: Finding[] = [];

  for (const finding of findings) {
    if (finding.fix !== undefined) {
      result.push(finding);
      continue;
    }

    const code = snippet(finding.file, finding.line, cwd);
    if (code === undefined) {
      result.push(finding);
      continue;
    }

    const prompt = [
      `Finding: ${finding.message}`,
      `File: ${finding.file}`,
      `Line: ${finding.line}`,
      '',
      code
    ].join('\n');

    const message = await send(prompt, SYSTEM_PROMPT);
    if (message === undefined) {
      result.push(finding);
      continue;
    }

    const patch = parsePatch(message);
    // The model must confirm the exact target it was given. Anything else is a
    // patch for a line we did not ask about, and applying it would be a silent
    // wrong fix.
    if (patch === undefined || patch.file !== finding.file || patch.line !== finding.line) {
      result.push(finding);
      continue;
    }

    const fix: FixDescriptor = {
      kind: 'replace-line',
      file: finding.file,
      line: finding.line,
      replacement: patch.replacement,
      rewrite: true
    };
    result.push({ ...finding, message: `${finding.message}\n  AI: ${patch.explanation}`, fix });
  }

  return result;
}
