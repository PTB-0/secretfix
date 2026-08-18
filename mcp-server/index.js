import { execFile } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

const execFileAsync = promisify(execFile);

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SECRETFIX_BIN = path.join(__dirname, '..', 'bin', 'secretfix.js');

const server = new McpServer({ name: 'secretfix-mcp-server', version: '0.1.0' });

server.registerTool(
  'scan_repo',
  {
    description:
      'Runs secretfix against a git repository\'s currently STAGED changes (git add), looking for leaked ' +
      'secrets, unsafe patterns (eval, SQL/shell injection, disabled TLS, etc.), vulnerable dependencies, and ' +
      'web-app auth/CORS holes. Only scans what is staged, not the whole working tree — if nothing is staged, ' +
      'this returns zero findings even if the repo has real issues. Never mutates the repo or its git index.',
    inputSchema: {
      path: z.string().describe('Absolute path to the git repository to scan'),
      wholeFile: z
        .boolean()
        .optional()
        .describe(
          'true (default) scans the entire content of staged files; false scans only the lines a commit would add.',
        ),
    },
  },
  async ({ path: repoPath, wholeFile }) => {
    const args = ['scan', '--json'];
    if (wholeFile !== false) {
      args.push('--whole-file');
    }

    try {
      // `shell: true`: plain `execFile('node', ...)` reliably ENOENTs here even
      // though `node` resolves fine everywhere else — this process is spawned
      // several levels deep (Venus -> stdio MCP transport -> this wrapper), and
      // something in that chain (env stripped of PATHEXT, or a security tool
      // policing nested node.exe spawns) breaks plain PATH lookup at this
      // depth. Routing through cmd.exe's own resolution sidesteps it. Safe
      // here because argv is fully static — `SECRETFIX_BIN` is a path we
      // built ourselves and `args` only ever contains literal flags, never
      // caller-supplied text that could break out of the command line.
      const { stdout } = await execFileAsync('node', [SECRETFIX_BIN, ...args], {
        cwd: repoPath,
        maxBuffer: 10 * 1024 * 1024,
        shell: true,
      });
      return { content: [{ type: 'text', text: stdout }] };
    } catch (error) {
      // secretfix's own `--json` path always exits 0 (see scan.ts) — a
      // non-zero exit here means the process itself failed (bad cwd, not a
      // git repo, crashed), not "findings exist."
      const message = error instanceof Error ? error.message : String(error);
      return { content: [{ type: 'text', text: `secretfix scan failed: ${message}` }], isError: true };
    }
  },
);

const transport = new StdioServerTransport();
await server.connect(transport);
