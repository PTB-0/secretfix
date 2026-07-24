# VibeGuard

Ship with confidence. VibeGuard runs on `git commit` and stops the three mistakes
that AI-assisted code makes most often — a leaked API key, an unsafe pattern like
`eval()` or a concatenated SQL query, and a dependency with a known CVE — then
explains each one in plain English and offers to fix it for you.

```
$ git commit -m "add stripe checkout"

vibeguard: 2 issue(s) found in your staged changes.

Possible Stripe Live Key found in checkout.js:14. Move this value to an
environment variable instead of committing it.
[CRITICAL] Fix this now? (checkout.js:14) [y/n/skip] › y

SQL query appears to be built with string concatenation/interpolation. Use
parameterized queries to avoid SQL injection. (db.js:31)
[CRITICAL] Fix this now? (db.js:31) [y/n/skip] › n

vibeguard: 1 unresolved issue(s). Commit blocked.
```

## Install

```bash
npx vibeguard init
```

That installs a `pre-commit` hook (via husky, or a plain `.git/hooks/pre-commit`
if husky is unavailable) and writes a default `.vibeguardrc.json`. An existing
pre-commit hook is appended to, never overwritten, and re-running `init` is safe.

Requires Node.js 18 or newer.

## What it checks

| Scanner | Finds |
|---|---|
| `secrets` | AWS, Stripe, GitHub, Slack, Google, Anthropic and OpenAI keys; private key blocks; passwords inside connection strings; assigned `apiKey`/`token`/`password` literals; high-entropy strings that look like credentials; and files that must never be staged at all (`.env`, `id_rsa`, `*.pem`, `credentials.json`, `.npmrc`) |
| `owasp` | `eval()` / `new Function()`, SQL built by string concatenation, shell commands built by string concatenation, `innerHTML` / `dangerouslySetInnerHTML`, disabled TLS verification, MD5/SHA-1 password hashing, hardcoded password literals, `Math.random()` used where a CSPRNG belongs |
| `deps` | Vulnerable npm dependencies, via `npm audit` cross-referenced with [OSV.dev](https://osv.dev) |

**Only the lines your commit adds are judged.** Install VibeGuard into a codebase
that already has an `eval()` in it and you can still commit — you only answer for
what you are introducing. Pass `--whole-file` (or set `"scanMode": "whole-file"`)
to audit entire staged files instead. Two things are always reported regardless:
a sensitive file being staged, and a vulnerable dependency, because neither is
about a line you typed.

Only **staged** content is scanned — what is actually about to be committed, not
your working tree. Binary blobs, files over 1 MB, `node_modules/`, lockfiles and
minified bundles are skipped; they are all high-entropy by construction and
produce nothing but false positives.

### What blocks, and what only warns

By default **critical and high** findings block the commit; **medium and low** are
printed as notes and let it through. Blocking on every `Math.random()` teaches
people to reach for `--no-verify`, which is worse than not gating at all. Change
the line with `"failOn": "medium"` or `--fail-on medium`.

## Fixes

Answer `y` and VibeGuard applies the fix and re-stages the file:

- **Leaked secret** — the value moves to `.env`, `.env` is added to `.gitignore`,
  and the source line becomes `process.env.YOUR_KEY`. A second secret that would
  reuse a name gets a unique one (`SUSPECTED_SECRET_2`) instead of clobbering the
  first. `.env` itself is never staged.
- **Vulnerable dependency** — the version range in `package.json` is bumped to the
  first patched release. Run your installer afterwards to update the lockfile.
- **Staged secret file** — `.env` and friends are removed from the commit with
  `git restore --staged` and added to `.gitignore`. The file itself stays exactly
  where it is on your disk; only the commit is changed.
- **Unsafe pattern** — no machine can rewrite these safely, so the line is
  annotated with `// vibeguard-ignore-next-line — reviewed: <rule>`, recording
  that you looked at it. The line itself is left exactly as you wrote it.

After every accepted fix VibeGuard re-scans the updated index, so a fix that did
not actually resolve the problem still blocks the commit.

## Configuration

`.vibeguardrc.json` in the repository root:

```json
{
  "secrets": true,
  "owasp": true,
  "deps": true,
  "scanMode": "added-lines",
  "failOn": "high",
  "ignoreLines": {
    "src/fixtures.ts": [12, 13]
  },
  "excludeFiles": ["test/fixtures/", ".generated.ts"]
}
```

- `secrets` / `owasp` / `deps` — turn a scanner off entirely.
- `scanMode` — `"added-lines"` (default) judges only what the commit introduces;
  `"whole-file"` judges every line of every staged file.
- `failOn` — lowest severity that blocks: `"critical"`, `"high"` (default),
  `"medium"` or `"low"`.
- `ignoreLines` — silence specific lines of specific files.
- `excludeFiles` — never scan these. Matches an exact path, a bare file name, a
  path suffix (`.generated.ts`) or a directory prefix (`test/fixtures/`). Entries
  are **added** to the built-in exclusions, so lockfiles stay excluded.

Silence a single line from the source itself:

```js
// vibeguard-ignore-next-line
const testKey = "AKIAIOSFODNN7EXAMPLE";

const other = "AKIAIOSFODNN7EXAMPLE"; // vibeguard-ignore
```

Flags override the config file for one run:

```bash
vibeguard scan --no-deps            # skip the dependency scan (it can hit the network)
vibeguard scan --no-owasp
vibeguard scan --no-secrets
vibeguard scan --whole-file         # audit whole files, not just added lines
vibeguard scan --fail-on medium     # let medium findings block too
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Nothing to report, or every finding was fixed and the re-scan came back clean |
| `1` | Unresolved findings, or the scan could not complete |

VibeGuard **fails closed**: if it crashes, times out, or cannot read your answers,
the commit is blocked rather than let through. In particular, a hook launched
without a terminal — a GUI git client, CI — answers `skip` for every finding and
blocks, instead of silently passing.

To bypass it deliberately:

```bash
git commit --no-verify
```

## Behaviour notes

- Each scanner is isolated and given 5 seconds. If one fails — OSV.dev
  unreachable, `npm audit` erroring — you get a warning and the other scanners
  still gate the commit.
- Fixes are written to your working tree. If a file has unstaged edits, its
  working-tree content may differ from the staged content that was scanned; a fix
  that no longer matches is refused rather than applied to the wrong line.
- Dependency scanning is npm-only. Python, Go and other ecosystems are out of
  scope for this release.
- No telemetry. Nothing about your code leaves your machine except package
  name/version pairs sent to OSV.dev, which you can disable with `--no-deps` or
  `"deps": false`.

## Development

```bash
pnpm install
pnpm test          # builds, then runs the full suite
pnpm test:watch
```

## License

MIT
