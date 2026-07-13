import { execFileSync } from 'node:child_process';
import type { Finding, Scanner, StagedFile } from '../types.js';

interface NpmAuditAdvisory {
  severity: string;
  range: string;
  fixAvailable?: boolean | { name: string; version: string };
}

interface NpmAuditJson {
  vulnerabilities?: Record<string, NpmAuditAdvisory>;
}

interface OsvFinding {
  name: string;
  version: string;
  id: string;
  summary: string;
}

export interface DepsScannerDeps {
  runNpmAudit: (cwd: string) => NpmAuditJson;
  queryOsv: (packages: { name: string; version: string }[]) => Promise<OsvFinding[]>;
}

function defaultRunNpmAudit(cwd: string): NpmAuditJson {
  try {
    const output = execFileSync('npm', ['audit', '--json'], { cwd, encoding: 'utf8' });
    return JSON.parse(output) as NpmAuditJson;
  } catch (err) {
    const execErr = err as { stdout?: string };
    if (execErr.stdout) {
      return JSON.parse(execErr.stdout) as NpmAuditJson;
    }
    throw err;
  }
}

async function defaultQueryOsv(packages: { name: string; version: string }[]): Promise<OsvFinding[]> {
  if (packages.length === 0) return [];

  const response = await fetch('https://api.osv.dev/v1/querybatch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      queries: packages.map((pkg) => ({ package: { name: pkg.name, ecosystem: 'npm' }, version: pkg.version }))
    })
  });

  if (!response.ok) {
    throw new Error(`OSV.dev request failed with status ${response.status}`);
  }

  const body = (await response.json()) as { results: { vulns?: { id: string; summary?: string }[] }[] };

  const findings: OsvFinding[] = [];
  body.results.forEach((result, index) => {
    const pkg = packages[index];
    for (const vuln of result.vulns ?? []) {
      findings.push({ name: pkg.name, version: pkg.version, id: vuln.id, summary: vuln.summary ?? 'Known vulnerability' });
    }
  });
  return findings;
}

function parsePackageJson(content: string): { name: string; version: string }[] {
  const parsed = JSON.parse(content) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  const deps = { ...parsed.dependencies, ...parsed.devDependencies };
  return Object.entries(deps).map(([name, version]) => ({ name, version: version.replace(/^[\^~]/, '') }));
}

function findLineOf(content: string, packageName: string): number {
  const lines = content.split('\n');
  const index = lines.findIndex((line) => line.includes(`"${packageName}"`));
  return index === -1 ? 1 : index + 1;
}

export function createDepsScanner(deps: DepsScannerDeps): Scanner {
  return {
    name: 'deps',
    async scan(stagedFiles: StagedFile[]): Promise<Finding[]> {
      const packageJsonFile = stagedFiles.find((f) => f.path === 'package.json');
      if (!packageJsonFile) return [];

      const packages = parsePackageJson(packageJsonFile.content);
      const findings: Finding[] = [];
      const seen = new Set<string>();

      let audit: NpmAuditJson;
      try {
        audit = deps.runNpmAudit(process.cwd());
      } catch {
        audit = {};
      }

      for (const [name, advisory] of Object.entries(audit.vulnerabilities ?? {})) {
        seen.add(name);
        findings.push({
          scanner: 'deps',
          severity: (advisory.severity as Finding['severity']) ?? 'medium',
          file: 'package.json',
          line: findLineOf(packageJsonFile.content, name),
          message: `Dependency "${name}" has a known ${advisory.severity} severity vulnerability (affected range ${advisory.range}).`,
          fix:
            typeof advisory.fixAvailable === 'object'
              ? {
                  kind: 'bump-dependency',
                  packageJsonPath: 'package.json',
                  packageName: name,
                  targetVersion: advisory.fixAvailable.version
                }
              : undefined
        });
      }

      const remaining = packages.filter((pkg) => !seen.has(pkg.name));
      const osvResults = await deps.queryOsv(remaining);
      for (const vuln of osvResults) {
        findings.push({
          scanner: 'deps',
          severity: 'medium',
          file: 'package.json',
          line: findLineOf(packageJsonFile.content, vuln.name),
          message: `Dependency "${vuln.name}@${vuln.version}" matches OSV advisory ${vuln.id}: ${vuln.summary}`
        });
      }

      return findings;
    }
  };
}

export const depsScanner = createDepsScanner({ runNpmAudit: defaultRunNpmAudit, queryOsv: defaultQueryOsv });
