import { describe, it, expect, vi } from 'vitest';
import { createDepsScanner } from '../../src/scanners/deps.js';

const packageJson = JSON.stringify({ dependencies: { leftpad: '1.0.0', chalk: '5.0.0' } }, null, 2);

describe('depsScanner', () => {
  it('reports npm audit findings with a bump-dependency fix when available', async () => {
    const scanner = createDepsScanner({
      runNpmAudit: () => ({
        vulnerabilities: {
          leftpad: { severity: 'high', range: '<1.0.1', fixAvailable: { name: 'leftpad', version: '1.0.1' } }
        }
      }),
      queryOsv: vi.fn().mockResolvedValue([])
    });

    const findings = await scanner.scan([{ path: 'package.json', content: packageJson }]);

    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('high');
    expect(findings[0].fix).toEqual({
      kind: 'bump-dependency',
      packageJsonPath: 'package.json',
      packageName: 'leftpad',
      targetVersion: '1.0.1'
    });
  });

  it('supplements with OSV results for packages npm audit did not flag', async () => {
    const queryOsv = vi.fn().mockResolvedValue([{ name: 'chalk', version: '5.0.0', id: 'OSV-2024-1', summary: 'Example advisory' }]);
    const scanner = createDepsScanner({ runNpmAudit: () => ({ vulnerabilities: {} }), queryOsv });

    const findings = await scanner.scan([{ path: 'package.json', content: packageJson }]);

    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain('OSV-2024-1');
    expect(queryOsv).toHaveBeenCalledWith([
      { name: 'leftpad', version: '1.0.0' },
      { name: 'chalk', version: '5.0.0' }
    ]);
  });

  it('does not duplicate a package already flagged by npm audit', async () => {
    const queryOsv = vi.fn().mockResolvedValue([]);
    const scanner = createDepsScanner({
      runNpmAudit: () => ({ vulnerabilities: { leftpad: { severity: 'high', range: '<1.0.1' } } }),
      queryOsv
    });

    await scanner.scan([{ path: 'package.json', content: packageJson }]);

    expect(queryOsv).toHaveBeenCalledWith([{ name: 'chalk', version: '5.0.0' }]);
  });

  it('returns no findings when package.json is not staged', async () => {
    const scanner = createDepsScanner({ runNpmAudit: vi.fn(), queryOsv: vi.fn() });

    const findings = await scanner.scan([{ path: 'app.js', content: 'x' }]);

    expect(findings).toHaveLength(0);
    expect(scanner.name).toBe('deps');
  });
});
