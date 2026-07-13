import type { Finding, Scanner, StagedFile } from './types.js';

const SCANNER_TIMEOUT_MS = 5000;

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('scanner timed out')), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      }
    );
  });
}

export async function runScanners(
  scanners: Scanner[],
  stagedFiles: StagedFile[],
  timeoutMs: number = SCANNER_TIMEOUT_MS
): Promise<{ findings: Finding[]; warnings: string[] }> {
  const findings: Finding[] = [];
  const warnings: string[] = [];

  for (const scanner of scanners) {
    try {
      const result = await withTimeout(scanner.scan(stagedFiles), timeoutMs);
      findings.push(...result);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      warnings.push(`${scanner.name} scanner failed: ${message}`);
    }
  }

  return { findings, warnings };
}
