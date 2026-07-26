import { describe, it, expect } from 'vitest';
import { detectFrameworks } from '../../../src/scanners/web/detect.js';

/** Builds a readRepoFile stub over a fixed path->content map. */
function reader(files: Record<string, string>) {
  return (path: string): string | undefined => files[path];
}

describe('detectFrameworks', () => {
  it('always includes agnostic', () => {
    expect(detectFrameworks(reader({}))).toEqual(new Set(['agnostic']));
  });

  it.each([
    ['next', 'nextjs'],
    ['express', 'express'],
    ['@supabase/supabase-js', 'supabase'],
    ['firebase-admin', 'firebase']
  ])('detects %s', (dependency, framework) => {
    const files = { 'package.json': JSON.stringify({ dependencies: { [dependency]: '1.0.0' } }) };
    expect(detectFrameworks(reader(files)).has(framework)).toBe(true);
  });

  it('detects a devDependency too', () => {
    const files = { 'package.json': JSON.stringify({ devDependencies: { express: '4.0.0' } }) };
    expect(detectFrameworks(reader(files)).has('express')).toBe(true);
  });

  it('detects both frameworks in one project', () => {
    const files = { 'package.json': JSON.stringify({ dependencies: { next: '16.0.0', express: '4.0.0' } }) };
    const frameworks = detectFrameworks(reader(files));
    expect(frameworks.has('nextjs')).toBe(true);
    expect(frameworks.has('express')).toBe(true);
  });

  it('does not confuse a lookalike package name', () => {
    const files = { 'package.json': JSON.stringify({ dependencies: { 'express-rate-limit': '7.0.0' } }) };
    expect(detectFrameworks(reader(files)).has('express')).toBe(false);
  });

  it('falls back to agnostic on malformed package.json', () => {
    expect(detectFrameworks(reader({ 'package.json': '{ not json' }))).toEqual(new Set(['agnostic']));
  });

  it('detects Next.js from a config file when package.json is unreadable', () => {
    const frameworks = detectFrameworks(reader({ 'next.config.mjs': 'export default {};' }));
    expect(frameworks.has('nextjs')).toBe(true);
  });
});
