import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { canonicalStringify, digestOf } from '../src/canonical.js';

// The published conformance fixtures are load-bearing public artifacts: external
// implementations check themselves against these bytes. This suite keeps the JSON
// files and the implementation from drifting apart.

const fixturesDir = join(__dirname, 'fixtures');
const vectors = JSON.parse(readFileSync(join(fixturesDir, 'canonical-vectors.json'), 'utf8'));
const sample = JSON.parse(readFileSync(join(fixturesDir, 'compliance-record.json'), 'utf8'));

describe('published canonical vectors', () => {
  for (const v of vectors.vectors) {
    it(`reproduces "${v.name}" byte-for-byte`, () => {
      expect(canonicalStringify(v.input)).toBe(v.canonical);
      expect(digestOf(v.input)).toBe(v.digest);
    });
  }
});

describe('published compliance-record fixture', () => {
  it('reproduces the canonical form and recordDigest', () => {
    expect(canonicalStringify(sample.record)).toBe(sample.canonical);
    expect(digestOf(sample.record)).toBe(sample.recordDigest);
  });
});
