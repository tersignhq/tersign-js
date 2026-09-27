import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { canonicalStringify, chainLinkDigest, digestOf, foldAccumulator } from '../src/canonical.js';

/** The PUBLIC conformance vectors, decided by the TYPESCRIPT engine.
 *
 * These 19 vectors already existed, already carried both arms (10 valid / 9 reject) and
 * already asserted their own denominator — and they only ever ran against Python.
 * `sdk-py/tests/test_public_conformance.py` opens by asserting "the Python SDK decides the
 * PUBLIC conformance vectors the same way the TS engine does", which is a claim ABOUT
 * TypeScript that nothing tested against TypeScript. It was false: n10 (float), n11 (2^53)
 * and n35 (integer-valued float token) all say `reject`, and this engine accepted all three,
 * silently rounding 2^53+1 down to 2^53 so two distinct records shared one digest.
 *
 * A corpus run against one of two implementations measures that implementation, not the
 * agreement it exists to prove. This file is the other half.
 *
 * The vectors are VENDORED into this package (test/vectors), not read from ../sdk-py: the
 * published mirror (tersignhq/tersign-js) is a snapshot of sdk/ alone, and its publish CI runs
 * `npm test` there. Reading the Python copy threw ENOENT at module load in the mirror, i.e.
 * after the release tag was already public (2026-09-27, reproduced by simulating release-sdk.sh).
 * Both copies are checked against the public corpus by scripts/check-conformance-vendored.sh,
 * and against each other below wherever the monorepo is present. */

const VECTORS = join(__dirname, 'vectors');
const PY_VECTORS = join(__dirname, '..', '..', 'sdk-py', 'tests', 'vectors');
const EXPECTED_VECTOR_COUNT = 19;

type Vector = { id: string; kind: string; expect: 'valid' | 'reject'; input: Record<string, any> };

function normDigest(v: unknown): string | null {
  if (typeof v !== 'string') return null;
  const s = v.startsWith('0x') || v.startsWith('0X') ? v.slice(2) : v;
  return /^[0-9a-fA-F]{64}$/.test(s) ? '0x' + s.toLowerCase() : null;
}

/** Decide one vector using ONLY this package's primitives — the mirror of decide() in the
 * Python suite. Any throw from a primitive is a reject, exactly as a ValueError is there. */
function decide(vec: Vector): 'valid' | 'reject' {
  const inp = vec.input;
  switch (vec.kind) {
    case 'digest_recompute': {
      let got: string;
      try { got = digestOf(inp.payload); } catch { return 'reject'; }
      const expected = normDigest(inp.expected_digest);
      return expected !== null && got === expected ? 'valid' : 'reject';
    }
    case 'canonical_bytes': {
      // payload_text carries RAW JSON where the distinction under test cannot survive a parse
      // in every language — JS collapses the token `2.0` to `2`, which is precisely why the
      // ledger scans raw number tokens at ingest. Here the raw text is available, so the same
      // rule is applied before parsing rather than after.
      let got: string;
      try {
        if (typeof inp.payload_text === 'string') {
          if (/(^|[^"\w])-?\d+(\.\d+|[eE][+-]?\d+)/.test(stripStrings(inp.payload_text))) return 'reject';
          got = canonicalStringify(JSON.parse(inp.payload_text));
        } else {
          got = canonicalStringify(inp.payload);
        }
      } catch { return 'reject'; }
      return got === inp.claimed_canonical ? 'valid' : 'reject';
    }
    case 'chain_link': {
      const artifact = normDigest(inp.artifact_digest);
      const prev = inp.prev_digest === null || inp.prev_digest === undefined ? null : normDigest(inp.prev_digest);
      const seq = inp.seq;
      const expected = normDigest(inp.expected_link);
      if (artifact === null || expected === null) return 'reject';
      if (inp.prev_digest !== null && inp.prev_digest !== undefined && prev === null) return 'reject';
      if (typeof seq !== 'number' || !Number.isSafeInteger(seq) || seq < 1) return 'reject';
      try {
        return chainLinkDigest(artifact as `0x${string}`, prev as `0x${string}` | null, seq) === expected
          ? 'valid' : 'reject';
      } catch { return 'reject'; }
    }
    case 'chain_commitment': {
      // The corpus is a WIRE format (snake_case); this API is camelCase. Translating wrong is
      // how the Python suite's first draft failed two VALID vectors and looked like a
      // cross-language divergence when it was the test.
      let got: { acc: string; head: string };
      try {
        const records = [...inp.records]
          .sort((a: any, b: any) => a.seq - b.seq)
          .map((r: any) => ({ seq: r.seq, artifactDigest: r.artifact_digest, prevDigest: r.prev_digest ?? null }));
        got = foldAccumulator(records as any) as any;
      } catch { return 'reject'; }
      const head = inp.head ?? {};
      const claimedAcc = normDigest(head.acc);
      if (claimedAcc === null || got.acc !== claimedAcc) return 'reject';
      const claimedHead = normDigest(head.digest);
      if (claimedHead !== null && got.head !== claimedHead) return 'reject';
      return 'valid';
    }
    default:
      throw new Error(`undecidable kind vendored into this suite: ${vec.kind}`);
  }
}

/** Blank out string literals so a '.' inside a string is never read as a number token. */
function stripStrings(raw: string): string {
  return raw.replace(/"(?:[^"\\]|\\.)*"/g, '""');
}

const vectors: Vector[] = readdirSync(VECTORS)
  .filter((n) => n.endsWith('.json'))
  .sort()
  .map((n) => JSON.parse(readFileSync(join(VECTORS, n), 'utf8')));

describe('public conformance vectors — decided by the TypeScript engine', () => {
  // The denominator is asserted: a rename or a bad glob that silently decides fewer vectors is
  // the failure this corpus exists to prevent, and it would otherwise read as a pass.
  it(`decides all ${EXPECTED_VECTOR_COUNT} vectors`, () => {
    expect(vectors.length).toBe(EXPECTED_VECTOR_COUNT);
  });

  // Both arms asserted: an engine that accepted everything must fail the reject vectors, and
  // one that rejected everything must fail the valid ones.
  it('carries both arms', () => {
    expect(vectors.filter((v) => v.expect === 'valid').length).toBeGreaterThan(0);
    expect(vectors.filter((v) => v.expect === 'reject').length).toBeGreaterThan(0);
  });

  for (const v of vectors) {
    it(`${v.id} — ${v.expect}`, () => {
      expect(decide(v)).toBe(v.expect);
    });
  }

  // Two vendored copies of one corpus: in the monorepo they must be byte-identical, or the two
  // engines are being measured against different truths. Skipped only in the published mirror,
  // which carries sdk/ alone (release-sdk.sh runs this suite in the monorepo before it syncs).
  it.skipIf(!existsSync(PY_VECTORS))('is byte-identical to the Python suite\'s vendored copy', () => {
    const names = (d: string) => readdirSync(d).filter((n) => n.endsWith('.json')).sort();
    expect(names(VECTORS)).toEqual(names(PY_VECTORS));
    for (const n of names(VECTORS)) {
      expect(readFileSync(join(VECTORS, n)).equals(readFileSync(join(PY_VECTORS, n))), n).toBe(true);
    }
  });
});
