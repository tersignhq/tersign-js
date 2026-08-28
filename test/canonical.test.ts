import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { Hex } from 'viem';
import {
  ACC_GENESIS,
  CHAIN_COMMITMENT_SCHEMA,
  ChainIntegrityError,
  GENESIS_DIGEST,
  canonicalStringify,
  chainAccumulatorStep,
  chainCommitment,
  chainLinkDigest,
  commitmentDigest,
  digestOf,
  foldAccumulator,
  verifyCommitment,
  type ChainRecordLike,
} from '../src/canonical.js';

describe('canonical (cross-impl contract with @tersign/ledger)', () => {
  it('sorts keys recursively and is key-order invariant', () => {
    expect(canonicalStringify({ b: 'x', a: 1 })).toBe('{"a":1,"b":"x"}');
    expect(digestOf({ b: 'x', a: 1 })).toBe(digestOf({ a: 1, b: 'x' }));
  });
  it('matches the pinned cross-implementation vector (ledger pins the same)', () => {
    expect(digestOf({ b: 'x', a: 1 })).toBe('0x84fc3d9faf736ddfdb9baab9973656bd8d9bd142f1dfff8aa513a774fddfdd04');
  });
  it('drops undefined and function properties like JSON.stringify', () => {
    expect(canonicalStringify({ a: 1, u: undefined, f: () => 1 })).toBe('{"a":1}');
  });
  it('orders integer-like keys by UTF-16 code units, not numerically (RFC 8785)', () => {
    // JS engines hoist integer-like keys into numeric order on object rebuild — the class
    // of divergence this vector exists to catch. JCS order: "1" < "10" < "2".
    expect(canonicalStringify({ '10': 'a', '2': 'b', '1': 'c' })).toBe('{"1":"c","10":"a","2":"b"}');
    expect(digestOf({ '10': 'a', '2': 'b', '1': 'c' })).toBe('0x426b770f81b8ad5e307bcfb767deb02f8d32cd340d81a946be88bb184857e81b');
  });
  it('orders control-char keys before digits (RFC 8785)', () => {
    expect(canonicalStringify({ '1': 'One', '\r': 'CR' })).toBe('{"\\r":"CR","1":"One"}');
  });
});

/** Chain commitment accumulator — cross-implementation pins (anchored since 2026-08-28).
 * Every value here is pinned IDENTICALLY in the hosted ledger's, the Python SDK's and the
 * evidence-bundle verifier's test suites: edit all or none. The tersign-first-13 fixture is the
 * LIVE genesis chain walked from the public /verify endpoint on 2026-08-28; the demo vectors are
 * the public conformance suite's p6 records. */
const DEMO_ACCS = [
  '0xe720e2ed33d43c61b5dba81994d46200a51c1b28207c555c034fadc8877217f1',
  '0x067d811a57c765d912c1096b279c2bf19fd904830ab8d0c3f56c7ff2653a8e16',
  '0xae28e0e8b22b15cd27de2390efbe4e3c206decbfe5cede4751b85410f6648f4f',
] as const;
const DEMO_DIGESTS = [
  '0x4672842890404de85d907f76149e3edb90687d233ad7efbaabf887f888053ef4',
  '0x5a811da59710bb115a7744189a9732f27883180f5821caa7a99979bc33257c29',
  '0xdb17ed57683dea4c9ff668a1e769503e933fcc4e133ea0a823f7ddfc7b6106cd',
] as const;
const P26_COMMITMENT_DIGEST = '0x0ba9d97eb4a80b863ff720fbf61cbda9f705633fab4b6da5b8648406a9be3745';
const N37_LAST_LINK_ONLY_ACC = '0x4062010194c5605f41afc27e0094266c1cee5063703f5614901893c7fb67ec64';
const N36_SUBSTITUTED_TRUE_ACC = '0x5479a41d713938384141892656be4e7e8e0ffbdf621b65b6f2194ccd2688e3ba';
// The live tersign-first chain: anchor row seller:<commitment_13> is CONFIRMED (Bitcoin block 964428).
const TERSIGN_FIRST_ACC_13 = '0xfc831c0f98c8ea5df6417cd26afa278ed4ab82a1e682d170e47aa4a4173c5511';
const TERSIGN_FIRST_HEAD_13 = '0x339800528596c7d53d32571ad999695aef6dfc8fc86dcc4fb827bb6080493961';
const TERSIGN_FIRST_COMMITMENT_13 = '0xcbbef04598368ed02ae67fc0c8ffade6753628d0b8faf4e9211c9dd49a2dbe7b';

type FixtureRow = { seq: number; artifactDigest: Hex; prevDigest: Hex | null };
const fixture = JSON.parse(readFileSync(join(__dirname, 'fixtures', 'tersign-first-13.json'), 'utf8')) as {
  records: FixtureRow[];
  expected: { link_1: Hex; acc_1: Hex; acc_13: Hex; commitment_13: Hex; head: Hex };
};
const demoRecords = (digests: readonly Hex[]): ChainRecordLike[] =>
  digests.map((d, i) => ({ artifactDigest: d, prevDigest: i === 0 ? null : digests[i - 1]!, seq: i + 1 }));

describe('chain commitment accumulator — pins (cross-impl contract with @tersign/ledger)', () => {
  it('seed is the tagged digest, never the zero sentinel', () => {
    expect(ACC_GENESIS).toBe('0x79dde68558318c3f4b7d1af20992f140584708a1001befee3e4ec19c217acfe3');
    expect(CHAIN_COMMITMENT_SCHEMA).toBe('tersign-chain-commitment-v1');
    expect(ACC_GENESIS).not.toBe(GENESIS_DIGEST);
  });

  it('the conformance p6 demo records fold to the pinned accumulators and the p26 commitment digest', () => {
    const objs = [1, 2, 3].map((i) => ({ demo: i, note: 'synthetic chain-set record' }));
    objs.forEach((o, i) => expect(digestOf(o)).toBe(DEMO_DIGESTS[i]));
    const records = demoRecords(DEMO_DIGESTS);
    expect(foldAccumulator(records.slice(0, 1)).acc).toBe(DEMO_ACCS[0]);
    expect(foldAccumulator(records.slice(0, 2)).acc).toBe(DEMO_ACCS[1]);
    const full = foldAccumulator(records);
    expect(full.acc).toBe(DEMO_ACCS[2]);
    expect(full.head).toBe(DEMO_DIGESTS[2]);
    expect(digestOf(chainCommitment(3, DEMO_DIGESTS[2], DEMO_ACCS[2]))).toBe(P26_COMMITMENT_DIGEST);
    expect(commitmentDigest(3, DEMO_DIGESTS[2], DEMO_ACCS[2])).toBe(P26_COMMITMENT_DIGEST);
    // JCS key order of the commitment object is fixed: acc, head, schema, seq
    expect(canonicalStringify(chainCommitment(3, DEMO_DIGESTS[2], DEMO_ACCS[2]))).toBe(
      `{"acc":"${DEMO_ACCS[2]}","head":"${DEMO_DIGESTS[2]}","schema":"tersign-chain-commitment-v1","seq":3}`,
    );
  });

  it('the live tersign-first chain (13 rows, walked from /verify) folds to the pinned acc_13 and commitment', () => {
    expect(fixture.records).toHaveLength(13);
    expect(chainLinkDigest(fixture.records[0]!.artifactDigest, null, 1)).toBe(fixture.expected.link_1);
    expect(foldAccumulator(fixture.records.slice(0, 1)).acc).toBe(fixture.expected.acc_1);
    const out = foldAccumulator(fixture.records);
    expect(out.acc).toBe(fixture.expected.acc_13);
    expect(out.acc).toBe(TERSIGN_FIRST_ACC_13);
    expect(out.head).toBe(fixture.expected.head);
    expect(out.head).toBe(TERSIGN_FIRST_HEAD_13);
    expect(commitmentDigest(13, out.head, out.acc)).toBe(fixture.expected.commitment_13);
    expect(commitmentDigest(13, out.head, out.acc)).toBe(TERSIGN_FIRST_COMMITMENT_13);
    const res = verifyCommitment(fixture.records, { seq: 13, acc: TERSIGN_FIRST_ACC_13, head: TERSIGN_FIRST_HEAD_13 });
    expect(res).toEqual({ ok: true, acc: TERSIGN_FIRST_ACC_13, digest: TERSIGN_FIRST_COMMITMENT_13 });
  });

  it('negative vectors: truncated, substituted, reordered, mutated and last-link-only all differ from the true acc', () => {
    const records = demoRecords(DEMO_DIGESTS);
    const truth = foldAccumulator(records).acc;
    expect(foldAccumulator(records.slice(0, 2)).acc).not.toBe(truth); // truncated prefix under the full head
    // n36: record 1 substituted, prevs recomputed so the STRUCTURAL chain still walks
    const sub = { demo: 1, note: 'synthetic chain-set record (substituted)' };
    const subDigest = digestOf(sub);
    expect(subDigest).toBe('0x9473ed5e265517974b7a073afd50605372f918a60177ca3655da2117520ef53c');
    const subRecords = demoRecords([subDigest, DEMO_DIGESTS[1], DEMO_DIGESTS[2]]);
    expect(foldAccumulator(subRecords).acc).toBe(N36_SUBSTITUTED_TRUE_ACC);
    expect(N36_SUBSTITUTED_TRUE_ACC).not.toBe(truth);
    // n37: an accumulator over the LAST link only — the "anchor commits to the last record" shape this ruling closes
    const lastLink = chainLinkDigest(DEMO_DIGESTS[2], DEMO_DIGESTS[1], 3);
    expect(chainAccumulatorStep(ACC_GENESIS, lastLink)).toBe(N37_LAST_LINK_ONLY_ACC);
    expect(N37_LAST_LINK_ONLY_ACC).not.toBe(truth);
    // order matters
    expect(chainAccumulatorStep(DEMO_ACCS[0], DEMO_ACCS[1])).not.toBe(chainAccumulatorStep(DEMO_ACCS[1], DEMO_ACCS[0]));
  });

  it('foldAccumulator is fail-closed: gaps, prev mismatches, renumbering and empty input throw ChainIntegrityError', () => {
    const records = demoRecords(DEMO_DIGESTS);
    expect(() => foldAccumulator([records[0]!, records[2]!])).toThrow(ChainIntegrityError);
    const bad = records.map((r) => ({ ...r }));
    bad[1]!.prevDigest = DEMO_DIGESTS[2];
    expect(() => foldAccumulator(bad)).toThrow(ChainIntegrityError);
    expect(() => foldAccumulator(records.map((r) => ({ ...r, seq: r.seq + 1 })))).toThrow(ChainIntegrityError);
    expect(() => foldAccumulator([])).toThrow(ChainIntegrityError);
  });

  it('verifyCommitment rejects truncated, substituted and renumbered inputs against the real commitment', () => {
    const records = demoRecords(DEMO_DIGESTS);
    const real = { seq: 3, acc: DEMO_ACCS[2], head: DEMO_DIGESTS[2] };
    expect(verifyCommitment(records, real)).toEqual({ ok: true, acc: DEMO_ACCS[2], digest: P26_COMMITMENT_DIGEST });
    // /verify-shaped commitment objects (extra fields, no head) are accepted as-is
    const fromVerify = { seq: 3, acc: DEMO_ACCS[2] as string, status: 'confirmed', bitcoinBlockHeight: 1 };
    expect(verifyCommitment(records, fromVerify).ok).toBe(true);

    // truncated: the first two records presented under the seq-3 commitment
    const truncated = verifyCommitment(records.slice(0, 2), real);
    expect(truncated.ok).toBe(false);
    expect(truncated.acc).toBe(DEMO_ACCS[1]);
    expect(truncated.reason).toMatch(/seq ≤ 2.*seq ≤ 3/);

    // substituted: record 1 rewritten, prevs recomputed so the structural chain still walks
    const subDigest = digestOf({ demo: 1, note: 'synthetic chain-set record (substituted)' });
    const substituted = verifyCommitment(demoRecords([subDigest, DEMO_DIGESTS[1], DEMO_DIGESTS[2]]), real);
    expect(substituted.ok).toBe(false);
    expect(substituted.acc).toBe(N36_SUBSTITUTED_TRUE_ACC);
    expect(substituted.reason).toMatch(/accumulator mismatch/);

    // renumbered: same records, seqs shifted (2..4) or swapped (1,3,2)
    const shifted = verifyCommitment(records.map((r) => ({ ...r, seq: r.seq + 1 })), real);
    expect(shifted.ok).toBe(false);
    expect(shifted.reason).toMatch(/do not re-walk/);
    const swapped = verifyCommitment([records[0]!, records[2]!, records[1]!], real);
    expect(swapped.ok).toBe(false);
    expect(swapped.reason).toMatch(/do not re-walk/);

    // last-link-only accumulator presented as the commitment
    const lastOnly = verifyCommitment(records, { seq: 3, acc: N37_LAST_LINK_ONLY_ACC });
    expect(lastOnly.ok).toBe(false);
    expect(lastOnly.reason).toMatch(/accumulator mismatch/);

    // head mismatch with a correct acc names the head
    const wrongHead = verifyCommitment(records, { seq: 3, acc: DEMO_ACCS[2], head: DEMO_DIGESTS[1] });
    expect(wrongHead.ok).toBe(false);
    expect(wrongHead.reason).toMatch(/head mismatch/);
  });
});
