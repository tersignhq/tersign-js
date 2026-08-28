import { concatHex, keccak256, numberToHex, stringToHex, toBytes, type Hex } from 'viem';

/** Deterministic JSON — RFC 8785 (JCS) conformant for JSON-domain inputs: keys sorted by
 * UTF-16 code units, no whitespace, JSON.stringify scalar/escape semantics. Arrays keep
 * order; undefined properties are dropped (matches JSON.stringify semantics).
 *
 * The string is built directly, never via an object rebuild: JS engines hoist integer-like
 * keys ("1","2","10") into numeric order on insertion, which silently defeats a
 * sort-then-stringify round-trip (JCS orders them "1","10","2"). Byte-identical to the old
 * serializer for every shape without integer-like or control-char keys — the genesis receipt
 * digest and all pinned wire vectors are unchanged. */
export function canonicalStringify(value: unknown): string {
  return serialize(value) as string;
}

function serialize(value: unknown): string | undefined {
  if (value === null) return 'null';
  if (Array.isArray(value)) {
    return '[' + Array.from(value, (v) => serialize(v) ?? 'null').join(',') + ']';
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const parts: string[] = [];
    for (const key of Object.keys(obj).sort()) {
      const s = serialize(obj[key]);
      if (s !== undefined) parts.push(JSON.stringify(key) + ':' + s);
    }
    return '{' + parts.join(',') + '}';
  }
  // string/number/boolean serialize per JCS; undefined/function/symbol yield undefined (dropped)
  return JSON.stringify(value);
}

export function digestOf(value: unknown): `0x${string}` {
  return keccak256(toBytes(canonicalStringify(value)));
}

/** Hash-chain link, byte-identical to the hosted ledger's recompute: the ledger
 * counter-signs `keccak256(artifactDigest || prevDigest-or-32-zero-bytes || uint64be(seq))`.
 * `prevDigest` is the PREVIOUS record's artifactDigest (null at seq 1). */
export const GENESIS_DIGEST: Hex = `0x${'0'.repeat(64)}`;

export function chainLinkDigest(artifactDigest: Hex, prevDigest: Hex | null, seq: number): Hex {
  return keccak256(concatHex([artifactDigest, prevDigest ?? GENESIS_DIGEST, numberToHex(seq, { size: 8 })]));
}

/** Chain commitment accumulator (anchored since 2026-08-28). DERIVED, never signed, never
 * stored per row: acc_0 = keccak256(utf8("tersign-chain-commitment-v1")); acc_k =
 * keccak256(acc_{k-1} || link_k). A pure function of (a_1..a_k, 1..k) — any omission,
 * insertion, reordering or rewrite below k changes acc_k, so ONE anchored digest over acc_N
 * commits to the whole prefix. The anchor stamps digestOf({acc, head, schema, seq}).
 * Pinned cross-implementation (this SDK, the hosted ledger, the Python SDK and the evidence-bundle
 * verifier share the same test vectors): edit all or none. */
export const CHAIN_COMMITMENT_SCHEMA = 'tersign-chain-commitment-v1';
export const ACC_GENESIS: Hex = keccak256(stringToHex(CHAIN_COMMITMENT_SCHEMA));

export function chainAccumulatorStep(acc: Hex, link: Hex): Hex {
  return keccak256(concatHex([acc, link]));
}

export type ChainCommitment = { acc: Hex; head: Hex; schema: typeof CHAIN_COMMITMENT_SCHEMA; seq: number };

export function chainCommitment(seq: number, head: Hex, acc: Hex): ChainCommitment {
  return { acc, head, schema: CHAIN_COMMITMENT_SCHEMA, seq };
}

/** keccak256 over the JCS bytes of the commitment object — the anchored subject digest. */
export function commitmentDigest(seq: number, head: Hex, acc: Hex): Hex {
  return digestOf(chainCommitment(seq, head, acc));
}

/** A set of records that does not re-walk (gap, prev ≠ previous artifact, wrong seq): no
 * accumulator is derived over it — a value no independent recompute would reproduce. */
export class ChainIntegrityError extends Error {}

export type ChainRecordLike = { artifactDigest: Hex; prevDigest: Hex | null; seq: number };

/** Fold records 1..N (in seq order, dense, prev-continuous). Returns acc_N and the head
 * artifact digest a_N. Throws ChainIntegrityError on any discontinuity or on an empty set. */
export function foldAccumulator(records: ChainRecordLike[]): { acc: Hex; head: Hex } {
  if (records.length < 1) throw new ChainIntegrityError('no records to fold');
  let acc: Hex = ACC_GENESIS;
  let prev: Hex | null = null;
  for (let i = 0; i < records.length; i++) {
    const r = records[i]!;
    if (r.seq !== i + 1) throw new ChainIntegrityError(`seq ${r.seq} at position ${i + 1}`);
    if ((r.prevDigest ?? null) !== prev) throw new ChainIntegrityError(`prev mismatch at seq ${r.seq}`);
    acc = chainAccumulatorStep(acc, chainLinkDigest(r.artifactDigest, prev, r.seq));
    prev = r.artifactDigest;
  }
  return { acc, head: prev as Hex };
}

export type CommitmentVerifyResult = { ok: boolean; acc: Hex; digest: Hex; reason?: string };

/** Recompute the accumulator over `records` (seq 1..N as served by the ledger) and compare it
 * to an anchored commitment (the `commitment` object from `/v1/receipts/{digest}/verify`, or
 * any `{seq, acc, head?}`). `acc`/`digest` are the RECOMPUTED values — compare `digest` to the
 * anchor's subjectDigest. A truncated, substituted, reordered or renumbered prefix fails. */
export function verifyCommitment(
  records: ChainRecordLike[],
  commitment: { seq: number; acc: Hex | string; head?: Hex | string },
): CommitmentVerifyResult {
  let folded: { acc: Hex; head: Hex };
  try {
    folded = foldAccumulator(records);
  } catch (err) {
    const reason = err instanceof ChainIntegrityError ? err.message : String(err);
    return { ok: false, acc: ACC_GENESIS, digest: GENESIS_DIGEST, reason: `records do not re-walk: ${reason}` };
  }
  const digest = commitmentDigest(records.length, folded.head, folded.acc);
  if (records.length !== commitment.seq) {
    return { ok: false, acc: folded.acc, digest, reason: `records cover seq ≤ ${records.length}, commitment covers seq ≤ ${commitment.seq}` };
  }
  if (folded.acc.toLowerCase() !== String(commitment.acc).toLowerCase()) {
    return { ok: false, acc: folded.acc, digest, reason: 'accumulator mismatch: the commitment was not built over this prefix' };
  }
  if (commitment.head !== undefined && folded.head.toLowerCase() !== String(commitment.head).toLowerCase()) {
    return { ok: false, acc: folded.acc, digest, reason: 'head mismatch: the commitment names a different head record' };
  }
  return { ok: true, acc: folded.acc, digest };
}
