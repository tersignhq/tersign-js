/** What an EIP-712 verify can and cannot establish about WHO signed — shared by verifyReceipt,
 * verifyComplianceRecord, the `tersign verify` CLI and the MCP verify tools, so those four
 * surfaces cannot drift apart on the one question a verify result is read for. verifyActionRecord,
 * verifyDispute and verifyEvidence do NOT use it: they have no signer binding and no canonical
 * signature check (PUNT-REGISTER R8).
 *
 * ECDSA recovery yields an address for ANY payload and ANY well-formed signature. An edited
 * receipt therefore still "verifies" — it recovers a different address. A recovered signer is
 * evidence of authorship only when it is compared against an address the caller obtained
 * somewhere else; without that comparison it is UNAUTHENTICATED, and every result says so. */
import { publishedKeyLabel } from './known-keys.js';

export const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

export const MALFORMED_EXPECTED_SIGNER = 'expectedSigner is not a 20-byte 0x-prefixed hex address';

/** undefined, null and '' mean "not supplied". Anything else must be a 20-byte hex address:
 * a malformed value is a FAILURE, never a silently skipped comparison (0, false, [] and {}
 * included — a caller who passed something meant to bind). */
export function parseExpectedSigner(
  v: unknown,
): { ok: true; value: string | undefined } | { ok: false; reason: string } {
  if (v === undefined || v === null || v === '') return { ok: true, value: undefined };
  if (typeof v !== 'string' || !ADDRESS_RE.test(v)) return { ok: false, reason: MALFORMED_EXPECTED_SIGNER };
  return { ok: true, value: v };
}

export type SignerStatus = 'BOUND' | 'UNAUTHENTICATED' | 'MISMATCH';

/** The fields every binding-aware verify result carries. */
export interface SignerBinding {
  valid: boolean;
  signer?: `0x${string}`;
  /** true only when an expected signer was supplied AND the signature recovers to exactly it.
   * false with valid:true means `signer` is whatever the artifact's own signature recovers to:
   * that proves neither who signed nor that the artifact is unmodified. */
  signerBound: boolean;
  /** present when the recovered signer is a PUBLISHED test key (see known-keys.ts): anyone can
   * produce that signature, so even a bound match says nothing about who issued it. */
  testKey?: string;
  reason?: string;
}

/** BOUND: matched the expected signer. MISMATCH: an expected signer was supplied and the
 * signature recovers to a different address. UNAUTHENTICATED: none was supplied. Undefined when
 * nothing was recovered. Decided from the inputs, never from the reason text. */
export function signerStatus(r: SignerBinding, expected: string | undefined): SignerStatus | undefined {
  if (!r.signer) return undefined;
  if (r.signerBound) return 'BOUND';
  return expected ? 'MISMATCH' : 'UNAUTHENTICATED';
}

/** Attach signerBound + testKey to a recovered signer, comparing against `expected` when given. */
export function bindSigner(
  signer: `0x${string}`,
  expected: string | undefined,
  mismatchReason: string,
): SignerBinding {
  const out: SignerBinding = { valid: true, signer, signerBound: expected !== undefined };
  const label = publishedKeyLabel(signer);
  if (label) out.testKey = label;
  if (expected !== undefined && signer.toLowerCase() !== expected.toLowerCase()) {
    out.valid = false;
    out.signerBound = false;
    out.reason = mismatchReason;
  }
  return out;
}

/** secp256k1 group order. A signature's s must be at most N/2 (Ethereum's canonical low-s form). */
const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

/** Why an EIP-712 `signature` is not THE canonical encoding, or undefined. Checked BEFORE
 * recovery, with the same rules as the Python twin's verify_receipt (sdk-py tersign/verify.py
 * signature_error). The canonical encoding is exactly one string per signer and message:
 *
 *   "0x" + 130 LOWER-CASE hex digits = r (32 bytes) || s (32 bytes) || v (1 byte), with
 *   1 <= r, s < n; s <= n/2 (low-s); v = 27 or 28 (0x1b / 0x1c) — what viem's
 *   serializeSignature emits, so every signature this package and the ledger produce.
 *
 * Everything else is refused, each with its own reason: a non-string ({r,s,v} object, 65-number
 * array), a missing 0x, any other length, an upper-case hex digit, the recovery-id twin (v = 0/1
 * for 27/28), an out-of-range r/s, and the high-s twin. viem accepts every one of those and
 * recovers the real signer from each, and each re-encoding gives the file a different content
 * digest — so without this one issuance had several "also valid" byte-distinct copies, each
 * printing a bound VALID for signature bytes the issuer never produced (high-s, object and array
 * found 2026-09-27; v 0/1 and upper-case hex found by the release review the same day).
 *
 * Scope: verifyReceipt, verifyComplianceRecord and the CLI and MCP tools built on them. The
 * action-record, dispute and evidence verifiers (evidence/action.ts, dispute/sign.ts) do NOT call
 * this and still accept what viem accepts (PUNT-REGISTER R8). Neither does the ledger's ingest
 * (SECURITY-AUDIT A8), so a receipt the ledger counter-signed with a non-canonical signature is
 * refused here. The reasons are package text only: nothing from the file is echoed. */
export function signatureError(sig: unknown): string | undefined {
  if (typeof sig !== 'string') {
    const t = sig === null ? 'null' : Array.isArray(sig) ? 'an array' : typeof sig === 'undefined' ? 'missing' : typeof sig === 'object' ? 'an object' : `a ${typeof sig}`;
    return `signature must be a 0x-prefixed hex string of 65 bytes (r||s||v), not ${t}`;
  }
  if (!/^0x[0-9a-fA-F]{130}$/.test(sig)) return 'signature must be a 0x-prefixed hex string of 65 bytes (r||s||v)';
  if (/[A-F]/.test(sig)) return 'signature hex must be lower-case (non-canonical)';
  const r = BigInt(`0x${sig.slice(2, 66)}`);
  const s = BigInt(`0x${sig.slice(66, 130)}`);
  const v = Number.parseInt(sig.slice(130, 132), 16);
  if (v === 0 || v === 1) return `recovery id ${v} rejected (non-canonical): v must be 27 or 28`;
  if (v !== 27 && v !== 28) return `unsupported recovery id ${v}`;
  if (r < 1n || r >= SECP256K1_N || s < 1n || s >= SECP256K1_N) return 'r/s out of range';
  if (s > SECP256K1_N / 2n) return 'high-s signature rejected (non-canonical)';
  return undefined;
}

/** A UTF-16 surrogate with no partner. JSON's \uD800-\uDFFF escapes can put one in a parsed string;
 * UTF-8 cannot carry it, so the EIP-712 encoder (viem's TextEncoder) signs U+FFFD in its place and
 * the text the file holds is not the text that was signed. The Python verifier refuses such a file
 * outright ('utf-8' codec can't encode). */
export const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** The first string (key or value) anywhere in `v` holding a lone surrogate, as a path, or null. */
export function findLoneSurrogate(v: unknown, path = '$'): string | null {
  if (typeof v === 'string') return LONE_SURROGATE.test(v) ? path : null;
  if (Array.isArray(v)) {
    for (let i = 0; i < v.length; i++) {
      const hit = findLoneSurrogate(v[i], `${path}[${i}]`);
      if (hit) return hit;
    }
    return null;
  }
  if (isPlainObject(v)) {
    for (const [k, x] of Object.entries(v)) {
      if (LONE_SURROGATE.test(k)) return `${path} (a key)`;
      const hit = findLoneSurrogate(x, `${path}.${k}`);
      if (hit) return hit;
    }
  }
  return null;
}

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Code-point order — the order Python's sorted() gives, so both verifiers list fields alike. */
export function byCodePoint(a: string, b: string): number {
  const x = a[Symbol.iterator]();
  const y = b[Symbol.iterator]();
  for (;;) {
    const p = x.next();
    const q = y.next();
    if (p.done || q.done) return (p.done ? 0 : 1) - (q.done ? 0 : 1);
    const d = (p.value.codePointAt(0) ?? 0) - (q.value.codePointAt(0) ?? 0);
    if (d !== 0) return d;
  }
}

/** Render text that came from the artifact (a field NAME, a ledger's string) so it can never
 * forge output: control, format and line/paragraph-separator characters become \u escapes.
 * Without this a payload key such as "x\nVALID" would print a bare VALID line of its own. */
export function safeText(s: string, max = 96): string {
  return escapeInvisible(clip(s, max));
}

/** A field name as a JSON string literal — `"payload.amount"` — clipped, quotes and
 * backslashes escaped by JSON.stringify, and the invisible characters it leaves raw
 * (U+2028/U+2029, bidi and other format controls) escaped too. */
export function quoteField(name: string): string {
  return escapeInvisible(JSON.stringify(clip(name, 64)));
}

function clip(s: string, max: number): string {
  const cps = [...s];
  return cps.length > max ? cps.slice(0, max).join('') + '…' : s;
}

function escapeInvisible(s: string): string {
  return s.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, (ch) => {
    const cp = ch.codePointAt(0) ?? 0;
    return cp > 0xffff ? `\\u{${cp.toString(16)}}` : `\\u${cp.toString(16).padStart(4, '0')}`;
  });
}
