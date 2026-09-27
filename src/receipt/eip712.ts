import { recoverTypedDataAddress } from 'viem';
import type { Account } from 'viem/accounts';
import type { OfferPayload, ReceiptPayload, SignedOffer, SignedReceipt } from '../types.js';
import { LONE_SURROGATE, bindSigner, byCodePoint, isPlainObject, parseExpectedSigner, signatureError, type SignerBinding } from './binding.js';

/** Canonical EIP-712 material from the merged offer-receipt extension. Domain chainId is
 * hardcoded to 1 by spec (off-chain signing format; payment network lives in payload.network). */

export const RECEIPT_DOMAIN = { name: 'x402 receipt', version: '1', chainId: 1n } as const;
export const OFFER_DOMAIN = { name: 'x402 offer', version: '1', chainId: 1n } as const;

export const RECEIPT_TYPES = {
  Receipt: [
    { name: 'version', type: 'uint256' },
    { name: 'network', type: 'string' },
    { name: 'resourceUrl', type: 'string' },
    { name: 'payer', type: 'string' },
    { name: 'issuedAt', type: 'uint256' },
    { name: 'transaction', type: 'string' },
  ],
} as const;

export const OFFER_TYPES = {
  Offer: [
    { name: 'version', type: 'uint256' },
    { name: 'resourceUrl', type: 'string' },
    { name: 'scheme', type: 'string' },
    { name: 'network', type: 'string' },
    { name: 'asset', type: 'string' },
    { name: 'payTo', type: 'string' },
    { name: 'amount', type: 'string' },
    { name: 'validUntil', type: 'uint256' },
  ],
} as const;

function receiptMessage(p: ReceiptPayload) {
  return {
    version: BigInt(p.version),
    network: p.network,
    resourceUrl: p.resourceUrl,
    payer: p.payer,
    issuedAt: BigInt(p.issuedAt),
    transaction: p.transaction,
  };
}

function offerMessage(p: OfferPayload) {
  return {
    version: BigInt(p.version),
    resourceUrl: p.resourceUrl,
    scheme: p.scheme,
    network: p.network,
    asset: p.asset,
    payTo: p.payTo,
    amount: p.amount,
    validUntil: BigInt(p.validUntil),
  };
}

export async function signReceipt(payload: ReceiptPayload, account: Account): Promise<SignedReceipt> {
  if (!account.signTypedData) throw new Error('account cannot sign typed data');
  const signature = await account.signTypedData({
    domain: RECEIPT_DOMAIN,
    types: RECEIPT_TYPES,
    primaryType: 'Receipt',
    message: receiptMessage(payload),
  });
  return { format: 'eip712', payload, signature };
}

export async function signOffer(payload: OfferPayload, account: Account, acceptIndex?: number): Promise<SignedOffer> {
  if (!account.signTypedData) throw new Error('account cannot sign typed data');
  const signature = await account.signTypedData({
    domain: OFFER_DOMAIN,
    types: OFFER_TYPES,
    primaryType: 'Offer',
    message: offerMessage(payload),
  });
  return acceptIndex === undefined
    ? { format: 'eip712', payload, signature }
    : { format: 'eip712', payload, signature, acceptIndex };
}

/** What the EIP-712 Receipt signature covers. Anything else in the artifact rides along
 * unsigned: it changes the canonical digest (the ledger's content address) but not the
 * recovered signer. */
export const SIGNED_RECEIPT_FIELDS = RECEIPT_TYPES.Receipt.map((f) => f.name);
const ENVELOPE_FIELDS: ReadonlySet<string> = new Set(['format', 'payload', 'signature']);
const SIGNED: ReadonlySet<string> = new Set(SIGNED_RECEIPT_FIELDS);

/** Fields present in `artifact` that the signature does not cover, as paths relative to the
 * artifact — `payload.<k>` first, then top-level keys — in code-point order. */
export function unsignedReceiptFields(artifact: Record<string, unknown>): string[] {
  const payload = isPlainObject(artifact.payload) ? artifact.payload : {};
  return [
    ...Object.keys(payload).filter((k) => !SIGNED.has(k)).sort(byCodePoint).map((k) => `payload.${k}`),
    ...Object.keys(artifact).filter((k) => !ENVELOPE_FIELDS.has(k)).sort(byCodePoint),
  ];
}

function typeName(v: unknown): string {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  if (typeof v === 'number' && !Number.isInteger(v)) return 'a non-integer number';
  if (typeof v === 'number') return v < 0 ? 'a negative integer' : 'an integer outside the safe range';
  return typeof v;
}

/** The payload's signed fields, checked by JSON type before anything is recovered. BigInt()
 * coerces true, "1", " 1783761710 " and "0x6a4…" to the signed number: each such edit recovered
 * the real signer under a DIFFERENT digest, and nothing reported it. The ledger counter-signs
 * only JSON safe integers here, and the Python verifier applies the same rule. */
function signedFieldError(p: Record<string, unknown>): string | undefined {
  for (const k of ['version', 'issuedAt']) {
    const v = p[k];
    const ok = (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) || (typeof v === 'bigint' && v >= 0n && v < 2n ** 256n);
    if (!ok) return `payload.${k} must be a JSON integer, not ${typeName(v)}: the signature covers the number, so another spelling of it is unsigned text`;
  }
  for (const k of ['network', 'resourceUrl', 'payer', 'transaction']) {
    if (typeof p[k] !== 'string') return `payload.${k} must be a string, not ${typeName(p[k])}`;
    if (LONE_SURROGATE.test(p[k] as string)) {
      return `payload.${k} holds a lone UTF-16 surrogate (a \\uD800-\\uDFFF escape) that UTF-8 cannot carry: the signature covers U+FFFD in its place, not this text`;
    }
  }
  return undefined;
}

/** valid        the signature is well-formed and recovers to an address — and, when
 *               expectedSigner is given, to exactly that address.
 *  signerBound  true only when expectedSigner was supplied and matched. When false, `signer`
 *               is whatever the receipt's own signature recovers to, and recovery yields an
 *               address for ANY payload: an edited receipt still returns valid:true, with a
 *               different signer. valid:true with signerBound:false proves neither who signed
 *               nor that the payload is unmodified.
 *  testKey      the recovered signer is a PUBLISHED test key (known-keys.ts).
 *  unsignedFields  fields present in the artifact that the signature does not cover.
 * The same result shape as the Python twin's verify_receipt (minus its digest, which the
 * callers here compute themselves). */
export interface VerifyResult extends SignerBinding {
  unsignedFields?: string[];
}

/** Verify an EIP-712 receipt. `expectedSigner` implements the spec's payTo-key authorization
 * model; pass the seller's payTo address (or a registry-resolved key), obtained out-of-band,
 * to enforce it. Without it the recovered signer is UNAUTHENTICATED (signerBound:false). */
export async function verifyReceipt(artifact: SignedReceipt, expectedSigner?: string): Promise<VerifyResult> {
  const expected = parseExpectedSigner(expectedSigner);
  if (!expected.ok) return { valid: false, signerBound: false, reason: expected.reason };
  const notReceipt = { valid: false, signerBound: false, reason: 'not a signed receipt: expected {format, payload{...}, signature}' };
  if (!isPlainObject(artifact)) return notReceipt;
  if (artifact.format !== 'eip712') {
    return { valid: false, signerBound: false, reason: 'jws verification not implemented in v0' };
  }
  if (!isPlainObject((artifact as { payload?: unknown }).payload)) return notReceipt;
  const badField = signedFieldError(artifact.payload as unknown as Record<string, unknown>);
  if (badField) return { valid: false, signerBound: false, reason: badField };
  const badSig = signatureError((artifact as { signature?: unknown }).signature);
  if (badSig) return { valid: false, signerBound: false, reason: badSig };
  let signer: `0x${string}`;
  try {
    signer = await recoverTypedDataAddress({
      domain: RECEIPT_DOMAIN,
      types: RECEIPT_TYPES,
      primaryType: 'Receipt',
      message: receiptMessage(artifact.payload),
      signature: artifact.signature,
    });
  } catch (e) {
    return { valid: false, signerBound: false, reason: e instanceof Error ? e.message : 'signature recovery failed' };
  }
  const out: VerifyResult = bindSigner(signer, expected.value, 'signer does not match expected authorization key');
  const unsigned = unsignedReceiptFields(artifact as unknown as Record<string, unknown>);
  if (unsigned.length) out.unsignedFields = unsigned;
  return out;
}
