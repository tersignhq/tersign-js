import { recoverTypedDataAddress } from 'viem';
import type { Account } from 'viem/accounts';
import { digestOf } from '../canonical.js';
import type {
  Adjustment,
  ComplianceAttestationPayload,
  ComplianceRecordV1,
  SignedComplianceRecord,
  SignedReceipt,
  VerifyLike,
} from './types.js';
import { bindSigner, isPlainObject, parseExpectedSigner, signatureError, type SignerBinding } from '../receipt/binding.js';

/** EIP-712 domain named in the proposed compliance-fields extension (x402-foundation/x402#2853,
 * open — proposed, not settled spec). Migrated from the vendor domain 'tersign compliance-record' on 2026-07-14 while ZERO
 * production compliance records existed — a free change then, a breaking wire change after. */
export const COMPLIANCE_DOMAIN = { name: 'compliance-fields', version: '1', chainId: 1n } as const;

export const COMPLIANCE_TYPES = {
  ComplianceAttestation: [
    { name: 'version', type: 'uint256' },
    { name: 'recordDigest', type: 'bytes32' },
    { name: 'receiptDigest', type: 'bytes32' },
    { name: 'issuedAt', type: 'uint256' },
  ],
} as const;

/** Pinned digest of the compliance-attestation EIP-712 material (like DISPUTE_WIRE_VECTOR).
 * No cross-impl twin yet — the ledger does not re-declare this domain — but the pin catches
 * accidental drift; any change is a breaking protocol change (frozen wire format). */
export const COMPLIANCE_WIRE_VECTOR: `0x${string}` = digestOf({
  domain: { ...COMPLIANCE_DOMAIN, chainId: 1 },
  types: COMPLIANCE_TYPES,
});

export interface IssuerConfig {
  name: string;
  jurisdiction: string;
  taxId?: string;
  /** default 7 where no longer period applies (HK IRO s.51C, MiCA 5+2) — set the longest period
   * that applies to you (e.g. DE § 14b UStG: eight years); 7 is a default, not a sufficiency claim */
  retentionYears?: number;
}

export interface MinimalRecordInput {
  receipt: SignedReceipt;
  supplyDescription: string;
  tax: ComplianceRecordV1['tax'];
  issuedAt: number;
  buyer?: ComplianceRecordV1['buyer'];
  settlement?: ComplianceRecordV1['settlement'];
  refundOf?: `0x${string}`;
  adjustment?: Adjustment;
}

/** Build a record carrying the MINIMAL members of the proposed compliance-fields extension —
 * content isomorphic to the EU VAT Art 226b simplified invoice. Whether it suffices as an invoice
 * is decided by the invoicing rules that apply to the supply (Art 219a): Art 220a(1)(a) makes
 * every Member State allow simplified invoices up to EUR 100, a Member State may require further
 * details on them (Art 226b), and some supplies can never use one (Art 220(1)(2)-(3), Art 220a(2),
 * and national bars). MINIMAL needs `tax.amount` whenever `tax.scheme` is not `none`; that is the caller's
 * input. `seq` is not set here: it is the issuer's to assign before attestation. */
export function buildMinimalRecord(issuer: IssuerConfig, input: MinimalRecordInput): ComplianceRecordV1 {
  const record: ComplianceRecordV1 = {
    version: 1,
    canonicalizationVersion: 1,
    receiptDigest: digestOf(input.receipt),
    issuedAt: input.issuedAt,
    issuer: {
      name: issuer.name,
      jurisdiction: issuer.jurisdiction,
      ...(issuer.taxId !== undefined ? { taxId: issuer.taxId } : {}),
    },
    supply: { description: input.supplyDescription },
    tax: input.tax,
    retentionYears: issuer.retentionYears ?? 7,
  };
  if (input.buyer) record.buyer = input.buyer;
  if (input.settlement) record.settlement = input.settlement;
  if (input.refundOf) record.refundOf = input.refundOf;
  if (input.adjustment) record.adjustment = input.adjustment;
  return record;
}

export function recordDigest(record: ComplianceRecordV1): `0x${string}` {
  return digestOf(record);
}

export async function signComplianceRecord(
  record: ComplianceRecordV1,
  account: Account,
): Promise<SignedComplianceRecord> {
  if (!account.signTypedData) throw new Error('account cannot sign typed data');
  const payload: ComplianceAttestationPayload = {
    version: 1,
    recordDigest: recordDigest(record),
    receiptDigest: record.receiptDigest,
    issuedAt: record.issuedAt,
  };
  const signature = await account.signTypedData({
    domain: COMPLIANCE_DOMAIN,
    types: COMPLIANCE_TYPES,
    primaryType: 'ComplianceAttestation',
    message: {
      version: BigInt(payload.version),
      recordDigest: payload.recordDigest,
      receiptDigest: payload.receiptDigest,
      issuedAt: BigInt(payload.issuedAt),
    },
  });
  return { record, attestation: { format: 'eip712', payload, signature } };
}

/** VerifyLike plus the signer binding: signerBound is true only when expectedSigner was supplied
 * and matched; testKey flags a published test key. Without a bound signer a PASS proves the
 * record and attestation are internally consistent and nothing else — anyone can edit a record,
 * recompute its digest and re-sign the attestation with their own key. */
export type RecordVerifyResult = VerifyLike & SignerBinding;

export async function verifyComplianceRecord(
  signed: SignedComplianceRecord,
  expectedSigner?: string,
): Promise<RecordVerifyResult> {
  const expected = parseExpectedSigner(expectedSigner);
  if (!expected.ok) return { valid: false, signerBound: false, reason: expected.reason };
  if (
    !isPlainObject(signed) ||
    !isPlainObject((signed as { record?: unknown }).record) ||
    !isPlainObject((signed as { attestation?: unknown }).attestation) ||
    !isPlainObject((signed as { attestation: { payload?: unknown } }).attestation.payload)
  ) {
    return { valid: false, signerBound: false, reason: 'not a signed action record: expected {record, attestation{format, payload, signature}}' };
  }
  const { attestation, record } = signed;
  if (attestation.format !== 'eip712') return { valid: false, signerBound: false, reason: 'jws not implemented in v0' };
  let digest: `0x${string}`;
  try {
    digest = recordDigest(record);
  } catch (e) {
    return { valid: false, signerBound: false, reason: `cannot compute the record digest: ${e instanceof Error ? e.message : String(e)}` };
  }
  if (attestation.payload.recordDigest !== digest) {
    return { valid: false, signerBound: false, reason: 'record digest mismatch — record was altered after signing' };
  }
  if (attestation.payload.receiptDigest !== record.receiptDigest) {
    return { valid: false, signerBound: false, reason: 'attestation/receipt digest mismatch' };
  }
  const badSig = signatureError((attestation as { signature?: unknown }).signature);
  if (badSig) return { valid: false, signerBound: false, reason: `attestation ${badSig}` };
  let signer: `0x${string}`;
  try {
    signer = await recoverTypedDataAddress({
      domain: COMPLIANCE_DOMAIN,
      types: COMPLIANCE_TYPES,
      primaryType: 'ComplianceAttestation',
      message: {
        version: BigInt(attestation.payload.version),
        recordDigest: attestation.payload.recordDigest,
        receiptDigest: attestation.payload.receiptDigest,
        issuedAt: BigInt(attestation.payload.issuedAt),
      },
      signature: attestation.signature,
    });
  } catch (e) {
    return { valid: false, signerBound: false, reason: e instanceof Error ? e.message : 'signature recovery failed' };
  }
  return bindSigner(signer, expected.value, 'unexpected signer');
}
