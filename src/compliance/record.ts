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

export const COMPLIANCE_DOMAIN = { name: 'tersign compliance-record', version: '1', chainId: 1n } as const;

export const COMPLIANCE_TYPES = {
  ComplianceAttestation: [
    { name: 'version', type: 'uint256' },
    { name: 'recordDigest', type: 'bytes32' },
    { name: 'receiptDigest', type: 'bytes32' },
    { name: 'issuedAt', type: 'uint256' },
  ],
} as const;

export interface IssuerConfig {
  name: string;
  jurisdiction: string;
  taxId?: string;
  /** default 7 — HK IRO s.51C floor, ≥ MiCA 5+2 */
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

/** MINIMAL tier ≈ EU VAT Art 226b simplified-invoice content — legally sufficient for
 * sub-€100 supplies EU-wide, and the default for machine-to-machine micro-receipts. */
export function buildMinimalRecord(issuer: IssuerConfig, input: MinimalRecordInput): ComplianceRecordV1 {
  const record: ComplianceRecordV1 = {
    version: 1,
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

export async function verifyComplianceRecord(
  signed: SignedComplianceRecord,
  expectedSigner?: string,
): Promise<VerifyLike> {
  const { attestation, record } = signed;
  if (attestation.format !== 'eip712') return { valid: false, reason: 'jws not implemented in v0' };
  if (attestation.payload.recordDigest !== recordDigest(record)) {
    return { valid: false, reason: 'record digest mismatch — record was altered after signing' };
  }
  if (attestation.payload.receiptDigest !== record.receiptDigest) {
    return { valid: false, reason: 'attestation/receipt digest mismatch' };
  }
  try {
    const signer = await recoverTypedDataAddress({
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
    if (expectedSigner && signer.toLowerCase() !== expectedSigner.toLowerCase()) {
      return { valid: false, signer, reason: 'unexpected signer' };
    }
    return { valid: true, signer };
  } catch (e) {
    return { valid: false, reason: e instanceof Error ? e.message : 'signature recovery failed' };
  }
}
