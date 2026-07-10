import { recoverTypedDataAddress } from 'viem';
import type { Account } from 'viem/accounts';
import { digestOf } from '../canonical.js';
import type {
  AcceptanceCriteriaV1,
  CriteriaAttestationPayload,
  DisputeAttestationPayload,
  DisputePayloadV1,
  EvidenceAttestationPayload,
  EvidencePayloadV1,
  SignedCriteria,
  SignedDispute,
  SignedEvidence,
  VerifyLike,
} from './types.js';

export const DISPUTE_DOMAIN = { name: 'tersign dispute', version: '1', chainId: 1n } as const;
export const EVIDENCE_DOMAIN = { name: 'tersign evidence', version: '1', chainId: 1n } as const;
export const CRITERIA_DOMAIN = { name: 'tersign acceptance-criteria', version: '1', chainId: 1n } as const;

export const DISPUTE_TYPES = {
  DisputeAttestation: [
    { name: 'version', type: 'uint256' },
    { name: 'disputeDigest', type: 'bytes32' },
    { name: 'receiptDigest', type: 'bytes32' },
    { name: 'openedAt', type: 'uint256' },
  ],
} as const;

export const EVIDENCE_TYPES = {
  EvidenceAttestation: [
    { name: 'version', type: 'uint256' },
    { name: 'evidenceDigest', type: 'bytes32' },
    { name: 'disputeDigest', type: 'bytes32' },
    { name: 'submittedAt', type: 'uint256' },
  ],
} as const;

export const CRITERIA_TYPES = {
  CriteriaAttestation: [
    { name: 'version', type: 'uint256' },
    { name: 'criteriaDigest', type: 'bytes32' },
    { name: 'issuedAt', type: 'uint256' },
  ],
} as const;

/** Pinned digest of the dispute-layer EIP-712 material. The ledger re-declares these
 * constants (Workers bundle, no shared package yet) and pins the SAME vector — if either
 * side edits a domain or type, the cross-impl test breaks before signatures do. */
export const DISPUTE_WIRE_VECTOR: `0x${string}` = digestOf({
  domains: {
    dispute: { ...DISPUTE_DOMAIN, chainId: 1 },
    evidence: { ...EVIDENCE_DOMAIN, chainId: 1 },
    criteria: { ...CRITERIA_DOMAIN, chainId: 1 },
  },
  types: { ...DISPUTE_TYPES, ...EVIDENCE_TYPES, ...CRITERIA_TYPES },
});

export function disputeDigest(dispute: DisputePayloadV1): `0x${string}` {
  return digestOf(dispute);
}

export function evidenceDigest(evidence: EvidencePayloadV1): `0x${string}` {
  return digestOf(evidence);
}

export function criteriaDigest(criteria: AcceptanceCriteriaV1): `0x${string}` {
  return digestOf(criteria);
}

/** Sign a dispute as the CLAIMANT. The ledger only accepts disputes whose recovered
 * signer equals the disputed receipt's `payer` — possession of the paying key IS the
 * standing to dispute. */
export async function signDispute(dispute: DisputePayloadV1, account: Account): Promise<SignedDispute> {
  if (!account.signTypedData) throw new Error('account cannot sign typed data');
  const payload: DisputeAttestationPayload = {
    version: 1,
    disputeDigest: disputeDigest(dispute),
    receiptDigest: dispute.receiptDigest,
    openedAt: dispute.openedAt,
  };
  const signature = await account.signTypedData({
    domain: DISPUTE_DOMAIN,
    types: DISPUTE_TYPES,
    primaryType: 'DisputeAttestation',
    message: {
      version: BigInt(payload.version),
      disputeDigest: payload.disputeDigest,
      receiptDigest: payload.receiptDigest,
      openedAt: BigInt(payload.openedAt),
    },
  });
  return { dispute, attestation: { format: 'eip712', payload, signature } };
}

export async function verifyDispute(signed: SignedDispute, expectedSigner?: string): Promise<VerifyLike> {
  const { dispute, attestation } = signed;
  if (attestation.format !== 'eip712') return { valid: false, reason: 'jws not implemented in v0' };
  if (attestation.payload.disputeDigest !== disputeDigest(dispute)) {
    return { valid: false, reason: 'dispute digest mismatch — dispute was altered after signing' };
  }
  if (attestation.payload.receiptDigest !== dispute.receiptDigest) {
    return { valid: false, reason: 'attestation/receipt digest mismatch' };
  }
  try {
    const signer = await recoverTypedDataAddress({
      domain: DISPUTE_DOMAIN,
      types: DISPUTE_TYPES,
      primaryType: 'DisputeAttestation',
      message: {
        version: BigInt(attestation.payload.version),
        disputeDigest: attestation.payload.disputeDigest,
        receiptDigest: attestation.payload.receiptDigest,
        openedAt: BigInt(attestation.payload.openedAt),
      },
      signature: attestation.signature,
    });
    if (expectedSigner && signer.toLowerCase() !== expectedSigner.toLowerCase()) {
      return { valid: false, signer, reason: 'signer is not the receipt payer' };
    }
    return { valid: true, signer };
  } catch (e) {
    return { valid: false, reason: e instanceof Error ? e.message : 'signature recovery failed' };
  }
}

/** Sign evidence as either party. Role/identity binding is enforced by the ledger:
 * claimant evidence must recover to the receipt payer, respondent evidence to the
 * seller's payTo key. */
export async function signEvidence(evidence: EvidencePayloadV1, account: Account): Promise<SignedEvidence> {
  if (!account.signTypedData) throw new Error('account cannot sign typed data');
  const payload: EvidenceAttestationPayload = {
    version: 1,
    evidenceDigest: evidenceDigest(evidence),
    disputeDigest: evidence.disputeDigest,
    submittedAt: evidence.submittedAt,
  };
  const signature = await account.signTypedData({
    domain: EVIDENCE_DOMAIN,
    types: EVIDENCE_TYPES,
    primaryType: 'EvidenceAttestation',
    message: {
      version: BigInt(payload.version),
      evidenceDigest: payload.evidenceDigest,
      disputeDigest: payload.disputeDigest,
      submittedAt: BigInt(payload.submittedAt),
    },
  });
  return { evidence, attestation: { format: 'eip712', payload, signature } };
}

export async function verifyEvidence(signed: SignedEvidence, expectedSigner?: string): Promise<VerifyLike> {
  const { evidence, attestation } = signed;
  if (attestation.format !== 'eip712') return { valid: false, reason: 'jws not implemented in v0' };
  if (attestation.payload.evidenceDigest !== evidenceDigest(evidence)) {
    return { valid: false, reason: 'evidence digest mismatch — evidence was altered after signing' };
  }
  if (attestation.payload.disputeDigest !== evidence.disputeDigest) {
    return { valid: false, reason: 'attestation/dispute digest mismatch' };
  }
  try {
    const signer = await recoverTypedDataAddress({
      domain: EVIDENCE_DOMAIN,
      types: EVIDENCE_TYPES,
      primaryType: 'EvidenceAttestation',
      message: {
        version: BigInt(attestation.payload.version),
        evidenceDigest: attestation.payload.evidenceDigest,
        disputeDigest: attestation.payload.disputeDigest,
        submittedAt: BigInt(attestation.payload.submittedAt),
      },
      signature: attestation.signature,
    });
    if (expectedSigner && signer.toLowerCase() !== expectedSigner.toLowerCase()) {
      return { valid: false, signer, reason: 'unexpected signer for this evidence role' };
    }
    return { valid: true, signer };
  } catch (e) {
    return { valid: false, reason: e instanceof Error ? e.message : 'signature recovery failed' };
  }
}

/** Sign acceptance criteria as the SELLER, pre-committing the machine-checkable bar the
 * arbiter will hold the delivery to. Attach the returned digest to offers/records. */
export async function signCriteria(criteria: AcceptanceCriteriaV1, account: Account): Promise<SignedCriteria> {
  if (!account.signTypedData) throw new Error('account cannot sign typed data');
  const payload: CriteriaAttestationPayload = {
    version: 1,
    criteriaDigest: criteriaDigest(criteria),
    issuedAt: criteria.issuedAt,
  };
  const signature = await account.signTypedData({
    domain: CRITERIA_DOMAIN,
    types: CRITERIA_TYPES,
    primaryType: 'CriteriaAttestation',
    message: {
      version: BigInt(payload.version),
      criteriaDigest: payload.criteriaDigest,
      issuedAt: BigInt(payload.issuedAt),
    },
  });
  return { criteria, attestation: { format: 'eip712', payload, signature } };
}

export async function verifyCriteria(signed: SignedCriteria, expectedSigner?: string): Promise<VerifyLike> {
  const { criteria, attestation } = signed;
  if (attestation.format !== 'eip712') return { valid: false, reason: 'jws not implemented in v0' };
  if (attestation.payload.criteriaDigest !== criteriaDigest(criteria)) {
    return { valid: false, reason: 'criteria digest mismatch — criteria were altered after signing' };
  }
  try {
    const signer = await recoverTypedDataAddress({
      domain: CRITERIA_DOMAIN,
      types: CRITERIA_TYPES,
      primaryType: 'CriteriaAttestation',
      message: {
        version: BigInt(attestation.payload.version),
        criteriaDigest: attestation.payload.criteriaDigest,
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
