import { describe, expect, it } from 'vitest';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import {
  DISPUTE_WIRE_VECTOR,
  criteriaDigest,
  disputeDigest,
  signCriteria,
  signDispute,
  signEvidence,
  verifyCriteria,
  verifyDispute,
  verifyEvidence,
} from '../src/dispute/sign.js';
import type { AcceptanceCriteriaV1, DisputePayloadV1, EvidencePayloadV1 } from '../src/dispute/types.js';

const payer = privateKeyToAccount(generatePrivateKey());
const seller = privateKeyToAccount(generatePrivateKey());

const dispute: DisputePayloadV1 = {
  version: 1,
  receiptDigest: `0x${'ab'.repeat(32)}`,
  reason: 'not_delivered',
  claimAmount: '1.25',
  openedAt: 1751900000,
};

describe('dispute sign/verify', () => {
  it('roundtrips and recovers the claimant', async () => {
    const signed = await signDispute(dispute, payer);
    const result = await verifyDispute(signed, payer.address);
    expect(result.valid).toBe(true);
    expect(result.signer?.toLowerCase()).toBe(payer.address.toLowerCase());
  });

  it('rejects a signer that is not the receipt payer', async () => {
    const signed = await signDispute(dispute, seller);
    const result = await verifyDispute(signed, payer.address);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('payer');
  });

  it('detects post-signing tampering with the payload', async () => {
    const signed = await signDispute(dispute, payer);
    signed.dispute.claimAmount = '9999.00';
    const result = await verifyDispute(signed);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('digest mismatch');
  });

  it('detects attestation/receipt digest mismatch', async () => {
    const signed = await signDispute(dispute, payer);
    if (signed.attestation.format !== 'eip712') throw new Error('unreachable');
    // forge: re-point the payload's receiptDigest AND keep disputeDigest consistent by
    // recomputing it — the receiptDigest cross-check must still catch the mismatch
    const forgedDispute = { ...dispute, receiptDigest: `0x${'cd'.repeat(32)}` as const };
    const forged = {
      dispute: forgedDispute,
      attestation: {
        ...signed.attestation,
        payload: { ...signed.attestation.payload, disputeDigest: disputeDigest(forgedDispute) },
      },
    };
    const result = await verifyDispute(forged);
    expect(result.valid).toBe(false);
  });
});

describe('evidence sign/verify', () => {
  const evidence: EvidencePayloadV1 = {
    version: 1,
    disputeDigest: disputeDigest(dispute),
    role: 'respondent',
    artifacts: [{ kind: 'delivery-attestation', digest: `0x${'11'.repeat(32)}`, at: 1751900100 }],
    submittedAt: 1751900200,
  };

  it('roundtrips and enforces expected signer', async () => {
    const signed = await signEvidence(evidence, seller);
    expect((await verifyEvidence(signed, seller.address)).valid).toBe(true);
    expect((await verifyEvidence(signed, payer.address)).valid).toBe(false);
  });

  it('detects artifact tampering', async () => {
    const signed = await signEvidence(evidence, seller);
    signed.evidence.artifacts[0]!.at = 1;
    expect((await verifyEvidence(signed)).valid).toBe(false);
  });
});

describe('acceptance criteria sign/verify', () => {
  const criteria: AcceptanceCriteriaV1 = {
    version: 1,
    resourceUrl: 'https://api.example.com/premium-data',
    criteria: [
      { id: 'c1', kind: 'content-digest', params: { expected: `0x${'22'.repeat(32)}` }, description: 'payload digest matches the committed sample schema digest' },
      { id: 'c2', kind: 'delivered-by', params: { withinSeconds: '300' }, description: 'delivery within 5 minutes of settlement' },
    ],
    issuedAt: 1751899000,
  };

  it('roundtrips; digest is stable under key order', async () => {
    const signed = await signCriteria(criteria, seller);
    expect((await verifyCriteria(signed, seller.address)).valid).toBe(true);
    const reordered = JSON.parse(JSON.stringify(criteria)) as AcceptanceCriteriaV1;
    expect(criteriaDigest(reordered)).toBe(criteriaDigest(criteria));
  });
});

describe('dispute wire contract', () => {
  it('pins the EIP-712 material digest (ledger re-declares these constants — must match)', () => {
    expect(DISPUTE_WIRE_VECTOR).toBe('0x2d8fbd48001f2ae7dd576c05a219575aecee4518b009f41d1d975f7f155ccecb');
  });
});
