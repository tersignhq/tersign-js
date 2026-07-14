import { describe, expect, it } from 'vitest';
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import { signReceipt } from '../src/receipt/eip712.js';
import {
  buildMinimalRecord,
  recordDigest,
  signComplianceRecord,
  verifyComplianceRecord,
} from '../src/compliance/record.js';
import type { ReceiptPayload } from '../src/types.js';

const receiptPayload: ReceiptPayload = {
  version: 1,
  network: 'eip155:8453',
  resourceUrl: 'https://api.example.com/translate',
  payer: '0x857b06519E91e3A54538791bDbb0E22373e36b66',
  issuedAt: 1751856000,
  transaction: '0x' + 'ab'.repeat(32),
};

const issuer = { name: 'Example API Ltd', jurisdiction: 'HK', taxId: 'BR-12345678' };

describe('compliance record', () => {
  it('binds to the receipt by digest and verifies', async () => {
    const account = privateKeyToAccount(generatePrivateKey());
    const receipt = await signReceipt(receiptPayload, account);
    const record = buildMinimalRecord(issuer, {
      receipt,
      supplyDescription: 'Insurance document translation, per call',
      tax: { scheme: 'none', currency: 'USD' },
      issuedAt: receiptPayload.issuedAt,
    });
    const signed = await signComplianceRecord(record, account);
    const result = await verifyComplianceRecord(signed, account.address);
    expect(result.valid).toBe(true);
  });

  it('detects post-signing record mutation', async () => {
    const account = privateKeyToAccount(generatePrivateKey());
    const receipt = await signReceipt(receiptPayload, account);
    const record = buildMinimalRecord(issuer, {
      receipt,
      supplyDescription: 'A',
      tax: { scheme: 'none', currency: 'USD' },
      issuedAt: receiptPayload.issuedAt,
    });
    const signed = await signComplianceRecord(record, account);
    signed.record.supply.description = 'B';
    const result = await verifyComplianceRecord(signed);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('digest mismatch');
  });

  it('refund records hash-chain to the original (ViDA corrective-invoice reference)', async () => {
    const account = privateKeyToAccount(generatePrivateKey());
    const receipt = await signReceipt(receiptPayload, account);
    const original = buildMinimalRecord(issuer, {
      receipt,
      supplyDescription: 'API call',
      tax: { scheme: 'none', currency: 'USD' },
      issuedAt: receiptPayload.issuedAt,
    });
    const refund = buildMinimalRecord(issuer, {
      receipt,
      supplyDescription: 'Refund: API call',
      tax: { scheme: 'none', currency: 'USD' },
      issuedAt: receiptPayload.issuedAt + 60,
      refundOf: recordDigest(original),
      adjustment: {
        type: 'refund',
        status: 'completed',
        amount: '10000',
        currency: 'USD',
        adjusts: recordDigest(original),
      },
    });
    expect(refund.refundOf).toBe(recordDigest(original));
    expect(recordDigest(refund)).not.toBe(recordDigest(original));
  });
});

describe('frozen wire format', () => {
  it('matches the pinned compliance wire vector (spec-canonical domain, PR #2853)', async () => {
    const { COMPLIANCE_WIRE_VECTOR } = await import('../src/compliance/record.js');
    expect(COMPLIANCE_WIRE_VECTOR).toBe('0xaf3e5ebc19f8679adca15beb48356028aa46e220cf2e744cd8797c0bba1beabd');
  });
});
