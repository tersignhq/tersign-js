import { describe, expect, it } from 'vitest';
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import { signReceipt, verifyReceipt } from '../src/receipt/eip712.js';
import type { ReceiptPayload } from '../src/types.js';

const payload: ReceiptPayload = {
  version: 1,
  network: 'eip155:8453',
  resourceUrl: 'https://api.example.com/premium-data',
  payer: '0x857b06519E91e3A54538791bDbb0E22373e36b66',
  issuedAt: 1751856000,
  transaction: '',
};

describe('offer-receipt EIP-712', () => {
  it('sign/verify roundtrip recovers the signer (payTo authorization model)', async () => {
    const account = privateKeyToAccount(generatePrivateKey());
    const receipt = await signReceipt(payload, account);
    const result = await verifyReceipt(receipt, account.address);
    expect(result.valid).toBe(true);
    expect(result.signer?.toLowerCase()).toBe(account.address.toLowerCase());
  });

  it('rejects a wrong expected signer', async () => {
    const account = privateKeyToAccount(generatePrivateKey());
    const other = privateKeyToAccount(generatePrivateKey());
    const receipt = await signReceipt(payload, account);
    const result = await verifyReceipt(receipt, other.address);
    expect(result.valid).toBe(false);
  });

  it('rejects a tampered payload', async () => {
    const account = privateKeyToAccount(generatePrivateKey());
    const receipt = await signReceipt(payload, account);
    if (receipt.format !== 'eip712') throw new Error('unexpected');
    const tampered = { ...receipt, payload: { ...receipt.payload, payer: '0x0000000000000000000000000000000000000001' } };
    const result = await verifyReceipt(tampered, account.address);
    expect(result.valid).toBe(false);
  });
});
