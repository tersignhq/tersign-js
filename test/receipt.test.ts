import { describe, expect, it } from 'vitest';
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import { signReceipt, verifyReceipt } from '../src/receipt/eip712.js';
import type { ReceiptPayload, SignedReceipt } from '../src/types.js';

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

// x402 offer-and-receipt §5.5 step 2: payload.version selects the EIP-712 types and "currently
// only version 1 is defined". Before 0.6.2 a correctly signed version-2 receipt verified valid, bound.
describe('receipt payload.version: only version 1 is defined', () => {
  const V2_REASON =
    'payload.version 2 is not supported: version 1 is the only receipt version the x402 offer-and-receipt extension defines';

  it('a correctly signed version-2 receipt is refused, bound or not, before recovery', async () => {
    const account = privateKeyToAccount(generatePrivateKey());
    const receipt = await signReceipt({ ...payload, version: 2 } as unknown as ReceiptPayload, account);
    for (const expected of [account.address, undefined]) {
      expect(await verifyReceipt(receipt, expected)).toEqual({ valid: false, signerBound: false, reason: V2_REASON });
    }
  });

  it('a correctly signed version-0 receipt is refused too: the rule is exactly 1, not at most 1', async () => {
    const account = privateKeyToAccount(generatePrivateKey());
    const receipt = await signReceipt({ ...payload, version: 0 } as unknown as ReceiptPayload, account);
    for (const expected of [account.address, undefined]) {
      expect(await verifyReceipt(receipt, expected)).toEqual({
        valid: false,
        signerBound: false,
        reason: V2_REASON.replace('payload.version 2', 'payload.version 0'),
      });
    }
  });

  it('version 1, signed the same way, verifies bound (control)', async () => {
    const account = privateKeyToAccount(generatePrivateKey());
    const receipt = await signReceipt(payload, account);
    const r = await verifyReceipt(receipt, account.address);
    expect(r).toMatchObject({ valid: true, signerBound: true });
    expect(r.signer?.toLowerCase()).toBe(account.address.toLowerCase());
  });

  it("a string '1' is refused: the signature covers the number, not its spelling", async () => {
    const account = privateKeyToAccount(generatePrivateKey());
    const receipt = await signReceipt(payload, account);
    if (receipt.format !== 'eip712') throw new Error('unexpected');
    const edited = { ...receipt, payload: { ...receipt.payload, version: '1' } } as unknown as SignedReceipt;
    for (const expected of [account.address, undefined]) {
      const r = await verifyReceipt(edited, expected);
      expect(r).toMatchObject({ valid: false, signerBound: false });
      expect(r.reason).toBe('payload.version must be a JSON integer, not string: the signature covers the number, so another spelling of it is unsigned text');
    }
  });
});
