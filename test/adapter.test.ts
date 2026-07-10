import { describe, expect, it } from 'vitest';
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import { Assure } from '../src/assure.js';
import { withAssure, extractSettlement } from '../src/adapter/x402.js';
import { verifyReceipt } from '../src/receipt/eip712.js';
import { MemoryIdempotencyStore } from '../src/idempotency/middleware.js';
import type { SignedReceipt } from '../src/types.js';

const account = privateKeyToAccount(generatePrivateKey());
const assure = new Assure({ signer: account, issuer: { name: 'T', jurisdiction: 'HK' } });
const clock = () => 1751856000;

function settlementHeader(payer: string) {
  return btoa(JSON.stringify({ success: true, transaction: '0x' + 'cd'.repeat(32), network: 'eip155:8453', payer }));
}

const inner = async () =>
  new Response(JSON.stringify({ data: 42 }), {
    headers: {
      'content-type': 'application/json',
      'payment-response': settlementHeader('0x857b06519E91e3A54538791bDbb0E22373e36b66'),
    },
  });

describe('withAssure adapter', () => {
  it('decorates a settled JSON response with receipt + compliance extensions', async () => {
    const wrapped = withAssure(inner, { assure, clock });
    const res = await wrapped(new Request('https://api.example.com/v1/data'));
    const body = (await res.json()) as {
      data: number;
      extensions: Record<string, { info: Record<string, unknown> }>;
    };
    expect(body.data).toBe(42);
    const receipt = body.extensions['offer-receipt']?.info.receipt as SignedReceipt;
    const check = await verifyReceipt(receipt, account.address);
    expect(check.valid).toBe(true);
    expect(body.extensions['compliance-fields']?.info.record).toBeTruthy();
  });

  it('passes through unsettled responses untouched', async () => {
    const plain = async () => Response.json({ ok: true });
    const wrapped = withAssure(plain, { assure, clock });
    const res = await wrapped(new Request('https://api.example.com/free'));
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.extensions).toBeUndefined();
  });

  it('replays idempotent requests with the replay header', async () => {
    const store = new MemoryIdempotencyStore();
    const paymentHeader = btoa(
      JSON.stringify({ extensions: { 'payment-identifier': { info: { required: false, id: 'pay_' + 'a'.repeat(28) } } } }),
    );
    const wrapped = withAssure(inner, {
      assure,
      clock,
      idempotency: { store, required: false, scope: 's1:/v1/data' },
    });
    const mk = () => new Request('https://api.example.com/v1/data', { headers: { 'x-payment': paymentHeader } });
    const first = await wrapped(mk());
    expect(first.status).toBe(200);
    const second = await wrapped(mk());
    expect(second.headers.get('Idempotent-Replayed')).toBe('true');
    expect(await second.text()).toBe(await first.clone().text());
  });

  it('extractSettlement handles v1 and v2 header names and field aliases', () => {
    const v2 = new Headers({ 'payment-response': btoa(JSON.stringify({ success: true, txHash: '0xab', from: '0xcd' })) });
    const info = extractSettlement(v2);
    expect(info?.success).toBe(true);
    expect(info?.transaction).toBe('0xab');
    expect(info?.payer).toBe('0xcd');
    const v1 = new Headers({ 'x-payment-response': btoa(JSON.stringify({ success: false })) });
    expect(extractSettlement(v1)?.success).toBe(false);
  });
});
