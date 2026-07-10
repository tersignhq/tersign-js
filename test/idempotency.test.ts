import { describe, expect, it } from 'vitest';
import {
  MemoryIdempotencyStore,
  checkIdempotency,
  extractPaymentId,
  fingerprint,
} from '../src/idempotency/middleware.js';

const fp = fingerprint({ method: 'POST', path: '/v1/data', scheme: 'exact', network: 'eip155:8453', amount: '10000' });
const fp2 = fingerprint({ method: 'POST', path: '/v1/data', scheme: 'exact', network: 'eip155:8453', amount: '20000' });
const ID = 'pay_7d5d747be160e280504c099d984bcfe0';

function opts(store: MemoryIdempotencyStore, required = false) {
  return { store, required, scope: 'seller-1:/v1/data' };
}

describe('idempotency behavior table (payment-identifier spec + ACP semantics)', () => {
  it('new id → process; completion caches; same id+fingerprint → replay', async () => {
    const store = new MemoryIdempotencyStore();
    const first = await checkIdempotency(opts(store), ID, fp);
    expect(first.kind).toBe('process');
    if (first.kind !== 'process') return;
    await first.onComplete({ status: 200, headers: {}, body: '{"ok":true}' });
    const second = await checkIdempotency(opts(store), ID, fp);
    expect(second.kind).toBe('replay');
    if (second.kind === 'replay') expect(second.response.body).toBe('{"ok":true}');
  });

  it('same id + different fingerprint → conflict (409)', async () => {
    const store = new MemoryIdempotencyStore();
    const first = await checkIdempotency(opts(store), ID, fp);
    if (first.kind === 'process') await first.onComplete({ status: 200, headers: {}, body: 'a' });
    const conflicting = await checkIdempotency(opts(store), ID, fp2);
    expect(conflicting.kind).toBe('conflict');
  });

  it('in-flight duplicate → in-flight (409, retry later)', async () => {
    const store = new MemoryIdempotencyStore();
    await checkIdempotency(opts(store), ID, fp); // reserved, not completed
    const dup = await checkIdempotency(opts(store), ID, fp);
    expect(dup.kind).toBe('in-flight');
  });

  it('required but missing → missing (400); optional missing → process uncached', async () => {
    const store = new MemoryIdempotencyStore();
    expect((await checkIdempotency(opts(store, true), undefined, fp)).kind).toBe('missing');
    expect((await checkIdempotency(opts(store, false), undefined, fp)).kind).toBe('process');
  });

  it('extracts a valid payment-identifier id and rejects malformed ones', () => {
    const good = { extensions: { 'payment-identifier': { info: { required: false, id: ID } } } };
    const short = { extensions: { 'payment-identifier': { info: { required: false, id: 'abc' } } } };
    expect(extractPaymentId(good)).toBe(ID);
    expect(extractPaymentId(short)).toBeUndefined();
    expect(extractPaymentId({})).toBeUndefined();
  });
});
