import { describe, expect, it, vi } from 'vitest';
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import { Assure } from '../src/assure.js';
import {
  withAssure,
  extractSettlement,
  encodeX402Header,
  COMPLIANCE_FIELDS_ADVERTISEMENT_SCHEMA,
} from '../src/adapter/x402.js';
import { verifyReceipt } from '../src/receipt/eip712.js';
import { verifyComplianceRecord } from '../src/compliance/record.js';
import { digestOf } from '../src/canonical.js';
import { MemoryIdempotencyStore } from '../src/idempotency/middleware.js';
import type { ComplianceAttestationPayload, ComplianceRecordV1, SignedArtifact, SignedReceipt } from '../src/types.js';

const account = privateKeyToAccount(generatePrivateKey());
const assure = new Assure({ signer: account, issuer: { name: 'T', jurisdiction: 'HK' } });
const clock = () => 1751856000;
const PAYER = '0x857b06519E91e3A54538791bDbb0E22373e36b66';
const TX = '0x' + 'cd'.repeat(32);

/** Decode exactly as the upstream x402 reference client does (typescript/packages/core
 * decodePaymentResponseHeader: Base64EncodedRegex gate, then safeBase64Decode's Node branch,
 * Buffer → UTF-8, then JSON.parse) — main 5eee1e3c35, read 2026-09-29. Independent of the
 * adapter's own decoder, so a wrong encoding cannot pass by agreeing with itself. */
const Base64EncodedRegex = /^[A-Za-z0-9+/]*={0,2}$/;
function upstreamDecode(header: string | null): Record<string, any> {
  if (header === null) throw new Error('header absent');
  if (!Base64EncodedRegex.test(header)) throw new Error('Invalid payment response header');
  return JSON.parse(Buffer.from(header, 'base64').toString('utf-8')) as Record<string, any>;
}
function upstreamEncode(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64');
}

function settlementHeader(extra: Record<string, unknown> = {}) {
  return upstreamEncode({ success: true, transaction: TX, network: 'eip155:8453', payer: PAYER, ...extra });
}

const BODY = JSON.stringify({ data: 42 });
const inner = async () =>
  new Response(BODY, {
    headers: { 'content-type': 'application/json', 'payment-response': settlementHeader() },
  });

type Issued = {
  receipt: SignedReceipt;
  record: ComplianceRecordV1;
  attestation: SignedArtifact<ComplianceAttestationPayload>;
};
function issuedFrom(settlement: Record<string, any>): Issued {
  return {
    receipt: settlement.extensions['offer-receipt'].info.receipt,
    record: settlement.extensions['compliance-fields'].info.record,
    attestation: settlement.extensions['compliance-fields'].info.attestation,
  };
}

describe('withAssure — PAYMENT-RESPONSE header placement (x402 v2 HTTP transport)', () => {
  it('merges a verifiable receipt and a bound, verifiable compliance record into PAYMENT-RESPONSE', async () => {
    const res = await withAssure(inner, { assure, clock })(new Request('https://api.example.com/v1/data'));
    const settlement = upstreamDecode(res.headers.get('payment-response'));
    const { receipt, record, attestation } = issuedFrom(settlement);
    expect((await verifyReceipt(receipt, account.address)).valid).toBe(true);
    expect(receipt.format === 'eip712' && receipt.payload.payer).toBe(PAYER);
    expect(record.receiptDigest).toBe(digestOf(receipt));
    expect((await verifyComplianceRecord({ record, attestation }, account.address)).valid).toBe(true);
    // offer-receipt entry carries the schema the upstream reference server attaches
    expect(settlement.extensions['offer-receipt'].schema.required).toEqual(['receipt']);
  });

  it('keeps every settlement member and every other extension it found', async () => {
    const handler = async () =>
      new Response(BODY, {
        headers: {
          'content-type': 'application/json',
          'payment-response': settlementHeader({ amount: '10000', extensions: { bazaar: { info: { k: 1, title: 'Übersetzung 翻訳' } } } }),
        },
      });
    const res = await withAssure(handler, { assure, clock })(new Request('https://api.example.com/v1/data'));
    const settlement = upstreamDecode(res.headers.get('payment-response'));
    expect(settlement.success).toBe(true);
    expect(settlement.transaction).toBe(TX);
    expect(settlement.network).toBe('eip155:8453');
    expect(settlement.payer).toBe(PAYER);
    expect(settlement.amount).toBe('10000');
    expect(settlement.extensions.bazaar).toEqual({ info: { k: 1, title: 'Übersetzung 翻訳' } });
  });

  it('leaves the response body byte-identical by default', async () => {
    const res = await withAssure(inner, { assure, clock })(new Request('https://api.example.com/v1/data'));
    expect(await res.text()).toBe(BODY);
    expect(res.status).toBe(200);
  });

  it('issues for a non-JSON paid response (no JSON body required)', async () => {
    const handler = async () =>
      new Response('plain bytes', { headers: { 'content-type': 'text/plain', 'payment-response': settlementHeader() } });
    const res = await withAssure(handler, { assure, clock })(new Request('https://api.example.com/v1/file'));
    const { receipt } = issuedFrom(upstreamDecode(res.headers.get('payment-response')));
    expect((await verifyReceipt(receipt, account.address)).valid).toBe(true);
    expect(await res.text()).toBe('plain bytes');
  });

  it('rewrites the v1 X-PAYMENT-RESPONSE header in place and adds no v2 header', async () => {
    const handler = async () =>
      new Response(BODY, { headers: { 'content-type': 'application/json', 'x-payment-response': settlementHeader() } });
    const res = await withAssure(handler, { assure, clock })(new Request('https://api.example.com/v1/data'));
    expect(res.headers.get('payment-response')).toBeNull();
    const { receipt } = issuedFrom(upstreamDecode(res.headers.get('x-payment-response')));
    expect((await verifyReceipt(receipt, account.address)).valid).toBe(true);
  });

  it('signs a v1 network name from X-PAYMENT-RESPONSE as CAIP-2 (offer-receipt: servers MUST convert)', async () => {
    // A v1 facilitator reports `network: "base"`; the receipt payload must carry "eip155:8453".
    const handler = async () =>
      new Response(BODY, {
        headers: { 'content-type': 'application/json', 'x-payment-response': settlementHeader({ network: 'base' }) },
      });
    const res = await withAssure(handler, { assure, clock })(new Request('https://api.example.com/v1/data'));
    const settlement = upstreamDecode(res.headers.get('x-payment-response'));
    const { receipt } = issuedFrom(settlement);
    expect('payload' in receipt && receipt.payload.network).toBe('eip155:8453');
    expect((await verifyReceipt(receipt, account.address)).valid).toBe(true);
    // The settlement member itself is the facilitator's and is left as it reported it.
    expect(settlement.network).toBe('base');
  });

  it('a v1 name outside the offer-receipt table but settled by upstream v1 EVM (monad) is signed, and replays', async () => {
    // @x402/evm EVM_NETWORK_CHAIN_ID_MAP lists "monad" (143); its v1 facilitator reports that name.
    // A refusal here would come after the handler ran, and the settled call would carry no receipt.
    const store = new MemoryIdempotencyStore();
    const paymentHeader = btoa(
      JSON.stringify({ extensions: { 'payment-identifier': { info: { required: false, id: 'pay_' + 'b'.repeat(28) } } } }),
    );
    const handler = async () =>
      new Response(BODY, {
        headers: { 'content-type': 'application/json', 'x-payment-response': settlementHeader({ network: 'monad' }) },
      });
    const wrapped = withAssure(handler, { assure, clock, idempotency: { store, required: false, scope: 's1:/v1/data' } });
    const mk = () => new Request('https://api.example.com/v1/data', { headers: { 'x-payment': paymentHeader } });
    const first = await wrapped(mk());
    expect(first.status).toBe(200);
    const { receipt } = issuedFrom(upstreamDecode(first.headers.get('x-payment-response')));
    expect('payload' in receipt && receipt.payload.network).toBe('eip155:143');
    expect((await verifyReceipt(receipt, account.address)).valid).toBe(true);
    const second = await wrapped(mk());
    expect(second.status).toBe(200);
    expect(second.headers.get('Idempotent-Replayed')).toBe('true');
  });

  it('a settled v1 network outside the table (bsc) delivers the paid response unchanged, signs and submits nothing, and replays', async () => {
    // 0.6.0 as first cut threw here, after the payment had settled: the paid 200 was lost and the
    // payment id stayed in flight. The receipt cannot carry "bsc" (no CAIP-2 form in the table), so
    // there is no receipt; the buyer still gets what they paid for.
    const store = new MemoryIdempotencyStore();
    const paymentHeader = btoa(
      JSON.stringify({ extensions: { 'payment-identifier': { info: { required: false, id: 'pay_' + 'c'.repeat(28) } } } }),
    );
    const settled = settlementHeader({ network: 'bsc' });
    let handlerRuns = 0;
    const handler = async () => {
      handlerRuns++;
      return new Response(BODY, {
        status: 200,
        headers: { 'content-type': 'application/json', 'x-payment-response': settled, 'x-seller': 'kept' },
      });
    };
    let ledgerCalls = 0;
    const fetchImpl = (async () => {
      ledgerCalls++;
      return Response.json({});
    }) as unknown as typeof fetch;
    const chained = new Assure({
      signer: account,
      issuer: { name: 'T', jurisdiction: 'HK' },
      ledger: { url: 'https://ledger.invalid', apiKey: 'k', sellerId: 's', fetchImpl },
    });
    const errors: unknown[] = [];
    const wrapped = withAssure(handler, {
      assure: chained,
      clock,
      legacyBodyPlacement: true,
      onError: (e) => errors.push(e),
      idempotency: { store, required: false, scope: 's1:/v1/data' },
    });
    const mk = () => new Request('https://api.example.com/v1/data', { headers: { 'x-payment': paymentHeader } });
    const signSpy = vi.spyOn(account, 'signTypedData');
    let first: Response;
    try {
      first = await wrapped(mk());
      // "signs nothing": the network is refused before any signature is made.
      expect(signSpy).not.toHaveBeenCalled();
    } finally {
      signSpy.mockRestore();
    }
    expect(first.status).toBe(200);
    expect(first.headers.get('x-payment-response')).toBe(settled);
    expect(first.headers.get('payment-response')).toBeNull();
    expect(first.headers.get('x-seller')).toBe('kept');
    expect(await first.clone().text()).toBe(BODY);
    expect(ledgerCalls).toBe(0);
    expect(errors).toHaveLength(1);
    expect(String((errors[0] as Error).message)).toMatch(/Unknown network identifier: "bsc"/);
    const second = await wrapped(mk());
    expect(second.status).toBe(200);
    expect(second.headers.get('Idempotent-Replayed')).toBe('true');
    expect(second.headers.get('x-payment-response')).toBe(settled);
    expect(await second.text()).toBe(BODY);
    expect(handlerRuns).toBe(1);
  });

  it('a ledger error after settlement delivers the paid response unchanged, and a throwing onError does not throw', async () => {
    const fetchImpl = (async () => new Response('down', { status: 503 })) as unknown as typeof fetch;
    const chained = new Assure({
      signer: account,
      issuer: { name: 'T', jurisdiction: 'HK' },
      ledger: { url: 'https://ledger.invalid', apiKey: 'k', sellerId: 's', fetchImpl },
    });
    const seen: unknown[] = [];
    const res = await withAssure(inner, {
      assure: chained,
      clock,
      onError: (e) => {
        seen.push(e);
        throw new Error('reporter broke');
      },
    })(new Request('https://api.example.com/v1/data'));
    expect(res.status).toBe(200);
    expect(res.headers.get('payment-response')).toBe(settlementHeader());
    expect(await res.text()).toBe(BODY);
    expect(String((seen[0] as Error).message)).toMatch(/ledger submit failed: 503/);
  });

  it.each([
    ['toSettlementContext', { toSettlementContext: () => { throw new Error('seller context broke'); } }],
    ['describeSupply', { describeSupply: () => { throw new Error('seller context broke'); } }],
  ] as const)('a throwing %s after settlement delivers the paid response unchanged and reports once', async (_name, hooks) => {
    const errors: unknown[] = [];
    const res = await withAssure(inner, { assure, clock, onError: (e) => errors.push(e), ...hooks })(
      new Request('https://api.example.com/v1/data'),
    );
    expect(res.status).toBe(200);
    expect(res.headers.get('payment-response')).toBe(settlementHeader());
    expect(await res.text()).toBe(BODY);
    expect(errors).toHaveLength(1);
    expect(String((errors[0] as Error).message)).toBe('seller context broke');
  });

  it('an async onError that rejects is ignored: the paid response goes out and no rejection is left unhandled', async () => {
    // The public type `(err: unknown) => void` accepts an async function; its rejection must not
    // reach the process (Node's default for an unhandled rejection is to exit).
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => unhandled.push(reason);
    process.on('unhandledRejection', onUnhandled);
    try {
      const settled = settlementHeader({ network: 'bsc' });
      const handler = async () =>
        new Response(BODY, { headers: { 'content-type': 'application/json', 'payment-response': settled } });
      let calls = 0;
      const res = await withAssure(handler, {
        assure,
        clock,
        onError: async () => {
          calls++;
          throw new Error('async reporter broke');
        },
      })(new Request('https://api.example.com/v1/data'));
      expect(res.status).toBe(200);
      expect(res.headers.get('payment-response')).toBe(settled);
      expect(await res.text()).toBe(BODY);
      expect(calls).toBe(1);
      // Node reports an unhandled rejection once the microtask queue drains; give it a macrotask.
      await new Promise((r) => setTimeout(r, 20));
      expect(unhandled).toEqual([]);
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }
  });

  it('the default reporter prints a multi-line ledger error body as one line', async () => {
    const html = '<!DOCTYPE html>\n<html>\n  <head><title>503 Service Unavailable</title></head>\n  <body>down</body>\n</html>\n';
    const fetchImpl = (async () =>
      new Response(html, { status: 503, headers: { 'content-type': 'text/html' } })) as unknown as typeof fetch;
    const chained = new Assure({
      signer: account,
      issuer: { name: 'T', jurisdiction: 'HK' },
      ledger: { url: 'https://ledger.invalid', apiKey: 'k', sellerId: 's', fetchImpl },
    });
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const res = await withAssure(inner, { assure: chained, clock })(new Request('https://api.example.com/v1/data'));
      expect(res.status).toBe(200);
      expect(await res.text()).toBe(BODY);
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.mock.calls[0]).toHaveLength(1);
      const line = String(spy.mock.calls[0]?.[0]);
      expect(line).not.toMatch(/[\r\n]/);
      expect(line).toMatch(/receipt not issued.*ledger submit failed: 503 <!DOCTYPE html> <html> <head><title>503 Service Unavailable<\/title><\/head> <body>down/);
    } finally {
      spy.mockRestore();
    }
  });

  it('the default reporter flattens a CRLF ledger error body to one line', async () => {
    const crlf = '<html>\r\n<body>\r\ndown\r\n</body>\r\n</html>\r\n';
    const fetchImpl = (async () =>
      new Response(crlf, { status: 503, headers: { 'content-type': 'text/html' } })) as unknown as typeof fetch;
    const chained = new Assure({
      signer: account,
      issuer: { name: 'T', jurisdiction: 'HK' },
      ledger: { url: 'https://ledger.invalid', apiKey: 'k', sellerId: 's', fetchImpl },
    });
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const res = await withAssure(inner, { assure: chained, clock })(new Request('https://api.example.com/v1/data'));
      expect(res.status).toBe(200);
      expect(spy).toHaveBeenCalledTimes(1);
      const line = String(spy.mock.calls[0]?.[0]);
      expect(line).not.toMatch(/[\r\n]/);
      expect(line).toMatch(/ledger submit failed: 503 <html> <body> down <\/body> <\/html>/);
    } finally {
      spy.mockRestore();
    }
  });

  it.each([
    ['an Error whose message is not a string', () => Object.assign(new Error('x'), { message: undefined })],
    ['a value String() cannot convert', () => Object.create(null) as unknown],
  ])('the default reporter still prints one line for %s', async (_label, make) => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const wrapped = withAssure(inner, {
        assure,
        clock,
        toSettlementContext: () => {
          throw make();
        },
      });
      const res = await wrapped(new Request('https://api.example.com/v1/data'));
      expect(res.status).toBe(200);
      expect(await res.text()).toBe(BODY);
      expect(spy).toHaveBeenCalledTimes(1);
      expect(String(spy.mock.calls[0]?.[0])).toMatch(/^tersign withAssure: receipt not issued, response delivered unchanged: /);
    } finally {
      spy.mockRestore();
    }
  });

  it('without onError, an issuance failure is written to console.error once', async () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const handler = async () => new Response(BODY, { headers: { 'payment-response': settlementHeader({ network: 'bsc' }) } });
      const res = await withAssure(handler, { assure, clock })(new Request('https://api.example.com/v1/data'));
      expect(await res.text()).toBe(BODY);
      expect(spy).toHaveBeenCalledTimes(1);
      expect(String(spy.mock.calls[0]?.[0])).toMatch(/receipt not issued.*Unknown network identifier: "bsc"/);
    } finally {
      spy.mockRestore();
    }
  });

  it('legacyBodyPlacement leaves a body that is not a JSON object as it is, and the header still carries the receipt', async () => {
    const notJson = 'not json {';
    const handler = async () =>
      new Response(notJson, { headers: { 'content-type': 'application/json', 'payment-response': settlementHeader() } });
    const errors: unknown[] = [];
    const res = await withAssure(handler, { assure, clock, legacyBodyPlacement: true, onError: (e) => errors.push(e) })(
      new Request('https://api.example.com/v1/data'),
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(notJson);
    const { receipt } = issuedFrom(upstreamDecode(res.headers.get('payment-response')));
    expect((await verifyReceipt(receipt, account.address)).valid).toBe(true);
    expect(errors).toHaveLength(0);
  });

  it('carries non-Latin-1 record text through the header as UTF-8 (upstream decoder reads it intact)', async () => {
    const utf8 = new Assure({ signer: account, issuer: { name: 'Müller Übersetzung GmbH 翻訳', jurisdiction: 'DE' } });
    const res = await withAssure(inner, { assure: utf8, clock, describeSupply: () => 'Übersetzung — 請求書' })(
      new Request('https://api.example.com/v1/data'),
    );
    const { record, attestation } = issuedFrom(upstreamDecode(res.headers.get('payment-response')));
    expect(record.issuer.name).toBe('Müller Übersetzung GmbH 翻訳');
    expect(record.supply.description).toBe('Übersetzung — 請求書');
    expect((await verifyComplianceRecord({ record, attestation }, account.address)).valid).toBe(true);
  });

  it('carries the ledger counter-signature block when the Assure is chained', async () => {
    const countersign = { id: 'r1', digest: ('0x' + 'ee'.repeat(32)) as `0x${string}`, seq: 7, prevDigest: null, countersignature: '0x' + '11'.repeat(65) };
    const fetchImpl = (async () => Response.json(countersign)) as unknown as typeof fetch;
    const chained = new Assure({
      signer: account,
      issuer: { name: 'T', jurisdiction: 'HK' },
      ledger: { url: 'https://ledger.invalid', apiKey: 'k', sellerId: 's', fetchImpl },
    });
    const res = await withAssure(inner, { assure: chained, clock })(new Request('https://api.example.com/v1/data'));
    const header = res.headers.get('payment-response');
    const settlement = upstreamDecode(header);
    expect(settlement.extensions['compliance-fields'].info.ledger).toEqual({
      seq: 7,
      digest: countersign.digest,
      countersignature: countersign.countersignature,
    });
    // Size tripwire: a chained minimal record must stay well under common 8 KiB proxy header buffers.
    expect(header!.length).toBeLessThan(4096);
  });

  it('passes unsettled and failed-settlement responses through untouched', async () => {
    const plain = async () => Response.json({ ok: true });
    const r1 = await withAssure(plain, { assure, clock })(new Request('https://api.example.com/free'));
    expect(await r1.json()).toEqual({ ok: true });
    const failedHeader = upstreamEncode({ success: false, errorReason: 'insufficient_funds', transaction: '', network: 'eip155:8453' });
    const failed = async () => new Response('{}', { status: 402, headers: { 'payment-response': failedHeader } });
    const r2 = await withAssure(failed, { assure, clock, advertise: false })(new Request('https://api.example.com/v1/data'));
    expect(r2.headers.get('payment-response')).toBe(failedHeader);
  });

  it('legacyBodyPlacement also decorates the JSON body, and the header still carries the same receipt', async () => {
    const res = await withAssure(inner, { assure, clock, legacyBodyPlacement: true })(
      new Request('https://api.example.com/v1/data'),
    );
    const header = issuedFrom(upstreamDecode(res.headers.get('payment-response')));
    const body = (await res.json()) as { data: number; extensions: Record<string, { info: Record<string, unknown> }> };
    expect(body.data).toBe(42);
    expect(body.extensions['offer-receipt']?.info.receipt).toEqual(header.receipt);
    expect(body.extensions['compliance-fields']?.info.record).toEqual(header.record);
  });

  it('replays idempotent requests with the replay header and the same PAYMENT-RESPONSE', async () => {
    const store = new MemoryIdempotencyStore();
    const paymentHeader = btoa(
      JSON.stringify({ extensions: { 'payment-identifier': { info: { required: false, id: 'pay_' + 'a'.repeat(28) } } } }),
    );
    let t = 1751856000;
    const wrapped = withAssure(inner, {
      assure,
      clock: () => t++,
      idempotency: { store, required: false, scope: 's1:/v1/data' },
    });
    const mk = () => new Request('https://api.example.com/v1/data', { headers: { 'x-payment': paymentHeader } });
    const first = await wrapped(mk());
    expect(first.status).toBe(200);
    const second = await wrapped(mk());
    expect(second.headers.get('Idempotent-Replayed')).toBe('true');
    expect(second.headers.get('payment-response')).toBe(first.headers.get('payment-response'));
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

  it('encodeX402Header output passes the upstream decoder', () => {
    const value = { a: 'ä', b: [1, 2] };
    expect(upstreamDecode(encodeX402Header(value))).toEqual(value);
  });
});

describe('withAssure — compliance-fields advertised in PAYMENT-REQUIRED', () => {
  const paymentRequired = {
    x402Version: 2,
    error: 'PAYMENT-SIGNATURE header is required',
    resource: { url: 'https://api.example.com/v1/data' },
    accepts: [{ scheme: 'exact', network: 'eip155:8453', amount: '10000', asset: '0xabc', payTo: '0xdef', maxTimeoutSeconds: 60 }],
    extensions: { bazaar: { info: { k: 1 }, schema: {} } },
  };
  const required402 = (pr: unknown = paymentRequired) => async () =>
    new Response('{}', { status: 402, headers: { 'content-type': 'application/json', 'payment-required': upstreamEncode(pr) } });

  it('adds the extension with a schema and no tier or jurisdiction claim by default, keeping everything else', async () => {
    const res = await withAssure(required402(), { assure, clock })(new Request('https://api.example.com/v1/data'));
    expect(res.status).toBe(402);
    const pr = upstreamDecode(res.headers.get('payment-required'));
    expect(pr.extensions['compliance-fields']).toEqual({ info: {}, schema: COMPLIANCE_FIELDS_ADVERTISEMENT_SCHEMA });
    expect(pr.accepts).toEqual(paymentRequired.accepts);
    expect(pr.extensions.bazaar).toEqual(paymentRequired.extensions.bazaar);
    expect(pr.x402Version).toBe(2);
    expect(await res.text()).toBe('{}');
  });

  it('states configured tiers and jurisdictions', async () => {
    const res = await withAssure(required402(), {
      assure,
      clock,
      advertise: { tiers: ['minimal'], jurisdictions: ['HK-51C'] },
    })(new Request('https://api.example.com/v1/data'));
    const pr = upstreamDecode(res.headers.get('payment-required'));
    expect(pr.extensions['compliance-fields'].info).toEqual({ tiers: ['minimal'], jurisdictions: ['HK-51C'] });
  });

  it('advertise:false leaves the 402 untouched, and an existing compliance-fields entry is kept', async () => {
    const off = await withAssure(required402(), { assure, clock, advertise: false })(new Request('https://api.example.com/x'));
    expect(off.headers.get('payment-required')).toBe(upstreamEncode(paymentRequired));
    const own = { ...paymentRequired, extensions: { 'compliance-fields': { info: { tiers: ['full'] }, schema: {} } } };
    const kept = await withAssure(required402(own), { assure, clock })(new Request('https://api.example.com/x'));
    expect(upstreamDecode(kept.headers.get('payment-required')).extensions['compliance-fields']).toEqual(
      own.extensions['compliance-fields'],
    );
  });

  it('does not touch a PAYMENT-REQUIRED header on a non-402 response', async () => {
    const header = upstreamEncode(paymentRequired);
    const ok = async () => new Response('{}', { status: 200, headers: { 'payment-required': header } });
    const res = await withAssure(ok, { assure, clock })(new Request('https://api.example.com/x'));
    expect(res.headers.get('payment-required')).toBe(header);
  });
});
