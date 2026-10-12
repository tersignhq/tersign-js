import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { Assure } from '../src/assure.js';
import { digestOf } from '../src/canonical.js';
import { recordDisclosure } from '../src/evidence/disclose.js';
import { signActionRecord, type ActionRecordV1 } from '../src/evidence/action.js';
import { EvidenceSink } from '../src/intercept/sink.js';
import { LedgerClient } from '../src/ledgerClient.js';
import { ledgerBase } from '../src/ledgerUrl.js';
import { envDeps } from '../src/mcp/server.js';
import {
  adjudicateDisputeTool,
  getDisputeTool,
  issueReceiptTool,
  openDisputeTool,
  recordDisclosureTool,
  recordRefundTool,
  submitEvidenceTool,
} from '../src/mcp/tools.js';

/** Every ledger URL the SDK takes is joined to its paths through ledgerBase, so a URL given with
 * one or two trailing slashes reaches the same route as one given without. A base that kept a
 * slash sent "https://tersign.ai//v1/receipts", which the ledger answers with 404 (measured
 * 2026-10-12). The spawned entry points (TERSIGN_LEDGER_URL in `tersign intercept`, its --ledger,
 * `tersign disclose --ledger` and `tersign verify --ledger`) are in entrypoint-placeholders.test.ts. */

const HOST = 'https://ledger.example';
const SLASHED = [`${HOST}/`, `${HOST}//`];
const DIGEST = `0x${'ab'.repeat(32)}` as const;
const account = privateKeyToAccount(generatePrivateKey());
const KEY = generatePrivateKey();
const CLOCK = () => 1_754_000_000;

/** A fetch that records each URL and answers `body` with 201. */
function recorder(body: unknown = { id: 'r1', digest: DIGEST, seq: 1, prevDigest: null, countersignature: '0x' }) {
  const urls: string[] = [];
  const fetchImpl = (async (url: unknown) => {
    urls.push(String(url));
    return new Response(JSON.stringify(body), { status: 201, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
  return { urls, fetchImpl };
}

afterEach(() => vi.unstubAllGlobals());

describe('ledgerBase', () => {
  it('drops every trailing slash and nothing else', () => {
    expect(ledgerBase(HOST)).toBe(HOST);
    expect(ledgerBase(`${HOST}/`)).toBe(HOST);
    expect(ledgerBase(`${HOST}//`)).toBe(HOST);
    expect(ledgerBase(`${HOST}///`)).toBe(HOST);
    expect(ledgerBase(`${HOST}/api//`)).toBe(`${HOST}/api`);
    // only the END is trimmed: a slash inside the path stays
    expect(ledgerBase(`${HOST}//api`)).toBe(`${HOST}//api`);
    expect(ledgerBase('')).toBe('');
  });
});

describe('each entry point joins through ledgerBase', () => {
  it.each(SLASHED)('LedgerClient url %j: receipts, refunds and envelopes', async (url) => {
    const { urls, fetchImpl } = recorder();
    const client = new LedgerClient({ url, apiKey: 'k', sellerId: 's', fetchImpl });
    await client.recordRefund(DIGEST, '1.00', 'r');
    await client.fetchEnvelope(DIGEST).catch(() => undefined);
    const assure = new Assure({ signer: account, issuer: { name: 'T', jurisdiction: 'HK' }, ledger: { url, apiKey: 'k', sellerId: 's', fetchImpl } });
    await issueReceiptTool({ assure, clock: CLOCK }, { network: 'eip155:8453', resourceUrl: 'https://api.example.com/x', payer: account.address, supplyDescription: 'x' });
    expect(urls).toEqual([`${HOST}/v1/refunds`, `${HOST}/v1/receipts/${DIGEST}/envelope`, `${HOST}/v1/receipts`]);
  });

  it.each(SLASHED)('ledgerHttp url %j: the four dispute tools', async (url) => {
    const { urls, fetchImpl } = recorder({ id: DIGEST });
    vi.stubGlobal('fetch', fetchImpl);
    const deps = { assure: new Assure({ signer: account, issuer: { name: 'T', jurisdiction: 'HK' } }), signer: account, ledgerHttp: { url }, clock: CLOCK };
    await openDisputeTool(deps, { receiptDigest: DIGEST, reason: 'not_delivered', claimAmount: '1' });
    await submitEvidenceTool(deps, { disputeDigest: DIGEST, role: 'claimant', artifacts: [{ kind: 'transcript', digest: DIGEST }] });
    await adjudicateDisputeTool(deps, DIGEST);
    await getDisputeTool(deps, DIGEST);
    expect(urls).toEqual([
      `${HOST}/v1/disputes`,
      `${HOST}/v1/disputes/${DIGEST}/evidence`,
      `${HOST}/v1/disputes/${DIGEST}/adjudicate`,
      `${HOST}/v1/disputes/${DIGEST}`,
    ]);
  });

  it.each(SLASHED)('recordDisclosure ledger %j, directly and through record_disclosure', async (url) => {
    const { urls, fetchImpl } = recorder();
    await recordDisclosure({ text: 'AI', agentId: 'a', account, ledger: url, fetchImpl, clock: CLOCK });
    vi.stubGlobal('fetch', fetchImpl);
    const deps = { assure: new Assure({ signer: account, issuer: { name: 'T', jurisdiction: 'HK' } }), signer: account, ledgerHttp: { url }, clock: CLOCK };
    await recordDisclosureTool(deps, { text: 'AI', agentId: 'a' });
    expect(urls).toEqual([`${HOST}/v1/disclose`, `${HOST}/v1/disclose`]);
  });

  it.each(SLASHED)('EvidenceSink (tersign intercept) ledgerUrl %j', async (url) => {
    const dir = mkdtempSync(join(tmpdir(), 'tersign-ledger-url-'));
    try {
      const { urls, fetchImpl } = recorder();
      const sink = new EvidenceSink({ ledgerUrl: url, apiKey: 'k', sellerId: 's', dir, fetchImpl, warn: () => {} });
      const record: ActionRecordV1 = {
        version: 1,
        agent: { id: 'a' },
        action: { kind: 'tool-call', name: 'echo', inputDigest: digestOf(null), outputDigest: digestOf(null) },
        occurredAt: 1_754_000_000,
      };
      sink.push(await signActionRecord(record, account));
      await sink.close();
      expect(urls).toEqual([`${HOST}/v1/evidence`]);
      expect(sink.ledgerCount).toBe(1);
      expect(readdirSync(dir)).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.each(SLASHED)('TERSIGN_LEDGER_URL %j in the MCP server: chained issue_receipt, record_refund, get_dispute, record_disclosure', async (url) => {
    const { urls, fetchImpl } = recorder();
    vi.stubGlobal('fetch', fetchImpl);
    const deps = envDeps({ TERSIGN_SELLER_KEY: KEY, TERSIGN_LEDGER_URL: url, TERSIGN_LEDGER_API_KEY: 'k', TERSIGN_LEDGER_SELLER_ID: 's' });
    await issueReceiptTool(deps, { network: 'eip155:8453', resourceUrl: 'https://api.example.com/x', payer: account.address, supplyDescription: 'x' });
    await recordRefundTool(deps, DIGEST, '1.00', 'r');
    await getDisputeTool(deps, DIGEST);
    await recordDisclosureTool(deps, { text: 'AI', agentId: 'a' });
    expect(urls).toEqual([`${HOST}/v1/receipts`, `${HOST}/v1/refunds`, `${HOST}/v1/disputes/${DIGEST}`, `${HOST}/v1/disclose`]);
  });
});
