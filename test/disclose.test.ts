import { describe, expect, it } from 'vitest';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { digestOf } from '../src/canonical.js';
import { verifyActionRecord } from '../src/evidence/action.js';
import { recordDisclosure } from '../src/evidence/disclose.js';
import type { SignedActionRecord } from '../src/evidence/action.js';

const account = privateKeyToAccount(generatePrivateKey());
const CLOCK = () => 1_754_000_000;

function mockLedger(status = 201, body: unknown = { id: 'r1', digest: '0xabc', seq: 1 }) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fetchImpl = (async (url: unknown, init?: unknown) => {
    calls.push({ url: String(url), init: init as RequestInit });
    return new Response(JSON.stringify(body), { status });
  }) as typeof fetch;
  return { calls, fetchImpl };
}

describe('recordDisclosure', () => {
  it('digests the text locally — raw text never appears in the wire body', async () => {
    const { calls, fetchImpl } = mockLedger();
    const text = 'You are chatting with an AI assistant.';
    const result = await recordDisclosure({ text, agentId: 'test-agent', medium: 'chat', account, fetchImpl, clock: CLOCK });

    expect(calls).toHaveLength(1);
    const call = calls[0]!;
    expect(call.url).toBe('https://tersign.ai/v1/disclose');
    const wire = String(call.init.body);
    expect(wire).not.toContain(text);
    expect(wire).toContain(digestOf(text));
    expect(result.record.record.disclosure?.textDigest).toBe(digestOf(text));
  });

  it('produces a digest-consistent signed record this signer can be recovered from', async () => {
    const { calls, fetchImpl } = mockLedger();
    await recordDisclosure({ text: 'AI disclosure', agentId: 'a1', account, fetchImpl, clock: CLOCK });
    const sent = (JSON.parse(String(calls[0]!.init.body)) as { artifact: SignedActionRecord }).artifact;
    expect(sent.record.action.kind).toBe('disclosure');
    expect(sent.record.disclosure?.kind).toBe('ai-interaction');
    expect(sent.record.disclosure?.presentedAt).toBe(CLOCK());
    expect(sent.record.occurredAt).toBe(CLOCK());
    const verdict = await verifyActionRecord(sent, account.address);
    expect(verdict.valid).toBe(true);
  });

  it('a caller-supplied textDigest wins and no text is required', async () => {
    const { calls, fetchImpl } = mockLedger();
    const pre = digestOf('elsewhere');
    await recordDisclosure({ textDigest: pre, agentId: 'a1', account, fetchImpl, clock: CLOCK });
    const sent = (JSON.parse(String(calls[0]!.init.body)) as { artifact: SignedActionRecord }).artifact;
    expect(sent.record.disclosure?.textDigest).toBe(pre);
  });

  it('refuses a call with neither text nor textDigest', async () => {
    const { fetchImpl } = mockLedger();
    await expect(recordDisclosure({ agentId: 'a1', account, fetchImpl, clock: CLOCK })).rejects.toThrow(/text/);
  });

  it('surfaces ledger rejections with status and body', async () => {
    const { fetchImpl } = mockLedger(429, { error: 'rate limit' });
    await expect(
      recordDisclosure({ text: 'x', agentId: 'a1', account, fetchImpl, clock: CLOCK }),
    ).rejects.toThrow(/429.*rate limit/);
  });
});
