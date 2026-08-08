import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough, Writable } from 'node:stream';
import { afterAll, describe, expect, it } from 'vitest';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { digestOf } from '../src/canonical.js';
import { ACTION_WIRE_VECTOR, signActionRecord, verifyActionRecord } from '../src/evidence/action.js';
import type { ActionRecordV1, SignedActionRecord } from '../src/evidence/action.js';
import { McpCapture } from '../src/intercept/capture.js';
import { parseInterceptFlags } from '../src/intercept/flags.js';
import { LineSplitter, tryParseFrame } from '../src/intercept/frames.js';
import { startIntercept } from '../src/intercept/proxy.js';
import { EvidenceSink } from '../src/intercept/sink.js';

const account = privateKeyToAccount(generatePrivateKey());
const CLOCK = () => 1_754_600_000;

const frame = (obj: unknown): Buffer => Buffer.from(JSON.stringify(obj));

function makeCapture(events?: readonly string[], onError?: (err: unknown) => void) {
  const records: SignedActionRecord[] = [];
  const capture = new McpCapture({
    agentId: 'test-agent',
    account,
    ...(events !== undefined ? { events } : {}),
    ...(onError !== undefined ? { onError } : {}),
    clock: CLOCK,
    onRecord: (r) => records.push(r),
  });
  return { capture, records };
}

const tmpDirs: string[] = [];
function tmp(): string {
  const dir = mkdtempSync(join(tmpdir(), 'tersign-intercept-'));
  tmpDirs.push(dir);
  return dir;
}
afterAll(() => {
  for (const dir of tmpDirs) rmSync(dir, { recursive: true, force: true });
});

async function signedFixture(occurredAt: number): Promise<SignedActionRecord> {
  const record: ActionRecordV1 = {
    version: 1,
    agent: { id: 'sink-fixture' },
    action: { kind: 'tool-call', name: 'noop', inputDigest: digestOf(null), outputDigest: digestOf(null) },
    occurredAt,
  };
  return signActionRecord(record, account);
}

describe('frames — newline-delimited stream splitting', () => {
  it('reassembles a frame split across chunks', () => {
    const s = new LineSplitter();
    expect(s.feed(Buffer.from('{"jsonrpc":"2.0","id":1,'))).toEqual([]);
    const lines = s.feed(Buffer.from('"method":"ping"}\n'));
    expect(lines.map(String)).toEqual(['{"jsonrpc":"2.0","id":1,"method":"ping"}']);
  });

  it('splits multiple frames arriving in one chunk, keeping the trailing partial', () => {
    const s = new LineSplitter();
    const lines = s.feed(Buffer.from('{"a":1}\n{"b":2}\n{"c":'));
    expect(lines.map(String)).toEqual(['{"a":1}', '{"b":2}']);
    expect(s.feed(Buffer.from('3}\n')).map(String)).toEqual(['{"c":3}']);
  });

  it('buffers an arbitrarily large frame (1MB) fed in small chunks', () => {
    const s = new LineSplitter();
    const big = JSON.stringify({
      jsonrpc: '2.0',
      id: 9,
      method: 'tools/call',
      params: { name: 'blob', arguments: { data: 'x'.repeat(1 << 20) } },
    });
    const bytes = Buffer.from(`${big}\n`);
    const collected: Buffer[] = [];
    for (let i = 0; i < bytes.length; i += 65536) {
      collected.push(...s.feed(bytes.subarray(i, Math.min(i + 65536, bytes.length))));
    }
    expect(collected).toHaveLength(1);
    expect(String(collected[0])).toBe(big);
    expect((tryParseFrame(collected[0]!) as { id: number }).id).toBe(9);
  });

  it('never throws on non-JSON lines — they parse to undefined and are not captured', () => {
    expect(tryParseFrame(Buffer.from('[server] listening on stdio'))).toBeUndefined();
    expect(tryParseFrame(Buffer.from(''))).toBeUndefined();
    expect(tryParseFrame(Buffer.from('   '))).toBeUndefined();
  });

  it('tolerates CRLF line endings', () => {
    const s = new LineSplitter();
    const lines = s.feed(Buffer.from('{"a":1}\r\n'));
    expect(lines.map(String)).toEqual(['{"a":1}\r']);
    expect(tryParseFrame(lines[0]!)).toEqual({ a: 1 });
  });
});

describe('capture — direction-aware pairing', () => {
  it('pairs a tools/call request with its response into one signed record', async () => {
    const { capture, records } = makeCapture();
    const args = { city: 'HK', units: 'C' };
    const result = { content: [{ type: 'text', text: '31C' }] };
    capture.onFrame('client', frame({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'weather', arguments: args } }));
    capture.onFrame('server', frame({ jsonrpc: '2.0', id: 1, result }));
    await capture.settle();
    expect(records).toHaveLength(1);
    const rec = records[0]!.record;
    expect(rec.action.kind).toBe('tool-call');
    expect(rec.action.name).toBe('weather');
    expect(rec.action.inputDigest).toBe(digestOf(args));
    expect(rec.action.outputDigest).toBe(digestOf(result));
    expect(rec.agent.id).toBe('test-agent');
    expect(rec.occurredAt).toBe(CLOCK());
  });

  it('keeps ids independent per direction — same id in flight both ways at once', async () => {
    const { capture, records } = makeCapture();
    capture.onFrame('client', frame({ jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'search', arguments: { q: 'a' } } }));
    // server→client request reusing id 7 while the tool call is still pending
    capture.onFrame('server', frame({ jsonrpc: '2.0', id: 7, method: 'sampling/createMessage', params: {} }));
    // the client answers the SERVER's request — must not satisfy the pending tool call
    capture.onFrame('client', frame({ jsonrpc: '2.0', id: 7, result: { role: 'assistant' } }));
    await capture.settle();
    expect(records).toHaveLength(0);
    const toolResult = { content: [] };
    capture.onFrame('server', frame({ jsonrpc: '2.0', id: 7, result: toolResult }));
    await capture.settle();
    expect(records).toHaveLength(1);
    expect(records[0]!.record.action.outputDigest).toBe(digestOf(toolResult));
  });

  it('handles out-of-order responses', async () => {
    const { capture, records } = makeCapture();
    capture.onFrame('client', frame({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'first', arguments: { a: 1 } } }));
    capture.onFrame('client', frame({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'second', arguments: { b: 2 } } }));
    capture.onFrame('server', frame({ jsonrpc: '2.0', id: 2, result: { ok: 2 } }));
    capture.onFrame('server', frame({ jsonrpc: '2.0', id: 1, result: { ok: 1 } }));
    await capture.settle();
    expect(records).toHaveLength(2);
    expect(records[0]!.record.action.name).toBe('second');
    expect(records[1]!.record.action.name).toBe('first');
  });

  it('a JSON-RPC error response still produces a record — digest over the error object', async () => {
    const { capture, records } = makeCapture();
    const error = { code: -32602, message: 'invalid params' };
    capture.onFrame('client', frame({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'boom', arguments: {} } }));
    capture.onFrame('server', frame({ jsonrpc: '2.0', id: 4, error }));
    await capture.settle();
    expect(records).toHaveLength(1);
    expect(records[0]!.record.action.outputDigest).toBe(digestOf(error));
  });

  it('ignores non-captured methods, notifications, and non-JSON frames', async () => {
    const { capture, records } = makeCapture();
    capture.onFrame('client', frame({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2026-07-28' } }));
    capture.onFrame('server', frame({ jsonrpc: '2.0', id: 1, result: { capabilities: {} } }));
    capture.onFrame('client', frame({ jsonrpc: '2.0', method: 'notifications/initialized' }));
    capture.onFrame('client', frame({ jsonrpc: '2.0', id: 2, method: 'tools/list' }));
    capture.onFrame('server', frame({ jsonrpc: '2.0', id: 2, result: { tools: [] } }));
    capture.onFrame('server', Buffer.from('not json at all'));
    await capture.settle();
    expect(records).toHaveLength(0);
  });

  it('emits digests only — raw arguments and results never appear in the record', async () => {
    const { capture, records } = makeCapture();
    const secret = 'super-secret-argument-6f2a';
    const resultSecret = 'result-payload-9c1d';
    capture.onFrame('client', frame({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'lookup', arguments: { key: secret } } }));
    capture.onFrame('server', frame({ jsonrpc: '2.0', id: 3, result: { value: resultSecret } }));
    await capture.settle();
    const wire = JSON.stringify(records[0]!);
    expect(wire).not.toContain(secret);
    expect(wire).not.toContain(resultSecret);
    expect(records[0]!.record.action.inputDigest).toBe(digestOf({ key: secret }));
    expect(records[0]!.record.action.outputDigest).toBe(digestOf({ value: resultSecret }));
  });

  it('emitted records pass verifyActionRecord for the capture signer', async () => {
    const { capture, records } = makeCapture();
    capture.onFrame('client', frame({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 't', arguments: { x: 1 } } }));
    capture.onFrame('server', frame({ jsonrpc: '2.0', id: 1, result: {} }));
    await capture.settle();
    const verdict = await verifyActionRecord(records[0]!, account.address);
    expect(verdict.valid).toBe(true);
    expect(verdict.signer?.toLowerCase()).toBe(account.address.toLowerCase());
  });

  it('--events extends the set, and * captures every client→server request method', async () => {
    const extended = makeCapture(['tools/call', 'prompts/get']);
    extended.capture.onFrame('client', frame({ jsonrpc: '2.0', id: 1, method: 'prompts/get', params: { name: 'greet', arguments: {} } }));
    extended.capture.onFrame('server', frame({ jsonrpc: '2.0', id: 1, result: { messages: [] } }));
    extended.capture.onFrame('client', frame({ jsonrpc: '2.0', id: 2, method: 'resources/read', params: { uri: 'file:///x' } }));
    extended.capture.onFrame('server', frame({ jsonrpc: '2.0', id: 2, result: { contents: [] } }));
    await extended.capture.settle();
    expect(extended.records).toHaveLength(1);
    expect(extended.records[0]!.record.action.name).toBe('greet');

    const wild = makeCapture(['*']);
    wild.capture.onFrame('client', frame({ jsonrpc: '2.0', id: 5, method: 'resources/read', params: { uri: 'file:///x' } }));
    wild.capture.onFrame('server', frame({ jsonrpc: '2.0', id: 5, result: { contents: [] } }));
    await wild.capture.settle();
    expect(wild.records).toHaveLength(1);
    // resources/read has no params.name and no arguments — nameless record, digest of null
    expect(wild.records[0]!.record.action.name).toBeUndefined();
    expect(wild.records[0]!.record.action.inputDigest).toBe(digestOf(null));
  });
});

describe('capture — pending-map hygiene', () => {
  it('notifications/cancelled drops the pending entry — a late response emits nothing', async () => {
    const { capture, records } = makeCapture();
    capture.onFrame('client', frame({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'slow', arguments: { q: 1 } } }));
    capture.onFrame('client', frame({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 1, reason: 'user cancelled' } }));
    capture.onFrame('server', frame({ jsonrpc: '2.0', id: 1, result: { late: true } }));
    await capture.settle();
    expect(records).toHaveLength(0);
  });

  it('caps the pending map — overflow evicts the oldest entry, counts, and warns exactly once', async () => {
    const errors: unknown[] = [];
    const { capture, records } = makeCapture(undefined, (e) => errors.push(e));
    // 4097 unanswered requests: the 4097th must evict the oldest (id 0), not grow forever
    for (let id = 0; id <= 4096; id += 1) {
      capture.onFrame('client', frame({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 't', arguments: { id } } }));
    }
    expect(capture.evictedCount).toBe(1);
    expect(errors).toHaveLength(1);
    capture.onFrame('server', frame({ jsonrpc: '2.0', id: 0, result: { ok: true } })); // evicted — no record
    capture.onFrame('server', frame({ jsonrpc: '2.0', id: 1, result: { ok: true } })); // survived
    await capture.settle();
    expect(records).toHaveLength(1);
    expect(records[0]!.record.action.inputDigest).toBe(digestOf({ id: 1 }));
    // subsequent evictions count silently — no second warning
    capture.onFrame('client', frame({ jsonrpc: '2.0', id: 5000, method: 'tools/call', params: { name: 't', arguments: {} } }));
    capture.onFrame('client', frame({ jsonrpc: '2.0', id: 5001, method: 'tools/call', params: { name: 't', arguments: {} } }));
    expect(capture.evictedCount).toBe(2);
    expect(errors).toHaveLength(1);
  });

  it('same-direction id reuse drops the stale entry with one warning — never a fabricated pairing', async () => {
    const errors: unknown[] = [];
    const { capture, records } = makeCapture(undefined, (e) => errors.push(e));
    capture.onFrame('client', frame({ jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name: 'first', arguments: { a: 1 } } }));
    capture.onFrame('client', frame({ jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name: 'second', arguments: { b: 2 } } }));
    expect(errors).toHaveLength(1);
    const result = { ok: true };
    capture.onFrame('server', frame({ jsonrpc: '2.0', id: 9, result }));
    capture.onFrame('server', frame({ jsonrpc: '2.0', id: 9, result: { stray: true } })); // stale response — nothing pending
    await capture.settle();
    // exactly one record, bound to the SECOND request's input and its own response
    expect(records).toHaveLength(1);
    expect(records[0]!.record.action.name).toBe('second');
    expect(records[0]!.record.action.inputDigest).toBe(digestOf({ b: 2 }));
    expect(records[0]!.record.action.outputDigest).toBe(digestOf(result));
    expect(capture.collisionCount).toBe(1);
  });
});

describe('sink — non-blocking evidence delivery', () => {
  it('local mode appends one JSON line per record (0600) into the dated file', async () => {
    const dir = tmp();
    const sink = new EvidenceSink({ ledgerUrl: 'https://tersign.ai', dir, now: () => new Date('2026-08-08T12:00:00Z') });
    const a = await signedFixture(1_754_600_001);
    const b = await signedFixture(1_754_600_002);
    sink.push(a);
    sink.push(b);
    await sink.close();
    expect(sink.localCount).toBe(2);
    expect(sink.ledgerCount).toBe(0);
    expect(sink.failedCount).toBe(0);
    const path = join(dir, 'intercepts-2026-08-08.jsonl');
    expect(sink.localPath).toBe(path);
    const lines = readFileSync(path, 'utf8').trim().split('\n');
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]!)).toEqual(JSON.parse(JSON.stringify(a)));
    expect(JSON.parse(lines[1]!)).toEqual(JSON.parse(JSON.stringify(b)));
    expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  it('ledger mode POSTs {sellerId, artifact} with the bearer key and skips the local file', async () => {
    const dir = tmp();
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fetchImpl = (async (url: unknown, init?: unknown) => {
      calls.push({ url: String(url), init: init as RequestInit });
      return new Response(JSON.stringify({ id: 'r1' }), { status: 201 });
    }) as typeof fetch;
    const sink = new EvidenceSink({ ledgerUrl: 'https://ledger.example/', apiKey: 'sk_test', sellerId: 'seller-1', dir, fetchImpl });
    const a = await signedFixture(1_754_600_003);
    sink.push(a);
    await sink.close();
    expect(sink.ledgerCount).toBe(1);
    expect(sink.localCount).toBe(0);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe('https://ledger.example/v1/evidence');
    const headers = calls[0]!.init.headers as Record<string, string>;
    expect(headers.authorization).toBe('Bearer sk_test');
    const body = JSON.parse(String(calls[0]!.init.body)) as { sellerId: string; artifact: unknown };
    expect(body.sellerId).toBe('seller-1');
    expect(body.artifact).toEqual(JSON.parse(JSON.stringify(a)));
    expect(readdirSync(dir)).toEqual([]);
    expect(sink.localPath).toBeNull();
  });

  it('an HTTP failure falls back to the local file — no record dropped', async () => {
    const dir = tmp();
    const fetchImpl = (async () => new Response('{"error":"nope"}', { status: 500 })) as typeof fetch;
    const sink = new EvidenceSink({
      ledgerUrl: 'https://ledger.example',
      apiKey: 'k',
      sellerId: 's',
      dir,
      fetchImpl,
      now: () => new Date('2026-08-08T00:00:00Z'),
      warn: () => {},
    });
    sink.push(await signedFixture(1_754_600_004));
    await sink.close();
    expect(sink.ledgerCount).toBe(0);
    expect(sink.localCount).toBe(1);
    expect(readFileSync(join(dir, 'intercepts-2026-08-08.jsonl'), 'utf8').trim().split('\n')).toHaveLength(1);
  });

  it('a network failure (fetch throws) also falls back to the local file', async () => {
    const dir = tmp();
    const fetchImpl = (async () => {
      throw new Error('ECONNREFUSED');
    }) as typeof fetch;
    const sink = new EvidenceSink({
      ledgerUrl: 'https://ledger.example',
      apiKey: 'k',
      sellerId: 's',
      dir,
      fetchImpl,
      now: () => new Date('2026-08-08T00:00:00Z'),
    });
    sink.push(await signedFixture(1_754_600_005));
    await sink.close();
    expect(sink.ledgerCount).toBe(0);
    expect(sink.localCount).toBe(1);
  });

  it('a hanging ledger POST is timed out — close() completes and the record lands locally', async () => {
    const dir = tmp();
    // never settles AND ignores the abort signal — the sink must not trust fetchImpl to honor it
    const fetchImpl = (async () => new Promise(() => {})) as unknown as typeof fetch;
    const sink = new EvidenceSink({
      ledgerUrl: 'https://ledger.example',
      apiKey: 'k',
      sellerId: 's',
      dir,
      fetchImpl,
      ledgerTimeoutMs: 200,
      now: () => new Date('2026-08-08T00:00:00Z'),
      warn: () => {},
    });
    sink.push(await signedFixture(1_754_600_006));
    const started = Date.now();
    await sink.close();
    expect(Date.now() - started).toBeLessThan(4000);
    expect(sink.ledgerCount).toBe(0);
    expect(sink.localCount).toBe(1);
    expect(readFileSync(join(dir, 'intercepts-2026-08-08.jsonl'), 'utf8').trim().split('\n')).toHaveLength(1);
  }, 5000);

  it('a non-ok ledger response is consumed and warned once — later rejects count silently', async () => {
    const dir = tmp();
    const warns: string[] = [];
    const responses: Response[] = [];
    const fetchImpl = (async () => {
      const res = new Response('{"error":"seller key not registered for seller-1"}', { status: 403 });
      responses.push(res);
      return res;
    }) as typeof fetch;
    const sink = new EvidenceSink({
      ledgerUrl: 'https://ledger.example',
      apiKey: 'k',
      sellerId: 's',
      dir,
      fetchImpl,
      now: () => new Date('2026-08-08T00:00:00Z'),
      warn: (line) => warns.push(line),
    });
    sink.push(await signedFixture(1_754_600_007));
    sink.push(await signedFixture(1_754_600_008));
    await sink.close();
    expect(sink.ledgerCount).toBe(0);
    expect(sink.ledgerRejectCount).toBe(2);
    expect(sink.localCount).toBe(2);
    expect(warns).toHaveLength(1);
    expect(warns[0]).toContain('403');
    expect(warns[0]).toContain('seller key not registered');
    expect(warns[0]).toContain('TERSIGN_SELLER_KEY');
    // bodies are consumed — an unread body pins the connection in undici's pool
    expect(responses.every((r) => r.bodyUsed)).toBe(true);
  });
});

describe('intercept flags — the tokens before --', () => {
  it('accepts both --flag value and --flag=value shapes', () => {
    const p = parseInterceptFlags(['--events=tools/call,prompts/get', '--agent-id', 'agent-1', '--ledger=https://l.example']);
    expect(p).toEqual({
      ok: true,
      flags: { events: 'tools/call,prompts/get', agentId: 'agent-1', ledger: 'https://l.example' },
    });
  });

  it('rejects unknown flags instead of silently ignoring them', () => {
    const p = parseInterceptFlags(['--evnets', 'tools/call']);
    expect(p.ok).toBe(false);
    if (!p.ok) expect(p.error).toContain("--evnets");
    const q = parseInterceptFlags(['stray-positional']);
    expect(q.ok).toBe(false);
  });

  it('a flag missing its value errors instead of consuming the next flag', () => {
    const p = parseInterceptFlags(['--agent-id', '--ledger', 'https://l.example']);
    expect(p.ok).toBe(false);
    if (!p.ok) expect(p.error).toContain("--agent-id");
    const q = parseInterceptFlags(['--ledger']);
    expect(q.ok).toBe(false);
    if (!q.ok) expect(q.error).toContain('requires a value');
  });
});

describe('wire contract', () => {
  it('this build adds no new wire shape — ACTION_WIRE_VECTOR unchanged', () => {
    expect(ACTION_WIRE_VECTOR).toBe('0xfbd304c31fdc6da09e2e8433875f8afbb4319cd844ddee54c0e555215ed53c10');
  });
});

describe('proxy — exit-path stdout drain', () => {
  /** Reader sipping 16KB per 20ms — the slow-consumer shape that reproduced the truncation.
   * The high water mark is 1MiB so the whole burst buffers in Node userspace instead of
   * backpressuring the child: exactly the bytes a premature exit used to discard. */
  class SlowWritable extends Writable {
    completed = 0;
    readonly chunks: Buffer[] = [];
    constructor() {
      super({ highWaterMark: 1 << 20 });
    }
    override _write(chunk: Buffer, _enc: BufferEncoding, cb: (error?: Error | null) => void): void {
      let sipped = 0;
      const sip = (): void => {
        sipped += 16384;
        if (sipped >= chunk.length) {
          this.chunks.push(chunk);
          this.completed += chunk.length;
          cb();
        } else {
          setTimeout(sip, 20);
        }
      };
      setTimeout(sip, 20);
    }
  }

  it('done does not resolve until the outbound writable is fully drained — zero loss for a slow reader', async () => {
    const TOTAL = 1 << 20; // 1MiB burst, ending in a newline
    const { capture } = makeCapture();
    const sink = new EvidenceSink({ ledgerUrl: 'https://tersign.ai', dir: tmp() });
    const stdin = new PassThrough();
    const stdout = new SlowWritable();
    const { done } = startIntercept({
      command: process.execPath,
      args: ['-e', `const b = Buffer.alloc(${TOTAL}, 120); b[b.length - 1] = 10; process.stdout.write(b);`],
      capture,
      sink,
      stdin,
      stdout,
      stderr: 'ignore',
    });
    const code = await done;
    expect(code).toBe(0);
    // at resolution nothing may remain buffered — an exit here must lose zero bytes
    expect(stdout.writableLength).toBe(0);
    expect(stdout.completed).toBe(TOTAL);
    const got = Buffer.concat(stdout.chunks);
    const expected = Buffer.alloc(TOTAL, 120);
    expected[TOTAL - 1] = 10;
    expect(got.equals(expected)).toBe(true);
  }, 20000);
});

describe('end-to-end smoke — real child process through the proxy', () => {
  // Echo responder: replies to any JSON-RPC request with result.echo = the EXACT raw line it
  // received, proving the child got the client's bytes unmodified.
  const RESPONDER = `
let buf = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (d) => {
  buf += d;
  let i;
  while ((i = buf.indexOf('\\n')) !== -1) {
    const line = buf.slice(0, i);
    buf = buf.slice(i + 1);
    let msg;
    try { msg = JSON.parse(line); } catch { continue; }
    if (msg.id === undefined || msg.method === undefined) continue;
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { echo: line } }) + '\\n');
  }
});
`;

  async function waitFor(cond: () => boolean, timeoutMs = 5000): Promise<void> {
    const start = Date.now();
    while (!cond()) {
      if (Date.now() - start > timeoutMs) throw new Error('timed out waiting for condition');
      await new Promise((r) => setTimeout(r, 10));
    }
  }

  it('proxies bytes faithfully both ways and lands one record in the local sink', async () => {
    const dir = tmp();
    const sink = new EvidenceSink({ ledgerUrl: 'https://tersign.ai', dir, now: () => new Date('2026-08-08T12:00:00Z') });
    const records: SignedActionRecord[] = [];
    const capture = new McpCapture({
      agentId: 'e2e-agent',
      account,
      onRecord: (r) => {
        records.push(r);
        sink.push(r);
      },
    });
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const out: Buffer[] = [];
    stdout.on('data', (c: Buffer) => out.push(c));

    const { done } = startIntercept({
      command: process.execPath,
      args: ['-e', RESPONDER],
      capture,
      sink,
      stdin,
      stdout,
      stderr: 'ignore',
    });

    const args = { probe: 'e2e-payload' };
    const request = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'echo', arguments: args } });
    stdin.write(`${request}\n`);
    await waitFor(() => Buffer.concat(out).includes(0x0a));
    stdin.end(); // child stdin closes → the responder exits cleanly
    const code = await done;
    expect(code).toBe(0);

    // server→client passthrough is byte-exact: we can reconstruct the child's output verbatim
    const expected = `${JSON.stringify({ jsonrpc: '2.0', id: 1, result: { echo: request } })}\n`;
    expect(Buffer.concat(out).toString('utf8')).toBe(expected);
    // client→server passthrough is byte-exact: the child echoed the raw request line
    const reply = JSON.parse(Buffer.concat(out).toString('utf8')) as { result: { echo: string } };
    expect(reply.result.echo).toBe(request);

    expect(records).toHaveLength(1);
    expect(records[0]!.record.action.name).toBe('echo');
    expect(records[0]!.record.action.inputDigest).toBe(digestOf(args));
    const lines = readFileSync(join(dir, 'intercepts-2026-08-08.jsonl'), 'utf8').trim().split('\n');
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0]!)).toEqual(JSON.parse(JSON.stringify(records[0]!)));
  }, 15000);
});
