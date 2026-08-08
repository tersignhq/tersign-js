#!/usr/bin/env node
/** tersign intercept — byte-faithful MCP stdio proxy with signed, digest-only evidence.
 *
 *   tersign intercept [--events tools/call,prompts/get] [--agent-id id] [--ledger url] \
 *                     -- npx some-mcp-server --its-flags
 *
 * Sits between an MCP client and a stdio MCP server, passes every byte through untouched,
 * and emits one signed ActionRecordV1 per captured tool call — digests of arguments and
 * results only, never content (data-minimization by construction). Records go to the hosted
 * ledger when TERSIGN_LEDGER_API_KEY + TERSIGN_LEDGER_SELLER_ID are set, else to
 * ~/.tersign/intercepts-YYYY-MM-DD.jsonl. The hosted /v1/evidence gate only accepts the
 * seller's REGISTERED signing key: set TERSIGN_SELLER_KEY to that key, or every POST is
 * rejected (warned once) and records fall back to the local file.
 *
 * Exit code: the child's, except 1 when evidence was lost (failed both sinks) while the
 * child itself exited 0 — a child failure code is never masked.
 *
 * SEP-2624 ("Interceptors for the Model Context Protocol" — Draft, Bloomberg/Saxo-led)
 * defines audit-mode validators that observe traffic without mutating it; this prototype
 * implements that capture semantics as a transport-level proxy today and is structured to
 * migrate to the interceptor primitive when the SEP stabilizes. It makes no conformance
 * claim against the SEP — the SEP is a draft proposal, not a released spec. */
import { privateKeyToAccount } from 'viem/accounts';
import { DEFAULT_EVENTS, McpCapture } from './intercept/capture.js';
import { parseInterceptFlags } from './intercept/flags.js';
import { startIntercept } from './intercept/proxy.js';
import { EvidenceSink } from './intercept/sink.js';
import { resolveSignerKey } from './keystore.js';

const USAGE =
  'usage: tersign intercept [--events tools/call,prompts/get] [--agent-id id] [--ledger url] -- <mcp server command> [args…]\n' +
  'hosted ledger mode (TERSIGN_LEDGER_API_KEY + TERSIGN_LEDGER_SELLER_ID) requires the signer key\n' +
  'registered for that sellerId — set TERSIGN_SELLER_KEY; rejected records fall back to ~/.tersign.\n' +
  "exits with the child's code; 1 if evidence was lost while the child exited 0";

const sep = process.argv.indexOf('--');
const command = sep === -1 ? [] : process.argv.slice(sep + 1);
if (sep === -1 || command.length === 0) {
  console.error(USAGE);
  process.exit(2);
}
// Flags live strictly BEFORE '--'; everything after belongs to the child verbatim.
const parsed = parseInterceptFlags(process.argv.slice(2, sep));
if (!parsed.ok) {
  console.error(`tersign intercept: ${parsed.error}\n${USAGE}`);
  process.exit(2);
}
const flags = parsed.flags;

// --events ADDS to the default set; '*' captures every client→server request method.
const events = [...DEFAULT_EVENTS];
for (const e of (flags.events ?? '').split(',')) {
  const method = e.trim();
  if (method !== '' && !events.includes(method)) events.push(method);
}

const envAgentId = process.env.TERSIGN_AGENT_ID;
const agentId = flags.agentId ?? (envAgentId !== undefined && envAgentId !== '' ? envAgentId : 'mcp-intercept');
const ledgerUrl = flags.ledger ?? process.env.TERSIGN_LEDGER_URL ?? 'https://tersign.ai';
const apiKey = process.env.TERSIGN_LEDGER_API_KEY;
const sellerId = process.env.TERSIGN_LEDGER_SELLER_ID;

try {
  const { key, source } = resolveSignerKey({ create: true });
  const account = privateKeyToAccount(key);
  console.error(`signing key: ${account.address} (${source})`);

  const sink = new EvidenceSink({
    ledgerUrl,
    ...(apiKey !== undefined && apiKey !== '' ? { apiKey } : {}),
    ...(sellerId !== undefined && sellerId !== '' ? { sellerId } : {}),
  });
  // Capture warnings (dropped stale pairings, cap evictions, signing failures) are
  // diagnostics, not traffic — rate-limited so a pathological stream cannot flood stderr.
  let captureWarnings = 0;
  const onError = (err: unknown): void => {
    captureWarnings += 1;
    if (captureWarnings <= 5) console.error(`tersign intercept: ${err instanceof Error ? err.message : String(err)}`);
    if (captureWarnings === 6) console.error('tersign intercept: further capture warnings suppressed');
  };
  const capture = new McpCapture({ agentId, account, events, onRecord: (r) => sink.push(r), onError });

  const { child, done } = startIntercept({
    command: command[0]!,
    args: command.slice(1),
    capture,
    sink,
    stdin: process.stdin,
    stdout: process.stdout,
    stderr: 'inherit',
  });
  let childClosed = false;
  child.once('close', () => {
    childClosed = true;
  });
  let signalled = false;
  for (const sig of ['SIGINT', 'SIGTERM'] as const) {
    const code = sig === 'SIGINT' ? 130 : 143; // 128 + signal number
    process.on(sig, () => {
      if (signalled) process.exit(code); // a second signal always force-exits immediately
      signalled = true;
      if (childClosed) {
        // the child is already gone, so there is nothing to forward to — flush best-effort
        // (every sink write is time-capped), then force-exit
        void sink.close().finally(() => process.exit(code));
      } else {
        // forward to the child; its close event drives the flush + summary below
        child.kill(sig);
      }
    });
  }
  const code = await done;
  console.error(
    `tersign intercept: ${capture.recordCount} tool-call records (${sink.ledgerCount} ledger, ${sink.localCount} local` +
      (sink.failedCount > 0 ? `, ${sink.failedCount} FAILED — evidence lost` : '') +
      ')' +
      (sink.localPath !== null ? ` — ${sink.localPath}` : ''),
  );
  // Natural exit (exitCode + stdin teardown, never process.exit()) so Node flushes any stdout
  // still queued for a slow reader; evidence loss becomes exit 1 only when the child exited 0.
  process.stdin.pause();
  process.exitCode = sink.failedCount > 0 && code === 0 ? 1 : code;
} catch (e) {
  console.error(e instanceof Error ? e.message : String(e));
  process.stdin.pause();
  process.exitCode = 1;
}
