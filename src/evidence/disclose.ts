import type { Account } from 'viem/accounts';
import { digestOf } from '../canonical.js';
import { signActionRecord, type ActionRecordV1, type DisclosureKind, type SignedActionRecord } from './action.js';

/** One-call counter-signed disclosure — the wedge flow.
 *
 * Data-minimization by construction: the disclosure TEXT never leaves this machine. Only
 * `digestOf(text)` travels (or a caller-supplied digest); the ledger counter-signs the
 * digest-bearing record into the signer's per-seller hash chain and the raw content stays
 * under the deployer's own retention. The route is public and signer-keyed: first call
 * self-provisions a free wedge account bound set-once to the signing key. */

export interface RecordDisclosureOptions {
  /** the disclosure text as shown — digested locally, never transmitted */
  text?: string;
  /** pre-computed digest; wins over `text` when both are given */
  textDigest?: `0x${string}`;
  /** channel the disclosure was presented on: 'chat' | 'api' | 'voice' | 'ui' … */
  medium?: string;
  kind?: DisclosureKind;
  /** stable identifier for the agent (deployer-scoped) */
  agentId: string;
  resourceUrl?: string;
  /** ledger base URL */
  ledger?: string;
  /** signing account; callers on Node can resolve one via the keystore helper */
  account: Account;
  fetchImpl?: typeof fetch;
  clock?: () => number;
}

export interface RecordDisclosureResult {
  id: string;
  digest: `0x${string}`;
  seq: number;
  prevDigest: `0x${string}` | null;
  countersignature: string;
  ledgerSigner: string;
  signer: string;
  verifyUrl: string;
  tier: string;
  note: string;
  /** the exact signed record submitted — keep it; it is your half of the evidence */
  record: SignedActionRecord;
}

export async function recordDisclosure(opts: RecordDisclosureOptions): Promise<RecordDisclosureResult> {
  if (opts.text === undefined && opts.textDigest === undefined) {
    throw new Error('recordDisclosure needs `text` (digested locally) or a pre-computed `textDigest`');
  }
  const now = (opts.clock ?? (() => Math.floor(Date.now() / 1000)))();
  const record: ActionRecordV1 = {
    version: 1,
    agent: { id: opts.agentId },
    action: { kind: 'disclosure' },
    disclosure: {
      kind: opts.kind ?? 'ai-interaction',
      presentedAt: now,
      ...(opts.medium !== undefined ? { medium: opts.medium } : {}),
      textDigest: opts.textDigest ?? digestOf(opts.text as string),
    },
    ...(opts.resourceUrl !== undefined ? { resourceUrl: opts.resourceUrl } : {}),
    occurredAt: now,
  };
  const signed = await signActionRecord(record, opts.account);

  const base = (opts.ledger ?? 'https://tersign.ai').replace(/\/$/, '');
  const f = opts.fetchImpl ?? fetch;
  const res = await f(`${base}/v1/disclose`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ artifact: signed }),
  });
  const body: unknown = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`disclose failed: ${res.status} ${JSON.stringify(body)}`);
  return { ...(body as Omit<RecordDisclosureResult, 'record'>), record: signed };
}
