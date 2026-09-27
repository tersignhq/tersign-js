import type { Account } from 'viem/accounts';
import type { Assure, SettlementContext } from '../assure.js';
import { verifyReceipt } from '../receipt/eip712.js';
import { recordDigest, verifyComplianceRecord } from '../compliance/record.js';
import { digestOf } from '../canonical.js';
import { findLoneSurrogate, signerStatus, type SignerStatus } from '../receipt/binding.js';
import { verdictSentence } from '../verify-report.js';
import { signDispute, signEvidence } from '../dispute/sign.js';
import type { DisputeReason, EvidenceArtifactRef } from '../dispute/types.js';
import type { LedgerClient } from '../ledgerClient.js';
import type { ComplianceRecordV1, SignedComplianceRecord, SignedReceipt } from '../types.js';

/** Plain-function tool implementations, kept separate from MCP wiring so they are unit-testable
 * and reusable from non-MCP surfaces. */

export interface McpDeps {
  assure: Assure;
  ledger?: LedgerClient;
  /** signing key for dispute-side actions. Standing is key-based: opening a dispute
   * requires this key to be the disputed receipt's payer. */
  signer?: Account;
  /** raw ledger HTTP access for the PUBLIC dispute endpoints (no API key needed;
   * apiKey only authenticates respondent evidence). */
  ledgerHttp?: { url: string; apiKey?: string };
  clock?: () => number;
}

async function ledgerFetch(base: string, path: string, init?: { body?: unknown; apiKey?: string }) {
  const url = `${base.replace(/\/$/, '')}${path}`;
  const res = await fetch(url, {
    method: init?.body === undefined ? 'GET' : 'POST',
    headers: {
      ...(init?.body !== undefined ? { 'content-type': 'application/json' } : {}),
      ...(init?.apiKey ? { authorization: `Bearer ${init.apiKey}` } : {}),
    },
    ...(init?.body !== undefined ? { body: JSON.stringify(init.body) } : {}),
  });
  const json: unknown = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`ledger ${res.status}: ${JSON.stringify(json)}`);
  return json;
}

export interface IssueReceiptArgs {
  network: string;
  resourceUrl: string;
  payer: string;
  supplyDescription: string;
  settledAt?: number | undefined;
  txHash?: string | undefined;
  taxScheme?: 'none' | 'vat' | 'gst' | 'jct' | 'sales' | undefined;
  currency?: string | undefined;
  principal?: string | undefined;
}

export async function issueReceiptTool(deps: McpDeps, args: IssueReceiptArgs) {
  const now = deps.clock ?? (() => Math.floor(Date.now() / 1000));
  const ctx: SettlementContext = {
    network: args.network,
    resourceUrl: args.resourceUrl,
    payer: args.payer,
    settledAt: args.settledAt ?? now(),
    supplyDescription: args.supplyDescription,
    tax: { scheme: args.taxScheme ?? 'none', currency: args.currency ?? 'USD' },
    ...(args.txHash !== undefined ? { txHash: args.txHash } : {}),
    ...(args.principal !== undefined ? { buyer: { principal: args.principal } } : {}),
  };
  return deps.assure.issueFor(ctx);
}

/** What the MCP verify tools return: the library result led by a one-sentence `verdict` and an
 * explicit `signerStatus`, so an agent that reads only the first field is told what was NOT
 * checked. Same shape as `python3 -m tersign verify`'s JSON (its verdict says PASS/FAIL where
 * this says VALID/INVALID, the npm CLI's words). */
export interface VerifyToolResult {
  verdict: string;
  valid: boolean;
  signer?: `0x${string}`;
  signerStatus?: SignerStatus;
  signerBound: boolean;
  expectedSigner?: string;
  testKey?: string;
  digest?: `0x${string}`;
  unsignedFields?: string[];
  reason?: string;
}

function report(
  r: { valid: boolean; signer?: `0x${string}`; signerBound: boolean; testKey?: string; unsignedFields?: string[]; reason?: string },
  expectedSigner: string | undefined,
  digest: `0x${string}` | undefined,
  what: string,
): VerifyToolResult {
  const status = signerStatus(r, expectedSigner);
  // Key order is the Python CLI's: verdict first, the signer and its status next to each other.
  return {
    verdict: verdictSentence(r, expectedSigner, 'expectedSigner', what),
    valid: r.valid,
    ...(r.signer ? { signer: r.signer } : {}),
    ...(status ? { signerStatus: status } : {}),
    signerBound: r.signerBound,
    ...(expectedSigner ? { expectedSigner } : {}),
    ...(r.testKey ? { testKey: r.testKey } : {}),
    ...(digest ? { digest } : {}),
    ...(r.unsignedFields?.length ? { unsignedFields: r.unsignedFields } : {}),
    ...(r.reason ? { reason: r.reason } : {}),
  };
}

/** A digest failure (a float, an out-of-range integer) is a FAIL: an artifact with no canonical
 * content address cannot be the one a ledger recorded. The Python twin decides it the same way. */
function tryDigest(f: () => `0x${string}`): { digest?: `0x${string}`; error?: string } {
  try {
    return { digest: f() };
  } catch (e) {
    return { error: e instanceof Error ? e.message : String(e) };
  }
}

/** A lone UTF-16 surrogate anywhere in what is verified: UTF-8 cannot carry it, so the signed and
 * digested text is U+FFFD, not what the object says. Package text only — no path, since key names
 * are chosen by whoever wrote the object. */
const LONE_SURROGATE_REASON =
  'a string in the object holds a lone UTF-16 surrogate (a \\uD800-\\uDFFF escape) that UTF-8 cannot carry: the signed and digested text would be U+FFFD, not this text';

export async function verifyReceiptTool(artifact: SignedReceipt, expectedSigner?: string): Promise<VerifyToolResult> {
  if (findLoneSurrogate(artifact) !== null) {
    return report({ valid: false, signerBound: false, reason: LONE_SURROGATE_REASON }, expectedSigner, undefined, 'receipt');
  }
  const r = await verifyReceipt(artifact, expectedSigner);
  if (!r.signer) return report(r, expectedSigner, undefined, 'receipt');
  const d = tryDigest(() => digestOf(artifact));
  if (d.error !== undefined) {
    return report({ valid: false, signerBound: false, reason: `cannot compute the canonical digest: ${d.error}` }, expectedSigner, undefined, 'receipt');
  }
  return report(r, expectedSigner, d.digest, 'receipt');
}

export async function verifyRecordTool(
  record: ComplianceRecordV1,
  attestation: SignedComplianceRecord['attestation'],
  expectedSigner?: string,
): Promise<VerifyToolResult> {
  if (findLoneSurrogate({ record, attestation }) !== null) {
    return report({ valid: false, signerBound: false, reason: LONE_SURROGATE_REASON }, expectedSigner, undefined, 'compliance record');
  }
  const r = await verifyComplianceRecord({ record, attestation }, expectedSigner);
  const d = tryDigest(() => recordDigest(record));
  return report(r, expectedSigner, d.digest, 'compliance record');
}

export async function recordRefundTool(deps: McpDeps, originalDigest: `0x${string}`, amount: string, reason: string) {
  if (!deps.ledger) throw new Error('ledger not configured — set TERSIGN_LEDGER_URL / _API_KEY / _SELLER_ID');
  return deps.ledger.recordRefund(originalDigest, amount, reason);
}

export interface OpenDisputeArgs {
  receiptDigest: `0x${string}`;
  reason: DisputeReason;
  claimAmount: string;
  statement?: string | undefined;
}

/** Open a dispute as the PAYER. The configured key signs the dispute; the ledger rejects
 * it (403) unless the signature recovers to the disputed receipt's payer. */
export async function openDisputeTool(deps: McpDeps, args: OpenDisputeArgs) {
  if (!deps.signer) throw new Error('no signing key configured — set TERSIGN_SELLER_KEY (used as the acting key)');
  if (!deps.ledgerHttp) throw new Error('ledger URL not configured — set TERSIGN_LEDGER_URL');
  const now = deps.clock ?? (() => Math.floor(Date.now() / 1000));
  const artifact = await signDispute(
    {
      version: 1,
      receiptDigest: args.receiptDigest,
      reason: args.reason,
      claimAmount: args.claimAmount,
      ...(args.statement !== undefined ? { statement: args.statement } : {}),
      openedAt: now(),
    },
    deps.signer,
  );
  return ledgerFetch(deps.ledgerHttp.url, '/v1/disputes', { body: { artifact } });
}

export interface SubmitEvidenceArgs {
  disputeDigest: `0x${string}`;
  role: 'claimant' | 'respondent';
  artifacts: EvidenceArtifactRef[];
}

export async function submitEvidenceTool(deps: McpDeps, args: SubmitEvidenceArgs) {
  if (!deps.signer) throw new Error('no signing key configured');
  if (!deps.ledgerHttp) throw new Error('ledger URL not configured — set TERSIGN_LEDGER_URL');
  const now = deps.clock ?? (() => Math.floor(Date.now() / 1000));
  const artifact = await signEvidence(
    { version: 1, disputeDigest: args.disputeDigest, role: args.role, artifacts: args.artifacts, submittedAt: now() },
    deps.signer,
  );
  return ledgerFetch(deps.ledgerHttp.url, `/v1/disputes/${args.disputeDigest}/evidence`, {
    body: { artifact },
    ...(args.role === 'respondent' && deps.ledgerHttp.apiKey !== undefined ? { apiKey: deps.ledgerHttp.apiKey } : {}),
  });
}

/** Trigger deterministic adjudication (public — the rulebook is recomputable, so anyone
 * may pull the trigger once the route guard allows it). */
export async function adjudicateDisputeTool(deps: McpDeps, disputeDigest: `0x${string}`) {
  if (!deps.ledgerHttp) throw new Error('ledger URL not configured — set TERSIGN_LEDGER_URL');
  return ledgerFetch(deps.ledgerHttp.url, `/v1/disputes/${disputeDigest}/adjudicate`, { body: {} });
}

export async function getDisputeTool(deps: McpDeps, disputeDigest: `0x${string}`) {
  if (!deps.ledgerHttp) throw new Error('ledger URL not configured — set TERSIGN_LEDGER_URL');
  return ledgerFetch(deps.ledgerHttp.url, `/v1/disputes/${disputeDigest}`);
}

export interface RecordDisclosureArgs {
  text?: string | undefined;
  textDigest?: `0x${string}` | undefined;
  medium?: string | undefined;
  kind?: 'ai-interaction' | 'synthetic-content' | undefined;
  agentId: string;
  resourceUrl?: string | undefined;
}

/** One-call counter-signed disclosure (public wedge route — no API key needed; the ledger
 * defaults to the hosted instance). The text is digested locally; only the digest travels. */
export async function recordDisclosureTool(deps: McpDeps, args: RecordDisclosureArgs) {
  if (!deps.signer) throw new Error('no signing key configured');
  const { recordDisclosure } = await import('../evidence/disclose.js');
  return recordDisclosure({
    ...(args.text !== undefined ? { text: args.text } : {}),
    ...(args.textDigest !== undefined ? { textDigest: args.textDigest } : {}),
    ...(args.medium !== undefined ? { medium: args.medium } : {}),
    ...(args.kind !== undefined ? { kind: args.kind } : {}),
    agentId: args.agentId,
    ...(args.resourceUrl !== undefined ? { resourceUrl: args.resourceUrl } : {}),
    ledger: deps.ledgerHttp?.url ?? 'https://tersign.ai',
    account: deps.signer,
    ...(deps.clock ? { clock: deps.clock } : {}),
  });
}
