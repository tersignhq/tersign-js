import type { Account } from 'viem/accounts';
import type { Assure, SettlementContext } from '../assure.js';
import { verifyReceipt } from '../receipt/eip712.js';
import { verifyComplianceRecord } from '../compliance/record.js';
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

export async function verifyReceiptTool(artifact: SignedReceipt, expectedSigner?: string) {
  return verifyReceipt(artifact, expectedSigner);
}

export async function verifyRecordTool(
  record: ComplianceRecordV1,
  attestation: SignedComplianceRecord['attestation'],
  expectedSigner?: string,
) {
  return verifyComplianceRecord({ record, attestation }, expectedSigner);
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
