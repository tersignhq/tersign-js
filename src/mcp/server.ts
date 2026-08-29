import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { privateKeyToAccount } from 'viem/accounts';
import { Assure } from '../assure.js';
import { LedgerClient } from '../ledgerClient.js';
import { resolveSignerKey } from '../keystore.js';
import type { SignedReceipt, SignedComplianceRecord, ComplianceRecordV1 } from '../types.js';
import {
  adjudicateDisputeTool,
  getDisputeTool,
  issueReceiptTool,
  openDisputeTool,
  recordDisclosureTool,
  recordRefundTool,
  submitEvidenceTool,
  verifyReceiptTool,
  verifyRecordTool,
  type McpDeps,
} from './tools.js';
import type { EvidenceArtifactRef } from '../dispute/types.js';

/** MCP packaging: exposes assure as tools any MCP-speaking agent can call, so an agent
 * (or its framework) can issue, verify, and chain receipts without importing the SDK.
 * Config via env — see envDeps(). */

export function envDeps(env: Record<string, string | undefined> = process.env): McpDeps {
  // Same key resolution as the CLI surfaces: TERSIGN_SELLER_KEY, else the OS keychain, else a
  // 0600 keyfile, else generate one and persist it. record_disclosure's own description promises
  // that first call self-provisions a signer-keyed account; before this the MCP entry point threw
  // instead, so `npx tersign` died on first run for anyone who had not already exported a key —
  // and no directory or sandbox could introspect the server at all.
  const key = env.TERSIGN_SELLER_KEY ?? resolveSignerKey({ create: true }).key;
  const account = privateKeyToAccount(key as `0x${string}`);
  const assure = new Assure({
    signer: account,
    issuer: {
      name: env.TERSIGN_ISSUER_NAME ?? 'unnamed seller',
      jurisdiction: env.TERSIGN_ISSUER_JURISDICTION ?? 'unknown',
      ...(env.TERSIGN_ISSUER_TAX_ID !== undefined ? { taxId: env.TERSIGN_ISSUER_TAX_ID } : {}),
    },
    ...(env.TERSIGN_LEDGER_URL && env.TERSIGN_LEDGER_API_KEY && env.TERSIGN_LEDGER_SELLER_ID
      ? { ledger: { url: env.TERSIGN_LEDGER_URL, apiKey: env.TERSIGN_LEDGER_API_KEY, sellerId: env.TERSIGN_LEDGER_SELLER_ID } }
      : {}),
  });
  const ledger =
    env.TERSIGN_LEDGER_URL && env.TERSIGN_LEDGER_API_KEY && env.TERSIGN_LEDGER_SELLER_ID
      ? new LedgerClient({ url: env.TERSIGN_LEDGER_URL, apiKey: env.TERSIGN_LEDGER_API_KEY, sellerId: env.TERSIGN_LEDGER_SELLER_ID })
      : undefined;
  return {
    assure,
    signer: account,
    ...(ledger ? { ledger } : {}),
    ...(env.TERSIGN_LEDGER_URL
      ? {
          ledgerHttp: {
            url: env.TERSIGN_LEDGER_URL,
            ...(env.TERSIGN_LEDGER_API_KEY !== undefined ? { apiKey: env.TERSIGN_LEDGER_API_KEY } : {}),
          },
        }
      : {}),
  };
}

function json(value: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(value, null, 2) }] };
}

/** MUST match package.json name/version — the MCP handshake self-reports this identity to
 * every client; mcp.test.ts pins it against package.json so a release bump can't drift it. */
export const MCP_SERVER_IDENTITY = { name: 'tersign', version: '0.4.10' } as const;

export function buildServer(deps: McpDeps): McpServer {
  const server = new McpServer(MCP_SERVER_IDENTITY);

  server.registerTool(
    'issue_receipt',
    {
      title: 'Issue signed receipt',
      description:
        'Issue an x402 offer-receipt (EIP-712) plus a Tersign action record for a payment that has ALREADY settled, and counter-sign both into your hash chain when a ledger is configured. ' +
        'Use this for money that moved; use record_disclosure for a non-payment agent action. ' +
        'Side effects: signs with TERSIGN_SELLER_KEY, and performs ONE network write to the ledger when TERSIGN_LEDGER_URL/_API_KEY/_SELLER_ID are set (without them it signs locally and returns an unchained artifact). ' +
        'Returns the signed receipt artifact, its keccak256 canonical digest, and — when chained — the ledger counter-signature and sequence number.',
      inputSchema: {
        network: z.string().describe('settlement network as CAIP-2, e.g. "eip155:8453" for Base mainnet'),
        resourceUrl: z.string().url().describe('absolute URL of the resource that was paid for; appears verbatim in the receipt'),
        payer: z.string().describe('0x address that paid — the party who can later open a dispute against this receipt'),
        supplyDescription: z.string().describe('what was supplied, in the seller\'s own words; the human-readable line an auditor or venue reads'),
        settledAt: z.number().int().optional().describe('unix seconds when settlement occurred; defaults to now. Set it explicitly when back-filling'),
        txHash: z.string().optional().describe('on-chain settlement transaction hash, when one exists; omit for off-chain or fiat settlement'),
        taxScheme: z
          .enum(['none', 'vat', 'gst', 'jct', 'sales'])
          .optional()
          .describe('tax regime the seller is accounting under; recorded, never computed — Tersign does not calculate tax'),
        currency: z.string().optional().describe('settlement currency code, e.g. "USDC" or "USD"'),
        principal: z
          .string()
          .optional()
          .describe('the party on whose authority the paying agent acted (x402 sense: the buyer who delegated). Omit when a human paid directly'),
      },
    },
    async (args) => json(await issueReceiptTool(deps, args)),
  );

  server.registerTool(
    'verify_receipt',
    {
      title: 'Verify signed receipt',
      description:
        'Verify an offer-receipt artifact: recover the EIP-712 signature and confirm the payload digest binds to it. ' +
        'Fully OFFLINE — no network, no API key, no account; verifying someone else\'s receipt is the intended use. ' +
        'Use this for a receipt (money); use verify_compliance_record for an action record (a non-payment action). ' +
        'Returns { valid, signer, digest } and, when expectedSigner is supplied and does not match, valid:false with the recovered signer so you can see who actually signed.',
      inputSchema: {
        artifact: z
          .record(z.unknown())
          .describe('the receipt artifact exactly as issued: { format, payload, signature }. Pass the object, not a JSON string'),
        expectedSigner: z
          .string()
          .optional()
          .describe('0x address the receipt MUST be signed by — obtain it out-of-band, never from the artifact. Omit to recover the signer without enforcing it'),
      },
    },
    async ({ artifact, expectedSigner }) => json(await verifyReceiptTool(artifact as unknown as SignedReceipt, expectedSigner)),
  );

  server.registerTool(
    'record_disclosure',
    {
      title: 'Record counter-signed disclosure',
      description:
        'One-call disclosure evidence (EU AI Act Art 50 dialect): digests the disclosure text LOCALLY, signs an action record with your key, and the public ledger counter-signs it into your per-signer hash chain. No API key needed — first call self-provisions a free signer-keyed account.',
      inputSchema: {
        text: z.string().optional().describe('the disclosure text as presented — digested locally, never transmitted'),
        textDigest: z.string().regex(/^0x[0-9a-fA-F]{64}$/).optional().describe('pre-computed digest (wins over text)'),
        medium: z.string().optional().describe("channel: 'chat' | 'api' | 'voice' | 'ui' …"),
        kind: z
          .enum(['ai-interaction', 'synthetic-content'])
          .optional()
          .describe("what was disclosed: 'ai-interaction' = the user was told they are talking to an AI; 'synthetic-content' = output was marked machine-generated. Defaults to 'ai-interaction'"),
        agentId: z.string().describe('stable identifier for the disclosing agent — keep it constant across calls so one chain accumulates per agent'),
        resourceUrl: z.string().url().optional().describe('absolute URL of the surface the disclosure was presented on, when there is one'),
      },
    },
    async (args) => json(await recordDisclosureTool(deps, args as Parameters<typeof recordDisclosureTool>[1])),
  );

  server.registerTool(
    'verify_compliance_record',
    {
      title: 'Verify compliance record',
      description:
        'Verify a Tersign action record against its attestation: recompute the record\'s canonical digest, confirm the attestation commits to that exact digest, and recover the signature. ' +
        'Fully OFFLINE — no network, no API key, no account. ' +
        'Use this for an action record (a disclosure or other non-payment agent action); use verify_receipt for a payment receipt. ' +
        'PASS proves integrity and internal consistency only. Authorship needs an out-of-band signer address: pass expectedSigner, or the identity is whatever the artifact claims about itself. ' +
        'Returns { valid, signer, digest }; on mismatch, valid:false plus the recovered signer and the recomputed digest.',
      inputSchema: {
        record: z
          .record(z.unknown())
          .describe('the action record object as issued (ComplianceRecordV1 shape). Pass the object, not a JSON string; any field edit changes the digest and fails verification — which is the point'),
        attestation: z
          .record(z.unknown())
          .describe('the attestation that accompanies the record: the signature over the record digest, as returned alongside it at issuance'),
        expectedSigner: z
          .string()
          .optional()
          .describe('0x address the record MUST be signed by, obtained out-of-band (for the public ledger: https://tersign.ai/v1/ledger). Omit to recover the signer without enforcing it'),
      },
    },
    async ({ record, attestation, expectedSigner }) =>
      json(
        await verifyRecordTool(
          record as unknown as ComplianceRecordV1,
          attestation as unknown as SignedComplianceRecord['attestation'],
          expectedSigner,
        ),
      ),
  );

  server.registerTool(
    'record_refund',
    {
      title: 'Record refund',
      description:
        'Record a refund against an already-chained receipt, as the SELLER. The refund becomes its own counter-signed entry that references the original — nothing is edited or deleted, so the chain stays append-only and both the charge and the refund remain visible. ' +
        'Requires ledger configuration (TERSIGN_LEDGER_URL/_API_KEY/_SELLER_ID) and performs one network write; errors if the original digest is not on your chain. ' +
        'This RECORDS a refund you have already made — it moves no money. ' +
        'Returns the refund record, its digest, the ledger counter-signature and sequence number.',
      inputSchema: {
        originalDigest: z
          .string()
          .regex(/^0x[0-9a-fA-F]{64}$/)
          .describe('0x-prefixed keccak256 digest of the receipt being refunded — the digest returned by issue_receipt, and it must already exist on your chain'),
        amount: z
          .string()
          .describe('refunded amount as a decimal STRING in the original settlement currency, e.g. "12.50". A string, not a number, so no precision is lost. Partial refunds are allowed'),
        reason: z.string().describe('why the refund was issued, in your own words; recorded verbatim for whoever reads the chain later'),
      },
    },
    async ({ originalDigest, amount, reason }) =>
      json(await recordRefundTool(deps, originalDigest as `0x${string}`, amount, reason)),
  );

  const digestSchema = z.string().regex(/^0x[0-9a-fA-F]{64}$/);

  server.registerTool(
    'open_dispute',
    {
      title: 'Open dispute',
      description:
        'Open an objective dispute against a counter-signed receipt as the PAYER (the configured key must be the receipt payer). Reasons: not_delivered, wrong_content, duplicate_charge. Contested non-mechanical claims escalate to the arbiter; duplicate_charge is decided instantly from ledger arithmetic.',
      inputSchema: {
        receiptDigest: digestSchema.describe('0x-prefixed keccak256 digest of the counter-signed receipt being disputed'),
        reason: z
          .enum(['not_delivered', 'wrong_content', 'duplicate_charge'])
          .describe("grounds: 'not_delivered' nothing arrived · 'wrong_content' delivered but not what was bought · 'duplicate_charge' the same supply was billed twice (decided mechanically from the chain, no arbiter)"),
        claimAmount: z
          .string()
          .describe('amount claimed back, as a decimal STRING in the receipt\'s settlement currency, e.g. "12.50"; must not exceed the receipt amount'),
        statement: z.string().optional().describe('for humans reading the record — never an adjudication input'),
      },
    },
    async ({ receiptDigest, reason, claimAmount, statement }) =>
      json(await openDisputeTool(deps, { receiptDigest: receiptDigest as `0x${string}`, reason, claimAmount, statement })),
  );

  server.registerTool(
    'submit_dispute_evidence',
    {
      title: 'Submit dispute evidence',
      description:
        'Submit signed evidence to an open dispute. Claimant evidence must be signed by the payer key; respondent evidence additionally requires the seller API key (TERSIGN_LEDGER_API_KEY).',
      inputSchema: {
        disputeDigest: digestSchema.describe('0x-prefixed digest of the open dispute, as returned by open_dispute'),
        role: z
          .enum(['claimant', 'respondent'])
          .describe("which side you are filing as: 'claimant' = the payer who opened it (payer key) · 'respondent' = the seller answering it (also needs TERSIGN_LEDGER_API_KEY)"),
        artifacts: z
          .array(
            z.object({
              kind: z
                .enum(['content-digest', 'delivery-attestation', 'payment-proof', 'transcript'])
                .describe('what this artifact is; the adjudicator treats each kind differently'),
              digest: digestSchema.describe('0x-prefixed keccak256 digest of the artifact. Only the DIGEST is submitted — the content itself never leaves your side'),
              at: z.number().int().optional().describe('unix seconds the artifact was produced; supply it when timing is part of your argument'),
              note: z.string().optional().describe('short human-readable label for whoever reads the record; never an adjudication input'),
            }),
          )
          .min(1)
          .describe('at least one evidence reference; submit every artifact you want considered in a single call'),
      },
    },
    async ({ disputeDigest, role, artifacts }) =>
      json(
        await submitEvidenceTool(deps, {
          disputeDigest: disputeDigest as `0x${string}`,
          role,
          artifacts: artifacts as EvidenceArtifactRef[],
        }),
      ),
  );

  server.registerTool(
    'adjudicate_dispute',
    {
      title: 'Adjudicate dispute',
      description:
        'Trigger deterministic adjudication of an open dispute. The v0 rulebook is public and the verdict is recomputable by anyone from the chain — no discretion, no model in the loop. ' +
        'Side effects: writes a verdict entry, and a refund verdict automatically creates the corresponding refund record. Adjudicating twice is not meaningful; the first verdict stands. ' +
        'Returns the verdict, the rationale naming the rule applied, and the ledger signature over both.',
      inputSchema: {
        disputeDigest: digestSchema.describe('0x-prefixed digest of the open dispute to adjudicate, as returned by open_dispute'),
      },
    },
    async ({ disputeDigest }) => json(await adjudicateDisputeTool(deps, disputeDigest as `0x${string}`)),
  );

  server.registerTool(
    'get_dispute',
    {
      title: 'Get dispute record',
      description:
        'Fetch a dispute in full: its state, both sides\' evidence references, the verdict and rationale once adjudicated, and the ledger signature over the record. ' +
        'Read-only — one network read, no key required, and safe to poll while a dispute is open.',
      inputSchema: {
        disputeDigest: digestSchema.describe('0x-prefixed digest of the dispute to fetch, as returned by open_dispute'),
      },
    },
    async ({ disputeDigest }) => json(await getDisputeTool(deps, disputeDigest as `0x${string}`)),
  );

  return server;
}
