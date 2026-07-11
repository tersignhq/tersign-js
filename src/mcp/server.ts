import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { privateKeyToAccount } from 'viem/accounts';
import { Assure } from '../assure.js';
import { LedgerClient } from '../ledgerClient.js';
import type { SignedReceipt, SignedComplianceRecord, ComplianceRecordV1 } from '../types.js';
import {
  adjudicateDisputeTool,
  getDisputeTool,
  issueReceiptTool,
  openDisputeTool,
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
  const key = env.TERSIGN_SELLER_KEY;
  if (!key) throw new Error('TERSIGN_SELLER_KEY (0x-prefixed private key) is required');
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
export const MCP_SERVER_IDENTITY = { name: 'tersign', version: '0.1.4' } as const;

export function buildServer(deps: McpDeps): McpServer {
  const server = new McpServer(MCP_SERVER_IDENTITY);

  server.registerTool(
    'issue_receipt',
    {
      title: 'Issue signed receipt',
      description:
        'Issue an x402 offer-receipt (EIP-712) plus an Tersign compliance record for a settled payment; counter-signs into the ledger when configured.',
      inputSchema: {
        network: z.string().describe('CAIP-2, e.g. eip155:8453'),
        resourceUrl: z.string().url(),
        payer: z.string(),
        supplyDescription: z.string(),
        settledAt: z.number().int().optional(),
        txHash: z.string().optional(),
        taxScheme: z.enum(['none', 'vat', 'gst', 'jct', 'sales']).optional(),
        currency: z.string().optional(),
        principal: z.string().optional().describe('signed principal behind the paying agent'),
      },
    },
    async (args) => json(await issueReceiptTool(deps, args)),
  );

  server.registerTool(
    'verify_receipt',
    {
      title: 'Verify signed receipt',
      description: 'Verify an offer-receipt artifact (EIP-712) and optionally enforce an expected signer (payTo authorization).',
      inputSchema: {
        artifact: z.record(z.unknown()).describe('the receipt artifact object {format, payload, signature}'),
        expectedSigner: z.string().optional(),
      },
    },
    async ({ artifact, expectedSigner }) => json(await verifyReceiptTool(artifact as unknown as SignedReceipt, expectedSigner)),
  );

  server.registerTool(
    'verify_compliance_record',
    {
      title: 'Verify compliance record',
      description: 'Verify an Tersign compliance record + attestation (digest binding and signature).',
      inputSchema: {
        record: z.record(z.unknown()),
        attestation: z.record(z.unknown()),
        expectedSigner: z.string().optional(),
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
      description: 'Record a refund against a receipt digest in the Tersign ledger (requires ledger configuration).',
      inputSchema: {
        originalDigest: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
        amount: z.string(),
        reason: z.string(),
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
        receiptDigest: digestSchema,
        reason: z.enum(['not_delivered', 'wrong_content', 'duplicate_charge']),
        claimAmount: z.string().describe('claimed refund in the settlement currency'),
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
        disputeDigest: digestSchema,
        role: z.enum(['claimant', 'respondent']),
        artifacts: z
          .array(
            z.object({
              kind: z.enum(['content-digest', 'delivery-attestation', 'payment-proof', 'transcript']),
              digest: digestSchema,
              at: z.number().int().optional(),
              note: z.string().optional(),
            }),
          )
          .min(1),
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
        'Trigger deterministic adjudication of an open dispute (public — the v0 rulebook is recomputable by anyone). Refund verdicts create refund records automatically.',
      inputSchema: { disputeDigest: digestSchema },
    },
    async ({ disputeDigest }) => json(await adjudicateDisputeTool(deps, disputeDigest as `0x${string}`)),
  );

  server.registerTool(
    'get_dispute',
    {
      title: 'Get dispute record',
      description: 'Fetch a dispute record with its evidence, verdict, rationale, and ledger signature.',
      inputSchema: { disputeDigest: digestSchema },
    },
    async ({ disputeDigest }) => json(await getDisputeTool(deps, disputeDigest as `0x${string}`)),
  );

  return server;
}
