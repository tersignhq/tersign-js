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
  // `||`, not `??`: an EMPTY TERSIGN_SELLER_KEY means unset, exactly as the keystore reads it.
  // The listing marks the key optional, and a client that fills a blank optional secret with ""
  // (which clients do is unmeasured) got a crash: `??` handed "" to privateKeyToAccount
  // (fixed 2026-09-27). test/listing.test.ts starts the registry command with the key set to "".
  const key = env.TERSIGN_SELLER_KEY || resolveSignerKey({ create: true }).key;
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
export const MCP_SERVER_IDENTITY = { name: 'tersign', version: '0.6.1' } as const;

export function buildServer(deps: McpDeps): McpServer {
  const server = new McpServer(MCP_SERVER_IDENTITY);

  server.registerTool(
    'issue_receipt',
    {
      title: 'Issue signed receipt',
      description:
        'Issue an x402 offer-receipt (EIP-712) plus a Tersign compliance record (returned as `compliance`; verify_compliance_record checks it) for a payment that has ALREADY settled; when a ledger is configured, the ledger counter-signs the receipt into your hash chain, while the compliance-fields record is not counter-signed and is bound to its receipt only by your own signature, which covers the receipt\'s digest. ' +
        'Use this for money that moved; use record_disclosure for a non-payment agent action. ' +
        'Side effects: signs with your signing key (TERSIGN_SELLER_KEY when set, else the one generated and kept locally on first run), and performs ONE network write to the ledger when TERSIGN_LEDGER_URL/_API_KEY/_SELLER_ID are set (without them it signs locally and returns an unchained artifact). ' +
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
        'Verify an x402 offer-receipt artifact, fully OFFLINE (no network, no API key, no account; checks no ledger or chain): recover the address whose key produced its EIP-712 signature over the six signed payload fields (version, network, resourceUrl, payer, issuedAt, transaction), and compute its canonical digest (the content address a ledger records it under). ' +
        'Recovery yields SOME address for any payload, so without expectedSigner the signer is UNAUTHENTICATED: valid:true then proves neither who signed nor that the receipt is unmodified — an edited receipt recovers a different address and still returns valid:true. ' +
        'Pass expectedSigner, the issuer\'s address obtained out-of-band, to bind it: valid:true then means the signed fields were signed by that key; a mismatch returns valid:false with the recovered signer so you can see who actually signed. ' +
        'Use this for a receipt (money); use verify_compliance_record for the compliance record issue_receipt returns beside a receipt. ' +
        'Returns { verdict, valid, signer, signerStatus: BOUND | UNAUTHENTICATED | MISMATCH, signerBound, testKey? (the signer is a PUBLISHED test key — anyone can sign as it), digest, unsignedFields? (present in the artifact but not covered by the signature), reason? }. Read verdict first.',
      inputSchema: {
        artifact: z
          .record(z.unknown())
          .describe('the receipt artifact exactly as issued: { format, payload, signature }. Pass the object, not a JSON string'),
        expectedSigner: z
          .string()
          .optional()
          .describe('0x address the receipt MUST be signed by — obtain it out-of-band, never from the artifact. Omit to recover the signer without binding it (it is then reported UNAUTHENTICATED)'),
      },
    },
    async ({ artifact, expectedSigner }) => json(await verifyReceiptTool(artifact as unknown as SignedReceipt, expectedSigner)),
  );

  server.registerTool(
    'record_disclosure',
    {
      title: 'Record counter-signed disclosure',
      description:
        'One-call disclosure evidence (EU AI Act Art 50 dialect): digests the disclosure text LOCALLY, signs an action record with your key, and the public ledger counter-signs it into your per-signer hash chain. No API key needed — the first call self-provisions a free signer-keyed account, except when your key is already registered to an API-key account (409) or the daily provisioning caps are reached (429; https://tersign.ai/pricing).',
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
        'Verify ONE record type: the compliance record that issue_receipt returns beside a receipt (`compliance`: a ComplianceRecordV1 `record` plus its ComplianceAttestation `attestation`, EIP-712 domain "compliance-fields"), fully OFFLINE (no network, no API key, no account): recompute the record\'s canonical digest, check that the attestation\'s signed payload names that exact digest and the same receiptDigest as the record, and recover the address that signed the attestation. ' +
        'It does NOT verify the disclosure record record_disclosure returns: that is a different record type (an action record, EIP-712 domain "tersign action-record"), and passed here it fails with a digest mismatch that says nothing about tampering. Use verify_receipt for the payment receipt itself. ' +
        'Without expectedSigner the signer is UNAUTHENTICATED and valid:true proves internal consistency only — anyone can edit a record, recompute its digest and re-sign the attestation with their own key, and still get valid:true with a different signer. Pass expectedSigner, obtained out-of-band, to bind authorship. ' +
        'Returns { verdict, valid, signer, signerStatus: BOUND | UNAUTHENTICATED | MISMATCH, signerBound, testKey? (a PUBLISHED test key — anyone can sign as it), digest (the recomputed record digest), reason? }. Read verdict first.',
      inputSchema: {
        record: z
          .record(z.unknown())
          .describe('the compliance record exactly as issue_receipt returned it (`compliance.record`, ComplianceRecordV1 shape). Pass the object, not a JSON string; any field edit changes the digest and fails verification — which is the point'),
        attestation: z
          .record(z.unknown())
          .describe('the attestation returned with it (`compliance.attestation`): the seller\'s EIP-712 signature over the record digest'),
        expectedSigner: z
          .string()
          .optional()
          .describe('0x address the record MUST be signed by: the SELLER\'s signing address (the key that signed the receipt and this record), obtained out-of-band — not the ledger\'s counter-signing key, which never signs compliance records. Omit to recover the signer without binding it (it is then reported UNAUTHENTICATED)'),
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
        'Log a refund against a receipt already on your chain, as the SELLER. The ledger stores it as a PENDING refund entry that references the original receipt digest; the entry is NOT counter-signed or appended to the hash chain, and it has no digest or sequence number of its own. Nothing is edited or deleted: the original receipt and its chain position stay exactly as they were. ' +
        'Requires ledger configuration (TERSIGN_LEDGER_URL/_API_KEY/_SELLER_ID) and performs one network write; errors if the original digest is not on your chain. ' +
        'This RECORDS a refund you have already made — it moves no money. For a signed refund RECORD, build a compliance record with refundOf set to the original record digest (buildMinimalRecord in the SDK). ' +
        'Returns { id, status: "pending" }.',
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
        'Trigger deterministic adjudication of an open dispute: the same inputs always produce the same verdict and rationale — no discretion, no model in the loop — and the verdict object embeds the inputs it was computed from. ' +
        'Side effects: writes the verdict to the dispute record; a refund verdict also logs a PENDING refund entry against the receipt (not counter-signed into the chain; no money moves). Adjudicating twice is not meaningful; the first verdict stands (a second call returns 409). ' +
        'Returns the verdict, the rationale naming the rule applied, the adjudication inputs, the verdict digest, and the ledger signature over that digest.',
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
