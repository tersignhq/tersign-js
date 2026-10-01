import type { Account } from 'viem/accounts';
import { signReceipt } from './receipt/eip712.js';
import { toCaip2Network } from './receipt/network.js';
import { buildMinimalRecord, signComplianceRecord, type IssuerConfig, type MinimalRecordInput } from './compliance/record.js';
import { LedgerClient, type LedgerConfig, type CountersignResult } from './ledgerClient.js';
import type { ComplianceRecordV1, ReceiptPayload, SignedComplianceRecord, SignedReceipt } from './types.js';

export interface AssureConfig {
  /** viem account holding the seller's signing key (payTo-key authorization model) */
  signer: Account;
  issuer: IssuerConfig;
  ledger?: LedgerConfig;
}

export interface SettlementContext {
  /** CAIP-2 (`"eip155:8453"`), or an x402 v1 name (`"base"`), which the receipt payload carries as
   * CAIP-2; an unknown name throws. */
  network: string;
  resourceUrl: string;
  payer: string;
  /** unix seconds */
  settledAt: number;
  txHash?: string;
  supplyDescription: string;
  tax?: ComplianceRecordV1['tax'];
  buyer?: ComplianceRecordV1['buyer'];
  fiatValuation?: { amount: string; currency: string; source: string };
}

export interface IssuedReceipt {
  receipt: SignedReceipt;
  compliance: SignedComplianceRecord;
  ledger?: CountersignResult;
}

/** The core primitive: after a settled x402 payment, issue the seller-signed receipt
 * (offer-receipt extension, EIP-712) and the Tersign compliance record. With a ledger configured,
 * the ledger counter-signs the receipt into the seller's hash chain; the compliance-fields record is not
 * counter-signed, and is bound to its receipt only by the seller's own signature, which covers the
 * receipt's digest. Merge the result into the x402 SettlementResponse (the `PAYMENT-RESPONSE`
 * header) with `attachToSettlementResponse`; `withAssure` does this for you. */
export class Assure {
  private ledger?: LedgerClient;
  constructor(private cfg: AssureConfig) {
    if (cfg.ledger) this.ledger = new LedgerClient(cfg.ledger);
  }

  async issueFor(ctx: SettlementContext): Promise<IssuedReceipt> {
    const payload: ReceiptPayload = {
      version: 1,
      network: toCaip2Network(ctx.network),
      resourceUrl: ctx.resourceUrl,
      payer: ctx.payer,
      issuedAt: ctx.settledAt,
      transaction: ctx.txHash ?? '',
    };
    const receipt = await signReceipt(payload, this.cfg.signer);

    const input: MinimalRecordInput = {
      receipt,
      supplyDescription: ctx.supplyDescription,
      tax: ctx.tax ?? { scheme: 'none', currency: 'USD' },
      issuedAt: ctx.settledAt,
    };
    if (ctx.buyer) input.buyer = ctx.buyer;
    if (ctx.fiatValuation) {
      input.settlement = {
        fiat: { ...ctx.fiatValuation, asOf: ctx.settledAt },
        ...(ctx.txHash !== undefined ? { txHash: ctx.txHash } : {}),
      };
    }
    const record = buildMinimalRecord(this.cfg.issuer, input);
    const compliance = await signComplianceRecord(record, this.cfg.signer);

    if (!this.ledger) return { receipt, compliance };
    const ledger = await this.ledger.submitReceipt(receipt, compliance);
    return { receipt, compliance, ledger };
  }
}

/** JSON Schema for `extensions["offer-receipt"]` on a SettlementResponse — the same shape the
 * upstream reference server attaches (x402-foundation/x402 typescript/packages/extensions/src/
 * offer-receipt/server.ts RECEIPT_SCHEMA, main 5eee1e3c35, read 2026-09-29). */
export const OFFER_RECEIPT_RESPONSE_SCHEMA = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  type: 'object',
  properties: {
    receipt: {
      type: 'object',
      properties: {
        format: { type: 'string' },
        payload: {
          type: 'object',
          properties: {
            version: { type: 'integer' },
            network: { type: 'string' },
            resourceUrl: { type: 'string' },
            payer: { type: 'string' },
            issuedAt: { type: 'integer' },
            transaction: { type: 'string' },
          },
          required: ['version', 'network', 'resourceUrl', 'payer', 'issuedAt'],
        },
        signature: { type: 'string' },
      },
      required: ['format', 'signature'],
    },
  },
  required: ['receipt'],
} as const;

function complianceInfo(issued: IssuedReceipt): Record<string, unknown> {
  return {
    record: issued.compliance.record,
    attestation: issued.compliance.attestation,
    ...(issued.ledger
      ? { ledger: { seq: issued.ledger.seq, digest: issued.ledger.digest, countersignature: issued.ledger.countersignature } }
      : {}),
  };
}

/** Merge the receipt and the compliance record into an x402 `SettlementResponse` — the object
 * the HTTP transport carries, base64-encoded, in the `PAYMENT-RESPONSE` header. The receipt goes
 * to `extensions["offer-receipt"].info.receipt` (offer-receipt spec §5.1, same for v1 and v2)
 * with its schema; the record and its attestation to `extensions["compliance-fields"].info`
 * (placement proposed in x402-foundation/x402#2853, open). Every other member of the settlement
 * response, and every other extension, is kept; an `offer-receipt` entry already present is
 * replaced, because the record binds to THIS receipt's digest. */
export function attachToSettlementResponse<T extends Record<string, unknown>>(
  settlement: T,
  issued: IssuedReceipt,
): T & { extensions: Record<string, unknown> } {
  const prior = isPlainRecord(settlement.extensions) ? settlement.extensions : {};
  return {
    ...settlement,
    extensions: {
      ...prior,
      'offer-receipt': { info: { receipt: issued.receipt }, schema: OFFER_RECEIPT_RESPONSE_SCHEMA },
      'compliance-fields': { info: complianceInfo(issued) },
    },
  };
}

function isPlainRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** LEGACY: decorate the resource's JSON response BODY with the same extension entries. The x402
 * v2 HTTP transport carries protocol data in headers only ("Response bodies are a server
 * implementation concern"), so a wallet reading `PAYMENT-RESPONSE` never sees a body placement.
 * Kept for readers built against tersign ≤0.5; `withAssure` uses it only with
 * `legacyBodyPlacement: true`. */
export function attachToExtensions<T extends Record<string, unknown>>(
  responseBody: T,
  issued: IssuedReceipt,
): T & { extensions: Record<string, unknown> } {
  const prior = (responseBody.extensions ?? {}) as Record<string, unknown>;
  return {
    ...responseBody,
    extensions: {
      ...prior,
      'offer-receipt': { info: { receipt: issued.receipt } },
      'compliance-fields': { info: complianceInfo(issued) },
    },
  };
}
