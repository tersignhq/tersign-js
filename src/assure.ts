import type { Account } from 'viem/accounts';
import { signReceipt } from './receipt/eip712.js';
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
  /** CAIP-2 */
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

/** The core primitive: after a settled x402 payment, issue the signed base receipt
 * (merged offer-receipt extension, EIP-712) plus the Tersign compliance record bound to it,
 * and counter-sign into the hosted ledger when configured. Attach the result to the
 * SettlementResponse via `attachToExtensions`. */
export class Assure {
  private ledger?: LedgerClient;
  constructor(private cfg: AssureConfig) {
    if (cfg.ledger) this.ledger = new LedgerClient(cfg.ledger);
  }

  async issueFor(ctx: SettlementContext): Promise<IssuedReceipt> {
    const payload: ReceiptPayload = {
      version: 1,
      network: ctx.network,
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

/** Decorate an x402 SettlementResponse body with the receipt at the spec-defined placement
 * (`extensions["offer-receipt"].info.receipt`) and the Tersign record alongside it. */
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
      'compliance-fields': {
        info: {
          record: issued.compliance.record,
          attestation: issued.compliance.attestation,
          ...(issued.ledger
            ? { ledger: { seq: issued.ledger.seq, digest: issued.ledger.digest, countersignature: issued.ledger.countersignature } }
            : {}),
        },
      },
    },
  };
}
