/** Wire types for the merged x402 `offer-receipt` extension (spec: x402-foundation/x402
 * specs/extensions/extension-offer-and-receipt.md, fetched 2026-07-07; receipt payload fields
 * and response placement re-read 2026-09-29 at main 5eee1e3c35). Everything outside this module
 * treats these as opaque via the codec functions, so upstream churn lands here only. */

export interface ReceiptPayload {
  version: 1;
  /** CAIP-2, e.g. "eip155:8453" */
  network: string;
  resourceUrl: string;
  payer: string;
  /** unix seconds */
  issuedAt: number;
  /** tx hash, or "" when privacy-minimal (EIP-712 empty-optional rule) */
  transaction: string;
}

export interface OfferPayload {
  version: 1;
  resourceUrl: string;
  scheme: string;
  network: string;
  asset: string;
  payTo: string;
  amount: string;
  /** unix seconds; 0 = absent (EIP-712 zero-optional rule) */
  validUntil: number;
}

export type SignedArtifact<P> =
  | { format: 'eip712'; payload: P; signature: `0x${string}`; acceptIndex?: number }
  | { format: 'jws'; signature: string; acceptIndex?: number };

export type SignedReceipt = SignedArtifact<ReceiptPayload>;
export type SignedOffer = SignedArtifact<OfferPayload>;

/** Adjustment vocabulary as the proposed compliance-fields extension takes it from UCP: `type` is
 * an OPEN string whose typical values are listed here, and only `status` is a fixed enum — so any
 * other `type` string is accepted. */
export type AdjustmentType =
  | 'refund'
  | 'return'
  | 'credit'
  | 'price_adjustment'
  | 'dispute'
  | 'cancellation'
  | (string & {});
export type AdjustmentStatus = 'pending' | 'completed' | 'failed';

export interface Adjustment {
  type: AdjustmentType;
  status: AdjustmentStatus;
  /** minor units, tax-inclusive, as string */
  amount: string;
  currency: string;
  reason?: string;
  /** digest of the receipt/record this adjusts — the hash-chain link */
  adjusts: `0x${string}`;
}

/** Compliance record v1 in the shape the `compliance-fields` extension proposes
 * (x402-foundation/x402#2853, open — not settled spec) — a SEPARATE artifact bound to the base
 * receipt by digest. The base receipt's EIP-712 schema is fixed upstream; extending it would
 * break signatures, so compliance data composes by reference. The MINIMAL tier is isomorphic to
 * the EU VAT Art 226b simplified-invoice content; whether a MINIMAL record suffices as an invoice
 * is decided by the invoicing rules that apply to the supply (Art 219a), not by this record.
 * FULL adds EN 16931-aligned fields. */
export interface ComplianceRecordV1 {
  version: 1;
  /** 1 = RFC 8785 (JCS) serialization, recordDigest = keccak256(utf8(canonical(record))).
   * A MINIMAL member of the proposed extension; `buildMinimalRecord` sets it. Records built by
   * tersign ≤0.5 omit it — readers accept both. */
  canonicalizationVersion?: 1;
  /** keccak256 of the canonicalized base receipt artifact */
  receiptDigest: `0x${string}`;
  /** sequential number per issuer series (Art 226(2)), assigned by the ISSUER before the record
   * is attested. A sequence attested only by its issuer evidences ordering only — never that no
   * record was omitted. `buildMinimalRecord` does not set it. */
  seq?: number;
  issuedAt: number;
  issuer: {
    name: string;
    /** VAT ID / JP T-number / HK BR no. — labeled by jurisdiction */
    taxId?: string;
    jurisdiction: string;
  };
  buyer?: {
    /** signed principal identity — AP2 mandate subject / deployer, never a bare wallet */
    principal?: string;
    /** AP2 Checkout/Payment-Mandate reference (hash), when present */
    mandateRef?: `0x${string}`;
  };
  /** nature of goods/services (Art 226b(c)) */
  supply: { description: string; category?: string };
  lines?: Array<{ description: string; quantity: string; unitPrice: string; net: string }>;
  tax: {
    scheme: 'none' | 'vat' | 'gst' | 'jct' | 'sales';
    currency: string;
    /** total tax, minor units; omit only when scheme = none */
    amount?: string;
    breakdown?: Array<{ rate: string; taxable: string; tax: string; category?: string }>;
  };
  /** fiat-equivalent valuation of the crypto settlement at issuance (1099-DA / profits-tax) */
  settlement?: {
    fiat: { amount: string; currency: string; source: string; asOf: number };
    txHash?: string;
  };
  /** hash-chain to the record this corrects/refunds (Art 226b(e); ViDA corrective-invoice ref) */
  refundOf?: `0x${string}`;
  adjustment?: Adjustment;
  /** retention floor in years the issuer commits to; set it to at least the longest period
   * that applies to the issuer (Art 247(1) leaves it to each Member State — e.g. DE § 14b UStG:
   * eight years). 7 is the default where no longer period applies (HK IRO s.51C, MiCA 5+2), not
   * a statement that 7 suffices. */
  retentionYears: number;
}

/** EIP-712-signed attestation over a compliance record. The record itself is JSON (schema may
 * evolve); the attestation schema stays fixed by binding digests only. */
export interface ComplianceAttestationPayload {
  version: 1;
  recordDigest: `0x${string}`;
  receiptDigest: `0x${string}`;
  issuedAt: number;
}

export type SignedComplianceRecord = {
  record: ComplianceRecordV1;
  attestation: SignedArtifact<ComplianceAttestationPayload>;
};
