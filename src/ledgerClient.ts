import type { SignedComplianceRecord, SignedReceipt } from './types.js';
import type { EnvelopeVenue, EvidenceEnvelopeV1 } from './envelope/types.js';
import { toInternetCourtSubmission, toKlerosEvidence, toUMAClaim, type Kleros1497Evidence } from './envelope/serialize.js';

export interface LedgerConfig {
  url: string;
  apiKey: string;
  sellerId: string;
  fetchImpl?: typeof fetch;
}

export interface CountersignResult {
  id: string;
  digest: `0x${string}`;
  seq: number;
  prevDigest: `0x${string}` | null;
  countersignature: string;
}

/** Client for the hosted Tersign ledger: counter-signature + hash-chain + exports.
 * The counter-signed chain is what makes a receipt independently verifiable and
 * audit-exportable after the fact — the hosted half of the product. */
export class LedgerClient {
  constructor(private cfg: LedgerConfig) {}

  private get f() {
    return this.cfg.fetchImpl ?? fetch;
  }

  async submitReceipt(artifact: SignedReceipt, compliance?: SignedComplianceRecord): Promise<CountersignResult> {
    const res = await this.f(`${this.cfg.url}/v1/receipts`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${this.cfg.apiKey}`,
      },
      body: JSON.stringify({ sellerId: this.cfg.sellerId, artifact, compliance }),
    });
    if (!res.ok) throw new Error(`ledger submit failed: ${res.status} ${await res.text()}`);
    return (await res.json()) as CountersignResult;
  }

  async recordRefund(originalDigest: `0x${string}`, amount: string, reason: string): Promise<{ id: string }> {
    const res = await this.f(`${this.cfg.url}/v1/refunds`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${this.cfg.apiKey}`,
      },
      body: JSON.stringify({ originalDigest, amount, reason }),
    });
    if (!res.ok) throw new Error(`ledger refund record failed: ${res.status} ${await res.text()}`);
    return (await res.json()) as { id: string };
  }

  /** Fetch the venue-neutral evidence envelope for a chained artifact (public endpoint — works
   * without an API key; the apiKey/sellerId in cfg are unused here). `statement` is an optional
   * party claim (≤500 chars) folded into the envelope, never raw evidence. */
  async fetchEnvelope(digest: `0x${string}`, statement?: string): Promise<EvidenceEnvelopeV1> {
    const q = statement !== undefined ? `?statement=${encodeURIComponent(statement)}` : '';
    const res = await this.f(`${this.cfg.url}/v1/receipts/${digest}/envelope${q}`);
    if (!res.ok) throw new Error(`envelope fetch failed: ${res.status} ${await res.text()}`);
    return (await res.json()) as EvidenceEnvelopeV1;
  }

  /** Fetch + serialize in one call: a jury-ready submission for the named venue. */
  async fetchVenueSubmission(
    digest: `0x${string}`,
    venue: Exclude<EnvelopeVenue, 'generic'>,
    statement?: string,
  ): Promise<string | Kleros1497Evidence> {
    const env = await this.fetchEnvelope(digest, statement);
    if (venue === 'internet-court') return toInternetCourtSubmission(env);
    if (venue === 'kleros') return toKlerosEvidence(env);
    return toUMAClaim(env);
  }
}
