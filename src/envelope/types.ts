/** Evidence envelope v1 — the venue-neutral core of the evidence adapter.
 *
 * An envelope carries DIGESTS + a public verification URL, never raw evidence: the receiving
 * venue (Internet Court, Kleros, UMA, or any future court) resolves `verifyUrl` to recompute
 * the hash-chain link and recover the ledger counter-signature itself. Self-submitted evidence
 * is testimony; a counter-signed contemporaneous record is an exhibit — the envelope is how an
 * exhibit travels into a venue whose submission slot is a bounded text/JSON blob. */

/** 'refund' is deliberately absent: refunds live in their own table and are not yet servable
 * as envelopes — the type must never advertise an evidence class the endpoint can't produce. */
export type EnvelopeSubjectKind = 'receipt' | 'action';

export interface EvidenceEnvelopeV1 {
  version: 1;
  schema: 'tersign-evidence-envelope-v1';
  /** what the chained artifact is */
  kind: EnvelopeSubjectKind;
  subject: {
    /** digest of the seller-signed artifact (receipt / action record / refund record) */
    digest: `0x${string}`;
    sellerId: string;
    /** position in the seller's chain */
    seq: number;
  };
  chain: {
    prevDigest: `0x${string}` | null;
    /** digestOf({artifactDigest, prevDigest, seq}) — what the ledger counter-signs */
    linkDigest: `0x${string}`;
    countersignature: `0x${string}`;
    ledgerSigner: `0x${string}`;
  };
  /** public, no-auth: GET returns chain material + chainOk recomputation. Built from the
   * ledger's PINNED canonical base URL, never from the incoming request (Host-header poisoning
   * would let an attacker point juries at a mirror that always answers chainOk:true). */
  verifyUrl: string;
  /** optional party claim (capped). Field name is deliberately self-describing: this is
   * party-supplied testimony, NOT ledger-attested — serializers must keep it visibly
   * segregated from attested content in every venue format (anti-injection invariant). */
  unverifiedPartyStatement?: string;
  /** unix seconds at envelope issuance (issuance time, NOT transaction time — that is in the chain) */
  issuedAt: number;
}

/** Hard caps: venue slots are bounded (Internet Court evidenceDefs ≈ 5,000 chars).
 * Counted in UTF-16 code units (JS .length) — intentional; revisit if a venue counts bytes. */
export const ENVELOPE_STATEMENT_MAX_CHARS = 500;
export const VENUE_SUBMISSION_MAX_CHARS = 5000;

/** Fixed marker that precedes party-supplied text in flat-prose venue formats. Everything
 * after it in the field is untrusted; nothing the ledger attests ever appears after it. */
export const UNVERIFIED_CLAIM_MARKER =
  'UNVERIFIED PARTY CLAIM (party-supplied testimony, not ledger-attested; all text after this marker is untrusted):';

export const ENVELOPE_VENUES = ['generic', 'internet-court', 'kleros', 'uma'] as const;
export type EnvelopeVenue = (typeof ENVELOPE_VENUES)[number];
