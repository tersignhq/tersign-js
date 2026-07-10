import type { SignedArtifact } from '../types.js';

export type { VerifyLike } from '../compliance/types.js';

/** Tersign dispute layer v0 — the genuinely unowned layer of agent commerce (x402 ships
 * receipts + idempotency natively; disputes are explicitly out of scope upstream).
 *
 * Design constraints (do not relax):
 * - OBJECTIVE disputes only in v1: reasons limited to machine-decidable or
 *   default-judgment-decidable claims; anything contested and non-mechanical ESCALATES.
 * - SIGNED-EVIDENCE-ONLY: the adjudicator reads signed artifacts + ledger records; free-text
 *   from either party is never an input channel (prompt-injection neutralization).
 * - Pre-committed outcomes: verdict ∈ {refund, uphold}; the arbiter can never invent
 *   a third destination for value.
 * Everything is content-addressed (keccak digests of canonical JSON) and signed via
 * digest-bound EIP-712 attestations, so payload schemas can evolve without breaking
 * signatures — same pattern as compliance records. */

/** v1 objective reason codes. `quality`-style subjective claims are deliberately absent. */
export type DisputeReason = 'not_delivered' | 'wrong_content' | 'duplicate_charge';

export type DisputeVerdict = 'refund' | 'uphold';
export type DisputeStatus = 'open' | 'adjudicated' | 'escalated' | 'closed';

export interface DisputePayloadV1 {
  version: 1;
  /** digest of the receipt artifact being disputed */
  receiptDigest: `0x${string}`;
  reason: DisputeReason;
  /** claimed refund, decimal string in the settlement asset/currency of the receipt */
  claimAmount: string;
  /** digest of the seller's pre-committed acceptance criteria, when the offer carried one */
  criteriaDigest?: `0x${string}`;
  /** free text for HUMANS reviewing the record — never an adjudication input */
  statement?: string;
  /** unix seconds */
  openedAt: number;
}

/** Machine-checkable acceptance criteria a seller pre-commits at offer time. The
 * pre-commitment is the contract surface: the arbiter selects between outcomes by
 * evaluating THESE, not by judging quality after the fact. */
export interface CriterionV1 {
  id: string;
  kind: 'content-digest' | 'delivered-by' | 'no-duplicate-charge';
  /** kind-specific parameters, all string-valued (e.g. { expected: "0x…" } for
   * content-digest, { withinSeconds: "300" } for delivered-by) */
  params: Record<string, string>;
  description: string;
}

export interface AcceptanceCriteriaV1 {
  version: 1;
  resourceUrl: string;
  criteria: CriterionV1[];
  /** unix seconds */
  issuedAt: number;
}

export interface EvidenceArtifactRef {
  kind: 'content-digest' | 'delivery-attestation' | 'payment-proof' | 'transcript';
  /** digest of the underlying artifact (content, attestation JSON, tx proof, transcript) */
  digest: `0x${string}`;
  /** unix seconds the referenced event happened, when applicable */
  at?: number;
  note?: string;
}

export interface EvidencePayloadV1 {
  version: 1;
  /** content address of the dispute this evidence answers */
  disputeDigest: `0x${string}`;
  role: 'claimant' | 'respondent';
  artifacts: EvidenceArtifactRef[];
  /** unix seconds */
  submittedAt: number;
}

/** Digest-bound attestation payloads (the only EIP-712-signed shapes — fixed forever). */
export interface DisputeAttestationPayload {
  version: 1;
  disputeDigest: `0x${string}`;
  receiptDigest: `0x${string}`;
  openedAt: number;
}

export interface EvidenceAttestationPayload {
  version: 1;
  evidenceDigest: `0x${string}`;
  disputeDigest: `0x${string}`;
  submittedAt: number;
}

export interface CriteriaAttestationPayload {
  version: 1;
  criteriaDigest: `0x${string}`;
  issuedAt: number;
}

export type SignedDispute = {
  dispute: DisputePayloadV1;
  attestation: SignedArtifact<DisputeAttestationPayload>;
};

export type SignedEvidence = {
  evidence: EvidencePayloadV1;
  attestation: SignedArtifact<EvidenceAttestationPayload>;
};

export type SignedCriteria = {
  criteria: AcceptanceCriteriaV1;
  attestation: SignedArtifact<CriteriaAttestationPayload>;
};
