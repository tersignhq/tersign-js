import type { SignedArtifact } from '../types.js';

export type { VerifyLike } from '../compliance/types.js';

/** Tersign dispute layer v0 — the genuinely unowned layer of agent commerce (x402 ships
 * receipts + idempotency natively; disputes are explicitly out of scope upstream).
 *
 * Design constraints (do not relax):
 * - OBJECTIVE disputes only in v1: reasons limited to claims fixed rules can classify (from
 *   ledger records, or from the seller's silence through the evidence window); anything
 *   contested and non-mechanical is marked ESCALATED, for an external venue the parties choose.
 * - SIGNED-EVIDENCE-ONLY: the triage rules read ledger records and whether each side filed
 *   signed evidence; free text from either party is never an input channel (prompt-injection
 *   neutralization).
 * - Pre-committed outcomes: a triage result is refund or uphold, or the dispute escalates; no
 *   rule can direct value anywhere but refund or uphold, and no outcome moves money.
 * A triage result is data, not an adjudication: it decides no legal claim and binds no one
 * unless the parties separately agree.
 * Everything is content-addressed (keccak digests of canonical JSON) and signed via
 * digest-bound EIP-712 attestations, so payload schemas can evolve without breaking
 * signatures — same pattern as compliance records. */

/** v1 objective reason codes. `quality`-style subjective claims are deliberately absent. */
export type DisputeReason = 'not_delivered' | 'wrong_content' | 'duplicate_charge';

/** The `verdict` wire field: a triage classification, not an adjudication, award or judgment.
 * The type name follows the wire field and stays. */
export type DisputeVerdict = 'refund' | 'uphold';
/** `adjudicated` is the wire name for a dispute the triage rules classified (refund or uphold);
 * `escalated` means a rule (R1-escalate or R3-escalate) found the claim not classifiable, and the
 * dispute is for an external venue the parties choose. */
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
  /** free text for HUMANS reviewing the record — never an input to the triage rules */
  statement?: string;
  /** unix seconds */
  openedAt: number;
}

/** Machine-checkable acceptance criteria a seller pre-commits at offer time. The
 * pre-commitment is the contract surface: the parties, or an external venue they choose, can
 * hold the delivery to THESE instead of assessing quality after the fact. The v0 triage rules
 * do not read them. */
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
