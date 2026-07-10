/** Venue serializers for EvidenceEnvelopeV1. Pure functions — the same envelope serializes for
 * every venue, which is what makes the adapter venue-neutral (supplier-to-N-courts, never
 * bound to one). MUST stay byte-identical to @tersign/ledger's copy (envelope.ts); the
 * cross-impl vector is pinned in both test suites.
 *
 * Anti-injection invariant (all venues): party-supplied text NEVER mixes with ledger-attested
 * prose. It travels either under a self-describing key (`unverifiedPartyStatement`) or after
 * the fixed UNVERIFIED_CLAIM_MARKER, always LAST, so no attested content follows untrusted
 * bytes. A statement can therefore never impersonate the neutral ledger voice to a human or
 * LLM juror. */

import {
  ENVELOPE_STATEMENT_MAX_CHARS,
  UNVERIFIED_CLAIM_MARKER,
  VENUE_SUBMISSION_MAX_CHARS,
  type EvidenceEnvelopeV1,
} from './types.js';

export function assertEnvelopeCaps(env: EvidenceEnvelopeV1): void {
  if (
    env.unverifiedPartyStatement !== undefined &&
    env.unverifiedPartyStatement.length > ENVELOPE_STATEMENT_MAX_CHARS
  ) {
    throw new Error(`envelope statement exceeds ${ENVELOPE_STATEMENT_MAX_CHARS} chars`);
  }
}

/** Internet Court submission: a self-describing JSON string that fits the evidenceDefs slot
 * (≤5,000 chars). Carries digests + verifyUrl, never raw evidence. */
export function toInternetCourtSubmission(env: EvidenceEnvelopeV1): string {
  assertEnvelopeCaps(env);
  const out = JSON.stringify({
    type: 'tersign-evidence-envelope-v1',
    summary:
      `Counter-signed ${env.kind} evidence: artifact ${env.subject.digest} at seq ${env.subject.seq} ` +
      `of seller '${env.subject.sellerId}' chain, counter-signed by neutral ledger ${env.chain.ledgerSigner} ` +
      `at transaction time (before this dispute arose).` +
      (env.unverifiedPartyStatement !== undefined
        ? ` The envelope.unverifiedPartyStatement field is party-supplied testimony, not ledger-attested.`
        : ''),
    envelope: env,
    howToVerify:
      `GET ${env.verifyUrl} (no account) recomputes the hash-chain link and returns chainOk; ` +
      `or recompute locally: linkDigest = keccak256(canonical({artifactDigest, prevDigest, seq})) ` +
      `and recover the counter-signature to ${env.chain.ledgerSigner}.`,
  });
  if (out.length > VENUE_SUBMISSION_MAX_CHARS) {
    throw new Error(`internet-court submission exceeds ${VENUE_SUBMISSION_MAX_CHARS} chars`);
  }
  return out;
}

/** Kleros ERC-1497 evidence JSON. fileURI resolves to the public verify endpoint; fileHash is
 * the artifact digest. The party statement travels in its own self-describing extension field,
 * never inside the attested description (ERC-1497 JSON tolerates extra fields). */
export interface Kleros1497Evidence {
  name: string;
  description: string;
  fileURI: string;
  fileHash: string;
  fileTypeExtension: string;
  unverifiedPartyStatement?: string;
}

export function toKlerosEvidence(env: EvidenceEnvelopeV1): Kleros1497Evidence {
  assertEnvelopeCaps(env);
  return {
    name: `Tersign counter-signed ${env.kind} (seq ${env.subject.seq})`,
    description:
      `Neutral-ledger evidence for ${env.kind} ${env.subject.digest} in seller '${env.subject.sellerId}' ` +
      `hash-chain. Counter-signed at transaction time by ${env.chain.ledgerSigner}; link digest ` +
      `${env.chain.linkDigest}. Verify without trusting any party at the fileURI.` +
      (env.unverifiedPartyStatement !== undefined
        ? ` A party-supplied claim accompanies this evidence in the unverifiedPartyStatement field (not ledger-attested).`
        : ''),
    fileURI: env.verifyUrl,
    fileHash: env.subject.digest,
    fileTypeExtension: 'json',
    ...(env.unverifiedPartyStatement !== undefined
      ? { unverifiedPartyStatement: env.unverifiedPartyStatement }
      : {}),
  };
}

/** UMA-style claim: a compact assertion string a verifier can check mechanically. The party
 * statement, when present, is appended LAST behind the fixed untrusted-text marker. */
export function toUMAClaim(env: EvidenceEnvelopeV1): string {
  assertEnvelopeCaps(env);
  const claim =
    `Tersign evidence envelope v1: ${env.kind} ${env.subject.digest} is entry seq ${env.subject.seq} ` +
    `(prev ${env.chain.prevDigest ?? 'genesis'}) of seller '${env.subject.sellerId}' hash-chain, ` +
    `counter-signed by ${env.chain.ledgerSigner} (link ${env.chain.linkDigest}). ` +
    `Verifiable at ${env.verifyUrl}.` +
    (env.unverifiedPartyStatement !== undefined
      ? ` ${UNVERIFIED_CLAIM_MARKER} ${env.unverifiedPartyStatement}`
      : '');
  if (claim.length > VENUE_SUBMISSION_MAX_CHARS) {
    throw new Error(`uma claim exceeds ${VENUE_SUBMISSION_MAX_CHARS} chars`);
  }
  return claim;
}
