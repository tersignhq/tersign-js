import { recoverTypedDataAddress } from 'viem';
import type { Account } from 'viem/accounts';
import { digestOf } from '../canonical.js';
import type { SignedArtifact } from '../types.js';
import type { VerifyLike } from '../compliance/types.js';

/** Agent ACTION records — the governance-evidence dialect (governance-evidence design note).
 *
 * A payment receipt proves an agent PAID; an action record proves what an agent DID:
 * a disclosure was presented (EU AI Act Art 50(1)/(2)), a governance checkpoint ran
 * (MAS SAFR audit-log shape: proposed action → rules applied → outcome), a tool call
 * happened. Records carry DIGESTS of content, never content — the ledger stays a
 * data-minimized evidence chain (GDPR data-minimization posture), and the seller keeps
 * the underlying artifacts under their own retention.
 *
 * Same digest-bound EIP-712 attestation pattern as compliance/dispute records: the
 * signed shape is fixed forever; the record schema can evolve. */

export type ActionKind = 'tool-call' | 'message' | 'decision' | 'disclosure' | 'payment';
export type DisclosureKind = 'ai-interaction' | 'synthetic-content';
export type GovernanceOutcome = 'allowed' | 'blocked' | 'escalated';

export interface ActionRecordV1 {
  version: 1;
  agent: {
    /** stable identifier for the agent (deployer-scoped; ERC-8004/DID id when available) */
    id: string;
    /** signed principal behind the agent — the liability anchor */
    principal?: string;
    model?: string;
    framework?: string;
  };
  action: {
    kind: ActionKind;
    /** tool/function/route name when applicable */
    name?: string;
    inputDigest?: `0x${string}`;
    outputDigest?: `0x${string}`;
  };
  /** Art 50 disclosure evidence: 'ai-interaction' → Art 50(1) (inform natural persons
   * they interact with an AI system); 'synthetic-content' → Art 50(2)/(4) marking and
   * deep-fake/text disclosure. textDigest = digest of the disclosure actually shown. */
  disclosure?: {
    kind: DisclosureKind;
    /** unix seconds the disclosure was presented */
    presentedAt: number;
    /** channel: 'chat' | 'api' | 'voice' | 'ui' … free-form */
    medium?: string;
    textDigest?: `0x${string}`;
  };
  /** SAFR-shaped governance checkpoint evidence (audit-log component: proposed action,
   * rules applied, outcome). SAFR is a MAS industry white paper (2026-07-03), not a
   * mandate — position as alignment, never as statutory compliance. */
  governance?: {
    policyId?: string;
    rulesApplied?: string[];
    outcome: GovernanceOutcome;
    /** digest of the controls-repository snapshot consulted */
    controlsDigest?: `0x${string}`;
  };
  /** opaque per-deployer subject reference — never PII (data-minimization default) */
  subjectRef?: string;
  resourceUrl?: string;
  /** unix seconds the action occurred */
  occurredAt: number;
}

export interface ActionAttestationPayload {
  version: 1;
  actionDigest: `0x${string}`;
  occurredAt: number;
}

export type SignedActionRecord = {
  record: ActionRecordV1;
  attestation: SignedArtifact<ActionAttestationPayload>;
};

export const ACTION_DOMAIN = { name: 'tersign action-record', version: '1', chainId: 1n } as const;

export const ACTION_TYPES = {
  ActionAttestation: [
    { name: 'version', type: 'uint256' },
    { name: 'actionDigest', type: 'bytes32' },
    { name: 'occurredAt', type: 'uint256' },
  ],
} as const;

/** Pinned digest of the action-record EIP-712 material — the ledger re-declares these
 * constants and pins the SAME vector (cross-impl drift tripwire, like DISPUTE_WIRE_VECTOR). */
export const ACTION_WIRE_VECTOR: `0x${string}` = digestOf({
  domain: { ...ACTION_DOMAIN, chainId: 1 },
  types: ACTION_TYPES,
});

export function actionDigest(record: ActionRecordV1): `0x${string}` {
  return digestOf(record);
}

export async function signActionRecord(record: ActionRecordV1, account: Account): Promise<SignedActionRecord> {
  if (!account.signTypedData) throw new Error('account cannot sign typed data');
  const payload: ActionAttestationPayload = {
    version: 1,
    actionDigest: actionDigest(record),
    occurredAt: record.occurredAt,
  };
  const signature = await account.signTypedData({
    domain: ACTION_DOMAIN,
    types: ACTION_TYPES,
    primaryType: 'ActionAttestation',
    message: {
      version: BigInt(payload.version),
      actionDigest: payload.actionDigest,
      occurredAt: BigInt(payload.occurredAt),
    },
  });
  return { record, attestation: { format: 'eip712', payload, signature } };
}

export async function verifyActionRecord(signed: SignedActionRecord, expectedSigner?: string): Promise<VerifyLike> {
  const { record, attestation } = signed;
  if (attestation.format !== 'eip712') return { valid: false, reason: 'jws not implemented in v0' };
  if (attestation.payload.actionDigest !== actionDigest(record)) {
    return { valid: false, reason: 'action digest mismatch — record was altered after signing' };
  }
  if (attestation.payload.occurredAt !== record.occurredAt) {
    return { valid: false, reason: 'attestation/occurredAt mismatch' };
  }
  try {
    const signer = await recoverTypedDataAddress({
      domain: ACTION_DOMAIN,
      types: ACTION_TYPES,
      primaryType: 'ActionAttestation',
      message: {
        version: BigInt(attestation.payload.version),
        actionDigest: attestation.payload.actionDigest,
        occurredAt: BigInt(attestation.payload.occurredAt),
      },
      signature: attestation.signature,
    });
    if (expectedSigner && signer.toLowerCase() !== expectedSigner.toLowerCase()) {
      return { valid: false, signer, reason: 'unexpected signer' };
    }
    return { valid: true, signer };
  } catch (e) {
    return { valid: false, reason: e instanceof Error ? e.message : 'signature recovery failed' };
  }
}
