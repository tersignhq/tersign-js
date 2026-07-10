import { describe, expect, it } from 'vitest';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import {
  ACTION_WIRE_VECTOR,
  actionDigest,
  signActionRecord,
  verifyActionRecord,
} from '../src/evidence/action.js';
import type { ActionRecordV1 } from '../src/evidence/action.js';

const deployer = privateKeyToAccount(generatePrivateKey());
const other = privateKeyToAccount(generatePrivateKey());

const record: ActionRecordV1 = {
  version: 1,
  agent: { id: 'support-bot-7', principal: 'acme-hk-ltd', model: 'claude-fable-5', framework: 'claude-agent-sdk' },
  action: { kind: 'disclosure' },
  disclosure: {
    kind: 'ai-interaction',
    presentedAt: 1751900000,
    medium: 'chat',
    textDigest: `0x${'aa'.repeat(32)}`,
  },
  subjectRef: 'subj_9f31',
  occurredAt: 1751900000,
};

describe('action record sign/verify', () => {
  it('roundtrips and recovers the deployer key', async () => {
    const signed = await signActionRecord(record, deployer);
    const result = await verifyActionRecord(signed, deployer.address);
    expect(result.valid).toBe(true);
    expect(result.signer?.toLowerCase()).toBe(deployer.address.toLowerCase());
  });

  it('rejects an unexpected signer', async () => {
    const signed = await signActionRecord(record, other);
    expect((await verifyActionRecord(signed, deployer.address)).valid).toBe(false);
  });

  it('detects post-signing tampering (digest binding)', async () => {
    const signed = await signActionRecord(record, deployer);
    signed.record.disclosure!.presentedAt = 1;
    const result = await verifyActionRecord(signed);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('digest mismatch');
  });

  it('governance-checkpoint records (SAFR shape) roundtrip', async () => {
    const gov: ActionRecordV1 = {
      version: 1,
      agent: { id: 'treasury-agent-1', principal: 'acme-hk-ltd' },
      action: { kind: 'decision', name: 'initiate-transfer', inputDigest: `0x${'bb'.repeat(32)}` },
      governance: { policyId: 'pol-transfers-v3', rulesApplied: ['limit-daily', 'allowlist-dest'], outcome: 'blocked' },
      occurredAt: 1751900100,
    };
    const signed = await signActionRecord(gov, deployer);
    expect((await verifyActionRecord(signed, deployer.address)).valid).toBe(true);
    expect(actionDigest(gov)).toMatch(/^0x[0-9a-f]{64}$/);
  });
});

describe('action wire contract', () => {
  it('pins the EIP-712 material digest (ledger re-declares — must match)', () => {
    expect(ACTION_WIRE_VECTOR).toBe('0xfbd304c31fdc6da09e2e8433875f8afbb4319cd844ddee54c0e555215ed53c10');
  });
});
