import { describe, expect, it } from 'vitest';
import { digestOf } from '../src/canonical.js';
import {
  ENVELOPE_STATEMENT_MAX_CHARS,
  VENUE_SUBMISSION_MAX_CHARS,
  type EvidenceEnvelopeV1,
} from '../src/envelope/types.js';
import { toInternetCourtSubmission, toKlerosEvidence, toUMAClaim } from '../src/envelope/serialize.js';

const D = (b: string) => `0x${b.repeat(32)}` as `0x${string}`;

/** Fixed fixture — identical bytes in @tersign/ledger's test/envelope.test.ts. */
const FIXTURE: EvidenceEnvelopeV1 = {
  version: 1,
  schema: 'tersign-evidence-envelope-v1',
  kind: 'receipt',
  subject: { digest: D('11'), sellerId: 'tersign-first', seq: 7 },
  chain: {
    prevDigest: D('22'),
    linkDigest: D('33'),
    countersignature: `0x${'44'.repeat(65)}` as `0x${string}`,
    ledgerSigner: '0x9d38BA84730271eb27Ac9bD4Bd2620c08dB4FDa6',
  },
  verifyUrl: `https://tersign-ledger.kevinn-zhang.workers.dev/v1/receipts/${D('11')}/verify`,
  unverifiedPartyStatement: 'Delivered resource did not match acceptance criteria.',
  issuedAt: 1783700000,
};

/** Cross-impl drift tripwire: digest of the exact internet-court submission string for the
 * fixture above. MUST equal the vector pinned in the ledger's suite — edit both or neither. */
const IC_SUBMISSION_VECTOR = '0x8fd9f114797f0b9c6c28de32cdadad2d5c7745f9140c8264c2ea6e5ed1d0ced4';

describe('evidence envelope serializers', () => {
  it('internet-court submission fits the slot, round-trips, and pins the cross-impl vector', () => {
    const s = toInternetCourtSubmission(FIXTURE);
    expect(s.length).toBeLessThanOrEqual(VENUE_SUBMISSION_MAX_CHARS);
    const parsed = JSON.parse(s) as { type: string; envelope: EvidenceEnvelopeV1; howToVerify: string };
    expect(parsed.type).toBe('tersign-evidence-envelope-v1');
    expect(parsed.envelope).toEqual(FIXTURE);
    expect(parsed.howToVerify).toContain(FIXTURE.verifyUrl);
    expect(digestOf(JSON.parse(s))).toBe(IC_SUBMISSION_VECTOR);
  });

  it('kleros ERC-1497 evidence carries fileURI=verifyUrl and fileHash=subject digest', () => {
    const k = toKlerosEvidence(FIXTURE);
    expect(k.fileURI).toBe(FIXTURE.verifyUrl);
    expect(k.fileHash).toBe(FIXTURE.subject.digest);
    expect(k.fileTypeExtension).toBe('json');
    expect(k.description).toContain(FIXTURE.chain.linkDigest);
    expect(k.description).not.toContain(FIXTURE.unverifiedPartyStatement); expect(k.unverifiedPartyStatement).toBe(FIXTURE.unverifiedPartyStatement);
  });

  it('uma claim names digest, chain position, signer, and verify URL', () => {
    const u = toUMAClaim(FIXTURE);
    expect(u).toContain(FIXTURE.subject.digest);
    expect(u).toContain('seq 7');
    expect(u).toContain(FIXTURE.chain.ledgerSigner);
    expect(u).toContain(FIXTURE.verifyUrl);
    expect(u).toContain('UNVERIFIED PARTY CLAIM');
    expect(u.indexOf('UNVERIFIED PARTY CLAIM')).toBeGreaterThan(u.indexOf(FIXTURE.verifyUrl));
  });

  it('genesis entries render prev as "genesis"', () => {
    const genesis = { ...FIXTURE, chain: { ...FIXTURE.chain, prevDigest: null } };
    expect(toUMAClaim(genesis)).toContain('(prev genesis)');
  });

  it('rejects over-cap statements in every serializer', () => {
    const fat = { ...FIXTURE, unverifiedPartyStatement: 'x'.repeat(ENVELOPE_STATEMENT_MAX_CHARS + 1) };
    expect(() => toInternetCourtSubmission(fat)).toThrow(/statement exceeds/);
    expect(() => toKlerosEvidence(fat)).toThrow(/statement exceeds/);
    expect(() => toUMAClaim(fat)).toThrow(/statement exceeds/);
  });
});
