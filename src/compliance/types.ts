export type {
  Adjustment,
  ComplianceAttestationPayload,
  ComplianceRecordV1,
  SignedComplianceRecord,
  SignedReceipt,
} from '../types.js';

export interface VerifyLike {
  valid: boolean;
  signer?: `0x${string}`;
  reason?: string;
}
