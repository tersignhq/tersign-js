/** Receipts the verify tests pin, shared by the library/MCP suite and the CLI suite. */
import { join } from 'node:path';
import type { SignedReceipt } from '../../src/types.js';

export type Eip712Receipt = Extract<SignedReceipt, { format: 'eip712' }>;

/** The live ledger's genesis receipt, seq 1 — the bytes the signature demo verifies. Pinned by
 * its content address (verify-signer-binding.test.ts recomputes it), so this copy cannot drift
 * from the ledger's without failing. */
export const GENESIS: Eip712Receipt = {
  format: 'eip712',
  payload: {
    issuedAt: 1783761710,
    network: 'eip155:8453',
    payer: '0x36f82906859E5B0bd076069f8cdfAea355358b14',
    resourceUrl: 'https://tersign-ledger.kevinn-zhang.workers.dev/v1/receipts/genesis/demo',
    transaction: '',
    version: 1,
  },
  signature:
    '0x88e3f596dc8e6e5f2aeac45b45eac4484c09e2f58a2b787c73469e5927706b18341c362491ecdc0df8764831b07f499210523eb11200bacf340869f50a4c46e81b',
};
export const GENESIS_DIGEST = '0xe5874f1ffe87f0a6dd9eb157730f67b86ee4538b125fe30fcc4e165213dd3fc4';
/** Recovered from the genesis signature; the ledger's genesis seller key. */
export const GENESIS_SIGNER = '0x36f82906859E5B0bd076069f8cdfAea355358b14';

/** Signed by Hardhat/Anvil dev account #0 (by viem). Byte-identical to the Python suite's
 * fixture of the same name, so both verifiers are pinned to one vector. */
export const TEST_KEY_RECEIPT_PATH = join(import.meta.dirname, 'receipt-signed-by-published-test-key.json');
export const TEST_KEY_SIGNER = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
/** That receipt's canonical digest (its content address) — public, printed by both CLIs. */
export const DEV0_RECEIPT_DIGEST = '0x2b64e8201e19803324e4c5223e8bb09ae8166ce109a4d692bc92d808c0fbee6a';
