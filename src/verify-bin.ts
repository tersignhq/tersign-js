#!/usr/bin/env node
/** tersign-verify — third-party receipt verification. No API key, no trust in Tersign:
 * signature recovery is local, and the ledger check only asks the public endpoint whether
 * the counter-signed hash-chain holds.
 *
 *   tersign-verify <receipt.json> [--signer 0xseller] [--ledger https://…]
 *   tersign-verify <0xdigest> --ledger https://…
 */
import { readFileSync } from 'node:fs';
import { digestOf } from './canonical.js';
import { verifyReceipt } from './receipt/eip712.js';
import { verifyComplianceRecord } from './compliance/record.js';
import type { SignedComplianceRecord, SignedReceipt } from './types.js';

function arg(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i > 0 ? process.argv[i + 1] : undefined;
}

function fail(msg: string): never {
  console.error(`INVALID: ${msg}`);
  process.exit(1);
}

const target = process.argv[2];
if (!target || target.startsWith('--')) {
  console.error('usage: tersign-verify <receipt.json | 0xdigest> [--signer 0xaddr] [--ledger url]');
  process.exit(2);
}
const ledger = arg('--ledger');
const expectedSigner = arg('--signer');

async function checkLedger(digest: string): Promise<void> {
  if (!ledger) return;
  const res = await fetch(`${ledger.replace(/\/$/, '')}/v1/receipts/${digest}/verify`);
  const body = (await res.json()) as {
    found?: boolean;
    chainOk?: boolean;
    seq?: number;
    sellerId?: string;
    ledgerSigner?: string;
  };
  if (!body.found) fail(`ledger has no record of ${digest}`);
  if (!body.chainOk) fail('ledger record found but the counter-signed hash-chain does NOT verify');
  console.log(`ledger:    counter-signed OK (seller ${body.sellerId}, seq ${body.seq}, ledger key ${body.ledgerSigner})`);
}

if (/^0x[0-9a-f]{64}$/i.test(target)) {
  if (!ledger) fail('a bare digest can only be checked against a ledger — pass --ledger');
  await checkLedger(target);
  console.log('VALID');
  process.exit(0);
}

const parsed = JSON.parse(readFileSync(target, 'utf8')) as
  | SignedReceipt
  | { receipt: SignedReceipt; record?: SignedComplianceRecord };

const receipt = 'payload' in parsed || 'signature' in parsed ? (parsed as SignedReceipt) : parsed.receipt;
const record = 'receipt' in parsed ? parsed.record : undefined;

const result = await verifyReceipt(receipt, expectedSigner);
if (!result.valid) fail(`receipt signature: ${result.reason}`);
const digest = digestOf(receipt);
console.log(`signature: OK (signer ${result.signer})`);
console.log(`digest:    ${digest}`);

if (record) {
  const rec = await verifyComplianceRecord(record, expectedSigner);
  if (!rec.valid) fail(`compliance record: ${rec.reason}`);
  if (record.record.receiptDigest !== digest) fail('compliance record is bound to a DIFFERENT receipt');
  console.log(`record:    OK (bound to receipt, signer ${rec.signer})`);
}

await checkLedger(digest);
console.log('VALID');
