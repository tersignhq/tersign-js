#!/usr/bin/env node
/** tersign-verify — third-party receipt verification. No API key, no trust in Tersign:
 * signature recovery is local, and the ledger check only asks the public endpoint whether
 * the counter-signed hash-chain holds.
 *
 *   tersign-verify <receipt.json> [--signer 0xseller] [--ledger https://…]
 *   tersign-verify <0xdigest> [--ledger https://…]
 *
 * A bare digest needs a ledger to check against, and with none named it uses the public
 * Tersign ledger — the one the published digests live on — rather than refusing. The
 * ledger actually used is always printed, so a reader can see which chain answered and
 * that the choice was theirs to change. `--ledger` still wins whenever it is given; a
 * receipt FILE with no `--ledger` verifies its signature locally and checks no chain,
 * which is unchanged.
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

/** Where a bare digest is checked when the caller names no ledger. */
export const DEFAULT_LEDGER = 'https://tersign.ai';

const target = process.argv[2];
if (!target || target.startsWith('--')) {
  console.error('usage: tersign-verify <receipt.json | 0xdigest> [--signer 0xaddr] [--ledger url]');
  console.error(`       a bare digest checks against ${DEFAULT_LEDGER} unless --ledger names another`);
  process.exit(2);
}

const ledger = arg('--ledger');
const expectedSigner = arg('--signer');

async function checkLedger(digest: string, url: string): Promise<void> {
  const res = await fetch(`${url.replace(/\/$/, '')}/v1/receipts/${digest}/verify`);
  const body = (await res.json()) as {
    found?: boolean;
    chainOk?: boolean;
    seq?: number;
    sellerId?: string;
    ledgerSigner?: string;
    commitment?: { seq: number; acc: string; status: string; bitcoinBlockHeight?: number | null };
  };
  // Name the ledger that answered, always — a verifier that hides which chain it consulted is
  // making the reader take its word for the one fact the check exists to establish. Nothing
  // beyond that: `--ledger` is documented in usage and the README, and the failure path is not
  // the place to advertise the alternative to the thing that just failed.
  if (!body.found) fail(`no record of ${digest} on the Tersign ledger (${url})`);
  if (!body.chainOk) fail('ledger record found but the counter-signed hash-chain does NOT verify');
  console.log(`ledger:    ${url}`);
  console.log(`           counter-signed OK (seller ${body.sellerId}, seq ${body.seq}, ledger key ${body.ledgerSigner})`);
  // Present once the record sits under an anchored chain commitment (anchors since 2026-08-28):
  // the accumulator covers every seq ≤ commitment.seq, so the anchor binds this record too.
  const c = body.commitment;
  if (c) {
    const block = c.bitcoinBlockHeight ? ` block ${c.bitcoinBlockHeight}` : '';
    console.log(`           commitment: seq ≤ ${c.seq} committed (acc ${c.acc.slice(0, 10)}…) — ${c.status}${block}`);
  }
}

if (/^0x[0-9a-f]{64}$/i.test(target)) {
  await checkLedger(target, ledger ?? DEFAULT_LEDGER);
  console.log('VALID');
  process.exit(0);
}

let raw: string;
try {
  raw = readFileSync(target, 'utf8');
} catch {
  fail(`cannot read '${target}' — pass a receipt JSON file that exists, or a 0x… digest with --ledger`);
}
let parsed: SignedReceipt | { receipt: SignedReceipt; record?: SignedComplianceRecord };
try {
  parsed = JSON.parse(raw) as typeof parsed;
} catch {
  fail(`'${target}' is not valid JSON — expected a signed receipt file`);
}

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

// A receipt FILE carries its own signature, so it verifies with no network at all. Only
// check a chain when the caller asked for one — defaulting here would turn an offline
// verification into a silent network call, which is the opposite of the point.
if (ledger) await checkLedger(digest, ledger);
console.log('VALID');
