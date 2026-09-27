#!/usr/bin/env node
/** tersign-verify — third-party receipt verification. No API key. A receipt FILE is checked
 * locally (signature recovery, canonical digest) with no trust in Tersign. A DIGEST lookup, and
 * the optional --ledger step after a file, only ASK a ledger whether it holds the record and
 * whether its counter-signed hash-chain holds: that answer is the ledger's own, nothing in it is
 * re-verified here, and the output says so (`VALID (ledger-reported)`).
 *
 *   tersign-verify <receipt.json> [--signer 0xissuer] [--ledger https://…]
 *   tersign-verify <0xdigest> [--ledger https://…]
 *
 * --signer binds the receipt to its issuer: pass the issuer's address, obtained out-of-band
 * (from the issuer through a channel you trust, never from the receipt itself). Without it the
 * signer is reported UNAUTHENTICATED, because a signature recovers to SOME address for any
 * payload: an unbound VALID proves neither who signed nor that the receipt is unmodified.
 * Receipts signed with a published test key are flagged either way. Until 2026-09-27 this
 * printed `signature: OK (signer X)` and a bare `VALID` for exactly those receipts, and ignored
 * a mistyped flag, which is the worst shape a verifier can have: not a wrong answer, an
 * unearned confidence.
 *
 * A file is one of three shapes (verify-report.ts resolveReceiptFile): the receipt itself,
 * {receipt, record}, or an evidence-bundle record file, whose verdict is qualified `record
 * artifact only` because its chain fields are not checked here. Anything else that nests a
 * receipt is refused, as are duplicate keys, non-integer number tokens, and a signed field in
 * another JSON type.
 *
 * Exit status: 0 VALID (read the last line: an unbound, test-key or ledger-reported VALID is
 * qualified there), 1 INVALID, 2 usage (an unknown, valueless or repeated flag, --signer with a
 * digest, a malformed address, a file that is missing, a directory, or not UTF-8 JSON) — the
 * same scheme as `python3 -m tersign verify`, NOT the same status on every input. Measured
 * 2026-09-27 (this build vs sdk-py 0.1.7; 33 adversarial probe files, each run unbound and
 * with two --signer values, plus three extra cases): the two agree except on these inputs,
 * npm/Python exit —
 *   {receipt, record} and {receipt} wrapper files        0/1  (Python has no `receipt` wrapper)
 *   a top-level receipt that also carries a `receipt` key 1/0  (refused here; Python lists it unsigned)
 *   a UTF-8 byte-order mark before the JSON               0/2
 *   a non-integer number token in a record file's own fields 1/0
 *   a NaN token                                           2/1
 *   a receipt FILE with --ledger (deliberate: this checks its digest's chain after the local
 *     checks; Python keeps files offline)                 0/2
 *   absurdly nested JSON                                  1/2
 * The signature-encoding class was re-measured after both twins adopted one canonical encoding
 * (final release pass, same day): 11 probe files (genuine; no 0x; the v 0/1 twin; upper-case hex,
 * all or one digit; a space or a trailing newline in the hex; the high-s twin with v 27/28 and
 * with v 0/1; an object; an array), each unbound and bound — 0/0 on the genuine file, 1/1 on the
 * rest, with the same reason text. The no-0x difference measured earlier is gone.
 * Any other difference is unmeasured, not absent.
 *
 * A bare digest needs a ledger to check against, and with none named it uses the public
 * Tersign ledger — the one the published digests live on — rather than refusing. The
 * ledger actually used is always printed, so a reader can see which chain answered and
 * that the choice was theirs to change. `--ledger` still wins whenever it is given; a
 * receipt FILE with no `--ledger` verifies its signature locally and checks no chain.
 */
import { readFileSync } from 'node:fs';
import { digestOf } from './canonical.js';
import { verifyReceipt } from './receipt/eip712.js';
import { verifyComplianceRecord } from './compliance/record.js';
import { ADDRESS_RE, findLoneSurrogate, safeText, signerStatus } from './receipt/binding.js';
import {
  DIGEST_RE,
  UsageError,
  findDuplicateKey,
  findNonIntegerNumberToken,
  oneLine,
  parseVerifyArgs,
  resolveReceiptFile,
  signerExplanation,
  testKeyNote,
  unsignedNote,
  verdictHead,
  wantsHelp,
} from './verify-report.js';
import type { SignedComplianceRecord, SignedReceipt } from './types.js';

/** Where a bare digest is checked when the caller names no ledger. */
export const DEFAULT_LEDGER = 'https://tersign.ai';

const USAGE =
  'usage: tersign-verify <receipt.json | 0xdigest> [--signer 0xaddr] [--ledger url]\n' +
  `       a bare digest checks against ${DEFAULT_LEDGER} unless --ledger names another\n` +
  "       --signer binds a receipt file to its issuer's address (obtained out-of-band);\n" +
  '       without it the signer is reported UNAUTHENTICATED\n' +
  '       exit: 0 VALID (read the last line) · 1 INVALID · 2 usage';

function usage(msg: string): never {
  console.error(`usage: ${msg}\n\n${USAGE}`);
  process.exit(2);
}

function fail(msg: string): never {
  console.error(`INVALID: ${oneLine(msg)}`);
  process.exit(1);
}

const args = process.argv.slice(2);
if (args.length === 0) {
  console.error(USAGE);
  process.exit(2);
}
if (wantsHelp(args)) {
  console.log(USAGE);
  process.exit(0);
}

let target: string;
let ledger: string | undefined;
let expectedSigner: string | undefined;
try {
  const parsed = parseVerifyArgs(args);
  target = parsed.target;
  ledger = parsed.opts['--ledger'];
  expectedSigner = parsed.opts['--signer'];
  if (ledger !== undefined) {
    let u: URL | undefined;
    try {
      u = new URL(ledger);
    } catch {
      u = undefined;
    }
    if (!u || (u.protocol !== 'https:' && u.protocol !== 'http:')) {
      throw new UsageError(`--ledger must be an http(s) URL, got ${safeText(ledger)}`);
    }
  }
  if (DIGEST_RE.test(target)) {
    if (expectedSigner !== undefined) {
      throw new UsageError(
        "--signer binds a receipt FILE's signature; a digest lookup checks the ledger's counter-signed " +
          'chain instead. Verify the receipt file with --signer.',
      );
    }
  } else if (expectedSigner !== undefined && !ADDRESS_RE.test(expectedSigner)) {
    throw new UsageError(`--signer must be a 20-byte 0x-prefixed hex address, got ${JSON.stringify(expectedSigner)}`);
  }
} catch (e) {
  if (e instanceof UsageError) usage(e.message);
  throw e;
}

async function checkLedger(digest: string, url: string): Promise<void> {
  let body: {
    found?: boolean;
    chainOk?: boolean;
    seq?: number;
    sellerId?: string;
    ledgerSigner?: string;
    commitment?: { seq: number; acc: string; status: string; bitcoinBlockHeight?: number | null };
  };
  try {
    const res = await fetch(`${url.replace(/\/$/, '')}/v1/receipts/${digest}/verify`);
    body = (await res.json()) as typeof body;
  } catch (e) {
    const cause = e instanceof Error && e.cause instanceof Error ? ` (${e.cause.message})` : '';
    fail(`could not get an answer from the ledger at ${url}: ${e instanceof Error ? e.message : String(e)}${cause}`);
  }
  // Name the ledger that answered, always — a verifier that hides which chain it consulted is
  // making the reader take its word for the one fact the check exists to establish. Nothing
  // beyond that: `--ledger` is documented in usage and the README, and the failure path is not
  // the place to advertise the alternative to the thing that just failed.
  if (!body.found) fail(`no record of ${digest} on the Tersign ledger (${url})`);
  if (!body.chainOk) fail('ledger record found but the counter-signed hash-chain does NOT verify');
  // Strings from the ledger are rendered inert: a hostile --ledger must not be able to print
  // a line of its own (a bare VALID, say) through a sellerId.
  const t = (v: unknown) => safeText(String(v));
  console.log(`ledger:    ${url}`);
  // "reports", never "OK": these are the server's own booleans. Nothing here checks the
  // counter-signature against a pinned ledger key — a look-alike server can answer the same.
  console.log(`           reports: found, counter-signed chain intact (seller ${t(body.sellerId)}, seq ${t(body.seq)}, ledger key ${t(body.ledgerSigner)}) — not checked locally`);
  // Present once the record sits under an anchored chain commitment (anchors since 2026-08-28):
  // the accumulator covers every seq ≤ commitment.seq, so the anchor binds this record too.
  const c = body.commitment;
  if (c) {
    const block = c.bitcoinBlockHeight ? ` block ${t(c.bitcoinBlockHeight)}` : '';
    console.log(`           commitment: seq ≤ ${t(c.seq)} committed (acc ${t(String(c.acc).slice(0, 10))}…) — ${t(c.status)}${block}`);
  }
}

if (DIGEST_RE.test(target)) {
  const used = ledger ?? DEFAULT_LEDGER;
  await checkLedger(target, used);
  // Qualified: the verdict is the ledger's answer about itself. Verifying the receipt FILE
  // (with --signer) is the local check.
  console.log(`VALID (ledger-reported) — ${safeText(used)} reports the record and its counter-signed chain; nothing was verified locally`);
  process.exit(0);
}

// ---- a receipt FILE: every check runs before anything is printed, so a failure prints only
// ---- the INVALID line and never a half-report that reads like a pass.
let bytes: Buffer;
try {
  bytes = readFileSync(target);
} catch (e) {
  const code = (e as { code?: string }).code;
  if (code === 'ENOENT') usage(`no such file: ${target} — pass a receipt JSON file, or a 0x-prefixed 32-byte digest`);
  if (code === 'EISDIR') {
    usage(
      `${target} is a directory: pass a receipt JSON file. An evidence bundle directory is checked by ` +
        'the bundle verifier (verify/verify_bundle.py).',
    );
  }
  usage(`cannot read ${target} (${code ?? (e instanceof Error ? e.message : String(e))})`);
}
let text: string;
try {
  // fatal: a lenient decode would swap bad bytes for U+FFFD and verify text the file does not hold
  text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
} catch {
  usage(`${target} is not UTF-8 text — expected a signed receipt JSON file`);
}
let doc: unknown;
try {
  doc = JSON.parse(text);
} catch (e) {
  usage(`${target} is not JSON (${e instanceof Error ? e.message : 'parse error'}) — expected a signed receipt file`);
}
const dup = findDuplicateKey(text);
if (dup !== null) fail(`duplicate key ${JSON.stringify(dup)} — one JSON object, two values for one name`);
const nonInteger = findNonIntegerNumberToken(text);
if (nonInteger !== null) {
  fail(`number ${safeText(nonInteger, 40)} is not an integer — the canonical digest is defined over integers only, and this file's bytes do not survive a parse unchanged`);
}

// A lone surrogate anywhere (key or value) makes the file's text differ from the bytes that are
// signed and digested: UTF-8 cannot carry it, so the encoder substitutes U+FFFD. The Python twin
// refuses such a file too.
const lone = findLoneSurrogate(doc);
if (lone !== null) {
  fail(`${safeText(lone, 64)} holds a lone UTF-16 surrogate (a \\uD800-\\uDFFF escape) that UTF-8 cannot carry — the signed and digested text would be U+FFFD, not what this file says`);
}

const file = resolveReceiptFile(doc);
if (!file.ok) fail(file.reason);
const receipt = file.receipt as SignedReceipt;

const result = await verifyReceipt(receipt, expectedSigner);
if (!result.valid) {
  fail(
    signerStatus(result, expectedSigner) === 'MISMATCH'
      ? `signer MISMATCH — ${signerExplanation(result, expectedSigner, '--signer')}`
      : `receipt signature: ${result.reason ?? 'invalid receipt'}`,
  );
}
let digest: `0x${string}`;
try {
  digest = digestOf(receipt);
} catch (e) {
  fail(`cannot compute the receipt's canonical digest: ${e instanceof Error ? e.message : String(e)}`);
}

let rec: Awaited<ReturnType<typeof verifyComplianceRecord>> | undefined;
if (file.record !== undefined) {
  const record = file.record as SignedComplianceRecord;
  rec = await verifyComplianceRecord(record, expectedSigner);
  if (!rec.valid) {
    fail(
      signerStatus(rec, expectedSigner) === 'MISMATCH'
        ? `record signer MISMATCH — ${signerExplanation(rec, expectedSigner, '--signer', 'record')}`
        : `compliance record: ${rec.reason ?? 'invalid record'}`,
    );
  }
  if (record.record.receiptDigest !== digest) fail('compliance record is bound to a DIFFERENT receipt');
}

const signer = result.signer as string;
console.log(`signature: recovers to ${signer}`);
console.log(`signer:    ${signerStatus(result, expectedSigner)} — ${signerExplanation(result, expectedSigner, '--signer')}`);
if (result.testKey) console.log(`test key:  ${testKeyNote(signer, result.testKey)}`);
if (rec) {
  console.log(`record:    OK — bound to this receipt's digest; signed by ${rec.signer}, signer ${signerStatus(rec, expectedSigner)}`);
  if (rec.testKey && rec.signer && rec.signer.toLowerCase() !== signer.toLowerCase()) {
    console.log(`test key:  ${testKeyNote(rec.signer, rec.testKey)}`);
  }
}
const recordFile = file.under === 'artifact';
if (recordFile) {
  console.log(
    `checked:   the receipt under "artifact" only — the record's own fields (${file.recordFieldsNotChecked.join(', ')}) ` +
      "were NOT checked: not its place in the chain, not the ledger's countersignature. The bundle verifier " +
      '(verify/verify_bundle.py) checks those.',
  );
} else if (file.under) {
  console.log(`checked:   the receipt under ${JSON.stringify(file.under)}${rec ? ' and its compliance record' : ''} in this file`);
}
const unsigned = (result.unsignedFields ?? []).map((f) => (file.under ? `${file.under}.${f}` : f));
if (unsigned.length) console.log(`unsigned:  ${unsignedNote(unsigned)}`);
console.log(`digest:    ${digest}`);

// A receipt FILE carries its own signature, so it verifies with no network at all. Only
// check a chain when the caller asked for one — defaulting here would turn an offline
// verification into a silent network call, which is the opposite of the point.
if (ledger) await checkLedger(digest, ledger);
// The verdict line. Bare `VALID` only when the signer is BOUND, no signer is a test key, and the
// file is the receipt itself or {receipt, record} (a bundle record file is qualified).
console.log(verdictHead(true, result.signerBound, Boolean(result.testKey || rec?.testKey), recordFile));
