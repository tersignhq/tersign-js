/** The words a verify result is reported in — shared by `tersign verify` (verify-bin.ts) and the
 * MCP verify tools, and the pure halves of the CLI (argument parsing, file-shape resolution,
 * duplicate-key detection) so they can be tested without running the script.
 *
 * The rule every sentence here follows: a verdict never says more than the checks behind it.
 * An unqualified VALID is printed only when the signer is BOUND to an address the caller
 * supplied and that address is not a published test key. Every other PASS says, in the verdict
 * itself, what it does not prove. Same rule as the Python twin (`python3 -m tersign verify`,
 * sdk-py/tersign/__main__.py), in the same words where both have the case; the inputs on which the
 * two exit differently are listed, as measured, in verify-bin.ts. */
import { SIGNED_RECEIPT_FIELDS } from './receipt/eip712.js';
import { byCodePoint, isPlainObject, quoteField, type SignerBinding } from './receipt/binding.js';

export const SIGNED_FIELDS_TEXT = SIGNED_RECEIPT_FIELDS.join(', ');

/** How the caller binds a signer on this surface: the CLI flag, or the MCP argument. */
export type BindHint = '--signer' | 'expectedSigner';

/** `VALID`, or VALID with every qualifier that applies; `INVALID` when not valid. The order is
 * the Python CLI's: signer UNAUTHENTICATED, published test key, record artifact only. */
export function verdictHead(valid: boolean, signerBound: boolean, testKey: boolean, recordArtifactOnly = false): string {
  if (!valid) return 'INVALID';
  const q: string[] = [];
  if (!signerBound) q.push('signer UNAUTHENTICATED');
  if (testKey) q.push('published test key');
  if (recordArtifactOnly) q.push('record artifact only');
  return q.length ? `VALID (${q.join(', ')})` : 'VALID';
}

/** What the signer status means for a receipt, in one or two sentences. */
export function signerExplanation(r: SignerBinding, expected: string | undefined, hint: BindHint, what = 'receipt'): string {
  const s = r.signer ?? '(none)';
  if (!r.valid && r.signer && expected) {
    return `the signature recovers to ${s}, not to the ${hint} ${expected}: this ${what} was not signed by that key, or was altered after signing.`;
  }
  const receipt = what === 'receipt';
  if (r.signerBound) {
    const covered = receipt ? `the signed receipt fields (${SIGNED_FIELDS_TEXT})` : `this ${what}'s signed digests`;
    return `${covered} were signed by ${s}, the address you supplied with ${hint}. The binding is only as strong as the channel that address came from.`;
  }
  const edit = receipt
    ? "an edit to any signed field's value recovers a different address and reaches this same result"
    : `anyone can edit the ${what}, recompute its digest and re-sign it with their own key, and reach this same result`;
  return (
    `the signature recovers to ${s}, but no ${hint} was supplied, so nothing binds that address to the issuer. ` +
    `This proves neither who signed nor that the ${what} is unmodified: ${edit}. For authorship, re-run with ` +
    `${hint} <the issuer's address, obtained out-of-band>.`
  );
}

export function testKeyNote(signer: string, label: string): string {
  return `${signer} is a PUBLISHED test key (${label}): anyone can produce this signature, so it is not evidence of who issued it.`;
}

export function unsignedNote(fields: readonly string[]): string {
  return `${fields.map(quoteField).join(', ')} — in this file but NOT covered by the signature, and not checked here`;
}

/** One sentence for machine readers (the MCP tools' `verdict`): head, then what it means. */
export function verdictSentence(
  r: SignerBinding & { unsignedFields?: readonly string[] },
  expected: string | undefined,
  hint: BindHint,
  what = 'receipt',
): string {
  if (!r.valid) {
    const why = r.signer && expected ? signerExplanation(r, expected, hint, what) : oneLine(r.reason ?? `invalid ${what}`);
    return `INVALID — ${why}`;
  }
  let s = `${verdictHead(true, r.signerBound, Boolean(r.testKey))} — ${signerExplanation(r, expected, hint, what)}`;
  if (r.testKey && r.signer) s += ` ${testKeyNote(r.signer, r.testKey)}`;
  // A count, never the names: they are chosen by whoever wrote the file, and the verdict is the
  // one sentence an agent reads as the tool's own. The names stay in `unsignedFields`.
  const n = r.unsignedFields?.length ?? 0;
  if (n) s += ` ${n} field${n === 1 ? '' : 's'} the signature does not cover ${n === 1 ? 'is' : 'are'} listed in unsignedFields.`;
  return s;
}

/** A library or viem reason, flattened to one line so it can never add an output line. */
export function oneLine(s: string): string {
  return s.replace(/\s*[\r\n\u2028\u2029]+\s*/g, ' ').trim();
}

// ---------------------------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------------------------

/** Every option `tersign verify` accepts. Anything else is refused: an unknown flag used to be
 * ignored, so `verify r.json --sigenr 0xWRONG` printed the same VALID as an unbound run and the
 * operator believed a binding had been checked that never ran. */
export const VERIFY_OPTIONS = {
  '--signer': '--signer 0x<issuer address>',
  '--ledger': '--ledger https://tersign.ai',
} as const;
export type VerifyOption = keyof typeof VERIFY_OPTIONS;

export class UsageError extends Error {}

export const DIGEST_RE = /^0x[0-9a-fA-F]{64}$/;

export function wantsHelp(args: readonly string[]): boolean {
  return args[0] === 'help' || args.includes('--help') || args.includes('-h');
}

/** verify's arguments → { target, opts }. Throws UsageError on anything ambiguous: an unknown or
 * valueless flag, a flag given twice, two targets, no target. Flags may come before or after
 * the target. */
export function parseVerifyArgs(args: readonly string[]): { target: string; opts: Partial<Record<VerifyOption, string>> } {
  let target: string | undefined;
  const opts: Partial<Record<VerifyOption, string>> = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i] as string;
    if (a.startsWith('-') && a !== '-') {
      if (!Object.hasOwn(VERIFY_OPTIONS, a)) {
        throw new UsageError(`unknown option ${a} (accepted: ${Object.keys(VERIFY_OPTIONS).sort().join(', ')})`);
      }
      const flag = a as VerifyOption;
      const v = args[i + 1];
      if (v === undefined || v.startsWith('-')) throw new UsageError(`${flag} requires a value, e.g. ${VERIFY_OPTIONS[flag]}`);
      if (opts[flag] !== undefined) throw new UsageError(`${flag} given twice`);
      opts[flag] = v;
      i++;
      continue;
    }
    if (target !== undefined) throw new UsageError(`one receipt path or digest per run (got ${target} and ${a})`);
    target = a;
  }
  if (target === undefined) throw new UsageError('verify needs a receipt path or a 0x-prefixed 32-byte digest');
  return { target, opts };
}

// ---------------------------------------------------------------------------------------------
// Receipt files
// ---------------------------------------------------------------------------------------------

/** The first key that appears twice in one JSON object, or null. `text` must already have
 * parsed as JSON. JSON.parse is last-wins while a human reader — and many first-wins parsers —
 * take the FIRST, so two "resourceUrl" keys would let the file a reader sees differ from the
 * value this CLI checked, under a VALID. The bundle verifier and the Python CLI refuse them too. */
export function findDuplicateKey(text: string): string | null {
  const stack: Array<{ keys: Set<string> | null; expectKey: boolean }> = [];
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      const top = stack[stack.length - 1];
      if (top?.keys && top.expectKey) {
        const key = JSON.parse(text.slice(i, j + 1)) as string; // decodes escapes: "a" and "\u0061" collide
        if (top.keys.has(key)) return key;
        top.keys.add(key);
        top.expectKey = false;
      }
      i = j;
    } else if (c === '{') {
      stack.push({ keys: new Set(), expectKey: true });
    } else if (c === '[') {
      stack.push({ keys: null, expectKey: false });
    } else if (c === '}' || c === ']') {
      stack.pop();
    } else if (c === ',') {
      const top = stack[stack.length - 1];
      if (top?.keys) top.expectKey = true;
    }
  }
  return null;
}

/** The first number token outside a string that is not a plain integer (`1.0`, `1e2`), or null.
 * JSON.parse collapses `1783761710.0` to `1783761710`, so a file whose bytes carry a float
 * would otherwise verify with the SAME digest as the integer original — while the Python
 * verifier (which parses it as a float) and the ledger (which scans these tokens at ingest)
 * both refuse it. The canonical digest is defined over integers only; so is this CLI. */
export function findNonIntegerNumberToken(text: string): string | null {
  for (let i = 0; i < text.length; i++) {
    const c = text[i] as string;
    if (c === '"') {
      i++;
      while (i < text.length && text[i] !== '"') i += text[i] === '\\' ? 2 : 1;
      continue;
    }
    if (c === '-' || (c >= '0' && c <= '9')) {
      const m = /^-?\d+(\.\d+)?([eE][+-]?\d+)?/.exec(text.slice(i, i + 400));
      if (m && (m[1] !== undefined || m[2] !== undefined)) return m[0];
      i += (m?.[0].length ?? 1) - 1;
    }
  }
  return null;
}

/** The fields an evidence-bundle record file (records/NNNNNN.json) carries beside the signed
 * receipt under `artifact`. The ONLY wrapper fields accepted there — the Python CLI's rule. */
export const RECORD_FIELDS = ['seq', 'format', 'artifactDigest', 'prevDigest', 'linkDigest', 'countersignature'] as const;

export type ResolvedFile =
  | {
      ok: true;
      receipt: unknown;
      record?: unknown;
      /** the wrapper key the receipt was found under, when it was not the file itself */
      under?: 'receipt' | 'artifact';
      /** for a bundle record file: its own fields, which this command does NOT check */
      recordFieldsNotChecked: string[];
    }
  | { ok: false; reason: string };

/** Which object in a parsed file is the receipt this run checks — never a guess, and never one
 * the reader could mistake for another.
 *
 *  {format, payload, signature}                the receipt itself
 *  {receipt, record?}                          a receipt with its compliance record (both checked)
 *  {artifact, seq, format, artifactDigest, …}  an evidence-bundle record file (RECORD_FIELDS)
 *
 * Anything else is refused, not dropped: a receipt at the top level AND under "receipt" /
 * "artifact" (a fabricated top-level receipt borrowing a genuine nested signature), or a
 * wrapper carrying any other field (a stray resourceUrl beside a genuine `artifact` reads as the
 * receipt that was checked). The Python CLI accepts only the receipt and the record-file shapes,
 * so a {receipt, record} file exits differently there (verify-bin.ts lists every measured case). */
export function resolveReceiptFile(doc: unknown): ResolvedFile {
  if (!isPlainObject(doc)) {
    return { ok: false, reason: 'not a signed receipt: expected a JSON object {format, payload, signature}' };
  }
  const own = (k: string) => Object.hasOwn(doc, k);
  const atTop = own('payload') || own('signature');
  const wrappers = (['receipt', 'artifact'] as const).filter(own);
  if (atTop && wrappers.length) {
    return {
      ok: false,
      reason: `not one receipt: a receipt at the top level AND one under ${wrappers.map(quoteField).join(' and ')} — refusing to choose which one the reader means; nothing was verified`,
    };
  }
  if (wrappers.length > 1) {
    return { ok: false, reason: 'not one receipt: a receipt under both "receipt" and "artifact" — refusing to choose; nothing was verified' };
  }
  if (atTop) return { ok: true, receipt: doc, recordFieldsNotChecked: [] };
  const under = wrappers[0];
  if (!under) {
    return {
      ok: false,
      reason: 'not a signed receipt: expected {format, payload, signature}, {receipt, record}, or an evidence-bundle record file',
    };
  }
  const allowed = new Set<string>(under === 'receipt' ? ['receipt', 'record'] : ['artifact', ...RECORD_FIELDS]);
  const extra = Object.keys(doc).filter((k) => !allowed.has(k)).sort(byCodePoint);
  if (extra.length) {
    const shape = under === 'receipt' ? '{receipt, record}' : 'evidence-bundle record';
    return {
      ok: false,
      reason:
        `not one receipt: the file nests a signed ${quoteField(under)} and also carries ${extra.length} top-level ` +
        `field${extra.length === 1 ? '' : 's'} no ${shape} has (first: ${quoteField(extra[0] as string)}), so its top-level ` +
        'fields would read as the receipt while the nested one was checked; nothing was verified. Pass the receipt ' +
        'itself, or an unmodified records/NNNNNN.json.',
    };
  }
  if (under === 'receipt') {
    return own('record')
      ? { ok: true, receipt: doc.receipt, record: doc.record, under, recordFieldsNotChecked: [] }
      : { ok: true, receipt: doc.receipt, under, recordFieldsNotChecked: [] };
  }
  return { ok: true, receipt: doc.artifact, under, recordFieldsNotChecked: RECORD_FIELDS.filter(own) };
}
