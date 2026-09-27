/** The published one-liner is the signature demo and appears in every README, the npm page
 * and the ARD catalog, so its behaviour is a public contract. These pin the two halves of it:
 * a bare digest resolves to the default ledger, and a receipt FILE still verifies with no
 * network unless a ledger is explicitly named. */
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, beforeAll } from 'vitest';
import { generatePrivateKey, mnemonicToAccount, privateKeyToAccount } from 'viem/accounts';
import { Assure } from '../src/assure.js';
import { issueReceiptTool } from '../src/mcp/tools.js';
import { signComplianceRecord } from '../src/compliance/record.js';
import { DEV_MNEMONIC } from '../src/receipt/known-keys.js';
import { GENESIS as GENESIS_RECEIPT, GENESIS_DIGEST, GENESIS_SIGNER, DEV0_RECEIPT_DIGEST, TEST_KEY_RECEIPT_PATH, TEST_KEY_SIGNER } from './fixtures/vectors.js';

// NOT imported from ../src/verify-bin.js: that module is a script — it calls process.exit(2)
// on import when argv carries no target, which kills the whole run. The contract is pinned
// through the CLI's own output below, which is the surface third parties actually see.
const DEFAULT_LEDGER = 'https://tersign.ai';

const GENESIS = '0xe5874f1ffe87f0a6dd9eb157730f67b86ee4538b125fe30fcc4e165213dd3fc4';

describe('verify CLI ledger resolution', () => {
  // CI runs `npm test` BEFORE `npm run build`, so dist/ does not exist there. Build it once
  // rather than skipping when it is missing — a test that quietly disappears in CI is worse
  // than no test, and this one first passed locally only because a stale dist/ happened to be
  // sitting there from an earlier manual build.
  //
  // Rebuilt when STALE too, not only when missing: a dist/ older than src/ is a different
  // program, and every assertion below would be about it.
  beforeAll(() => {
    if (!existsSync(cli()) || newestSourceMtime() > statSync(cli()).mtimeMs) {
      execFileSync('npx', ['tsc', '-p', 'tsconfig.build.json'], {
        cwd: join(import.meta.dirname, '..'),
        stdio: 'inherit',
        timeout: 180_000,
      });
    }
    if (!existsSync(cli())) throw new Error(`build did not produce ${cli()}`);
  }, 200_000);

  it('usage names the default ledger — third parties script against this', () => {
    let stderr = '';
    try {
      execFileSync(process.execPath, [cli()], { encoding: 'utf8', timeout: 30_000, stdio: 'pipe' });
    } catch (e) {
      stderr = String((e as { stderr?: string }).stderr ?? '');
    }
    expect(stderr).toContain(`a bare digest checks against ${DEFAULT_LEDGER}`);
  });

  // The digest is the frozen genesis receipt; the assertion is about WHICH ledger is
  // consulted, not about the network, so a run without connectivity fails loudly rather
  // than passing vacuously.
  it('a bare digest with no --ledger consults the default and says so', () => {
    const out = execFileSync(process.execPath, [cli(), GENESIS], { encoding: 'utf8', timeout: 30_000 });
    expect(out).toContain(DEFAULT_LEDGER);
    expect(out).toMatch(/^ledger:\s+https:\/\/tersign\.ai$/m);
    expect(out).toMatch(/reports: found, counter-signed chain intact .* — not checked locally/);
    expect(out).not.toMatch(/counter-signed OK/);
    expect(out.trimEnd().split('\n').pop()).toBe(
      `VALID (ledger-reported) — ${DEFAULT_LEDGER} reports the record and its counter-signed chain; nothing was verified locally`,
    );
  });

  it('an explicit --ledger wins and drops the default note', () => {
    const out = execFileSync(process.execPath, [cli(), GENESIS, '--ledger', DEFAULT_LEDGER], {
      encoding: 'utf8',
      timeout: 30_000,
    });
    expect(out).toContain(DEFAULT_LEDGER);
  });

  it('a receipt file without --ledger stays offline — no chain call', () => {
    // A receipt whose signature cannot recover fails at the signature step. If the CLI had
    // started defaulting a ledger call for FILES too, the failure text would name a ledger.
    const dir = mkdtempSync(join(tmpdir(), 'tersign-verify-'));
    const file = join(dir, 'bad.json');
    writeFileSync(file, JSON.stringify({ payload: { schema: 'x' }, signature: '0x00' }));
    let stderr = '';
    try {
      execFileSync(process.execPath, [cli(), file], { encoding: 'utf8', timeout: 30_000, stdio: 'pipe' });
    } catch (e) {
      stderr = String((e as { stderr?: string }).stderr ?? '');
    }
    expect(stderr).toMatch(/INVALID/);
    expect(stderr).not.toContain(DEFAULT_LEDGER);
  });
});

/** Built output, so the test exercises what actually ships rather than the source. */
function cli(): string {
  return join(import.meta.dirname, '..', 'dist', 'verify-bin.js');
}

function newestSourceMtime(): number {
  const src = join(import.meta.dirname, '..', 'src');
  let newest = 0;
  for (const f of readdirSync(src, { recursive: true }) as string[]) newest = Math.max(newest, statSync(join(src, f)).mtimeMs);
  return newest;
}

// ---------------------------------------------------------------------------------------------
// A verdict never says more than its checks (2026-09-27). 0.4.11 printed `signature: OK (signer
// X)` and a bare `VALID`, exit 0, for a receipt signed with a published test key and for the
// live genesis receipt with its resourceUrl edited, and ignored `--signer` on a digest and any
// flag it did not know. Every run below goes through the BUILT bin, the product a stranger runs.
// ---------------------------------------------------------------------------------------------

type Run = { rc: number | null; stdout: string; stderr: string };

function run(...args: string[]): Run {
  const r = spawnSync(process.execPath, [cli(), ...args], { encoding: 'utf8', timeout: 30_000 });
  return { rc: r.status, stdout: r.stdout, stderr: r.stderr };
}

const STACK = /^\s+at .+:\d+:\d+\)?$|Error\.captureStackTrace|Node\.js v\d/m;

/** The property itself, over any run. A bare `VALID` is allowed ONLY when the signer is BOUND
 * to an address the caller supplied AND is not a published test key; every other pass says, on
 * the verdict line, what it does not prove, and an unbound one says how to bind it. A DIGEST run
 * checks nothing locally, so its verdict is always `VALID (ledger-reported) — …`. (A file run with
 * --ledger that fails at the ledger step does print its local report first: that case is not run
 * through this helper.) */
function assertVerdictNotOverstated(r: Run): void {
  expect(r.stdout + r.stderr).not.toMatch(STACK);
  expect(r.stdout).not.toContain('signature: OK');
  expect(r.stdout).not.toContain('counter-signed OK');
  const lines = r.stdout.split('\n').filter((l) => l !== '');
  if (r.rc !== 0) {
    expect(r.stdout, 'a failing run prints no verdict on stdout').toBe('');
    return;
  }
  const verdicts = lines.filter((l) => l.startsWith('VALID'));
  expect(verdicts, 'exactly one verdict line, and it is the last').toEqual([lines[lines.length - 1]]);
  const last = lines[lines.length - 1] as string;
  if (!/^signer: {4}/m.test(r.stdout) && /^ledger: {4}/m.test(r.stdout)) {
    // a digest run: no signature was recovered, so the verdict can only be the ledger's
    expect(last).toMatch(/^VALID \(ledger-reported\) — .+ reports the record and its counter-signed chain; nothing was verified locally$/);
    return;
  }
  const bound = /^signer: {4}BOUND — /m.test(r.stdout);
  const unbound = /^signer: {4}UNAUTHENTICATED — /m.test(r.stdout);
  const testKey = /^test key: {2}.* is a PUBLISHED test key /m.test(r.stdout);
  const recordFile = /^checked: {3}the receipt under "artifact" only — /m.test(r.stdout);
  expect(bound !== unbound, 'exactly one signer status').toBe(true);
  // the verdict line and the lines above it tell one story
  expect(last.includes('signer UNAUTHENTICATED'), 'verdict vs signer line').toBe(unbound);
  expect(last.includes('published test key'), 'verdict vs test key line').toBe(testKey);
  expect(last.includes('record artifact only'), 'verdict vs checked line').toBe(recordFile);
  if (last === 'VALID') {
    expect(bound && !testKey && !recordFile, `bare VALID with bound=${bound} testKey=${testKey} recordFile=${recordFile}`).toBe(true);
    return;
  }
  if (unbound) {
    expect(last).toContain('signer UNAUTHENTICATED');
    // the instruction itself, not merely a mention of the flag ("no --signer was supplied")
    expect(r.stdout).toContain("re-run with --signer <the issuer's address, obtained out-of-band>");
  }
  if (testKey) expect(last).toContain('published test key');
}

describe('verify CLI — a verdict never says more than its checks', () => {
  let dir = '';
  const write = (name: string, v: unknown): string => {
    const p = join(dir, name);
    writeFileSync(p, typeof v === 'string' ? v : JSON.stringify(v));
    return p;
  };
  const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;
  const tampered = () => {
    const t = clone(GENESIS_RECEIPT);
    t.payload.resourceUrl = 'https://attacker.example/tampered';
    return t;
  };
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'tersign-verify-binding-'));
  });

  it('a published-test-key receipt never prints a bare VALID', () => {
    const r = run(TEST_KEY_RECEIPT_PATH);
    assertVerdictNotOverstated(r);
    expect(r.rc).toBe(0);
    expect(r.stdout.trimEnd().split('\n').pop()).toBe('VALID (signer UNAUTHENTICATED, published test key)');
    expect(r.stdout).toContain('Hardhat/Anvil default dev mnemonic, account #0');
    expect(r.stdout).toContain(`digest:    ${DEV0_RECEIPT_DIGEST}`);
  });

  it('bound to the test key it is still flagged', () => {
    const r = run(TEST_KEY_RECEIPT_PATH, '--signer', TEST_KEY_SIGNER);
    assertVerdictNotOverstated(r);
    expect(r.rc).toBe(0);
    expect(r.stdout.trimEnd().split('\n').pop()).toBe('VALID (published test key)');
  });

  it('genesis unbound is qualified; bound to its signer it is a plain VALID', () => {
    const g = write('g.json', GENESIS_RECEIPT);
    const u = run(g);
    assertVerdictNotOverstated(u);
    expect(u.stdout.trimEnd().split('\n').pop()).toBe('VALID (signer UNAUTHENTICATED)');
    const b = run(g, '--signer', GENESIS_SIGNER);
    assertVerdictNotOverstated(b);
    expect(b.rc).toBe(0);
    expect(b.stdout.trimEnd().split('\n').pop()).toBe('VALID');
    expect(b.stdout).toContain(`digest:    ${GENESIS_DIGEST}`);
  });

  it('--signer is honoured, in any position — the exact 0.4.11 input that printed VALID', () => {
    const g = write('g.json', GENESIS_RECEIPT);
    const r = run(g, '--signer', '0x' + '0'.repeat(39) + '1');
    assertVerdictNotOverstated(r);
    expect(r.rc).toBe(1);
    expect(r.stderr).toMatch(/^INVALID: signer MISMATCH — the signature recovers to 0x36f8/);
    const first = run('--signer', GENESIS_SIGNER, g);
    assertVerdictNotOverstated(first);
    expect(first.rc).toBe(0);
    expect(first.stdout.trimEnd().split('\n').pop()).toBe('VALID');
  });

  it('an edited receipt: unbound it is qualified (a different signer), bound it fails', () => {
    const t = write('t.json', tampered());
    const u = run(t);
    assertVerdictNotOverstated(u);
    expect(u.rc).toBe(0);
    expect(u.stdout).not.toContain(GENESIS_SIGNER);
    expect(run(t, '--signer', GENESIS_SIGNER).rc).toBe(1);
  });

  it('the fabricated-wrapper vector: a forged top-level receipt around a genuine nested one is refused', () => {
    // From the review of the Python CLI's signer-binding fix: a fabricated receipt at the top
    // level, a genuine issuer-signed one nested under "artifact". Checking either one while the
    // reader looks at the other lets the forgery borrow the genuine signature.
    const forged = {
      format: 'eip712',
      payload: { version: 1, network: 'eip155:8453', resourceUrl: 'https://attacker.example/refund-all', payer: '0x000000000000000000000000000000000000dEaD', issuedAt: 1790000000, transaction: '0xdeadbeef' },
      signature: '0x' + '11'.repeat(65),
      artifact: GENESIS_RECEIPT,
    };
    const f = write('nested.json', forged);
    for (const args of [[f], [f, '--signer', GENESIS_SIGNER]]) {
      const r = run(...args);
      assertVerdictNotOverstated(r);
      expect(r.rc).toBe(1);
      expect(r.stderr).toMatch(/^INVALID: not one receipt: a receipt at the top level AND one under "artifact"/);
    }
    // the mirror image: a genuine top-level receipt with a forged nested one
    const r2 = run(write('nested2.json', { ...GENESIS_RECEIPT, artifact: forged }), '--signer', GENESIS_SIGNER);
    expect(r2.rc).toBe(1);
    expect(r2.stderr).toMatch(/^INVALID: not one receipt/);
  });

  it('a wrapper is accepted only in a known shape; a record file is qualified and names what it did not check', () => {
    // a genuine receipt under "artifact" with a stray top-level field: a reader takes the
    // top-level resourceUrl for the checked receipt, so nothing is verified (Python: exit 1 too)
    const loose = write('loose.json', { resourceUrl: 'https://attacker.example/refund-all', payer: '0xdead', artifact: GENESIS_RECEIPT });
    const l = run(loose, '--signer', GENESIS_SIGNER);
    assertVerdictNotOverstated(l);
    expect(l.rc).toBe(1);
    expect(l.stderr).toMatch(/^INVALID: not one receipt: the file nests a signed "artifact" and also carries 2 top-level fields no evidence-bundle record has \(first: "payer"\)/);
    // the same for {receipt, record} with anything else beside them
    const r2 = run(write('receipt-extra.json', { receipt: GENESIS_RECEIPT, note: 'x' }), '--signer', GENESIS_SIGNER);
    expect(r2.rc).toBe(1);
    expect(r2.stderr).toMatch(/^INVALID: not one receipt: the file nests a signed "receipt"/);
    // a bundle / ledger record file: accepted, qualified, and its chain-link fields named
    const tk = JSON.parse(readFileSync(TEST_KEY_RECEIPT_PATH, 'utf8')) as unknown;
    const rec = write('000001.json', { seq: 1, format: 'eip712', artifact: tk, artifactDigest: DEV0_RECEIPT_DIGEST, prevDigest: null, linkDigest: '0x' + '0'.repeat(64), countersignature: '0x00' });
    const b = run(rec);
    assertVerdictNotOverstated(b);
    expect(b.rc).toBe(0);
    expect(b.stdout).toContain("the record's own fields (seq, format, artifactDigest, prevDigest, linkDigest, countersignature) were NOT checked");
    expect(b.stdout.trimEnd().split('\n').pop()).toBe('VALID (signer UNAUTHENTICATED, published test key, record artifact only)');
    // bound, and not a test key: still qualified, because the record's own fields were not checked
    const g = write('g-record.json', { seq: 1, format: 'eip712', artifact: GENESIS_RECEIPT, artifactDigest: GENESIS_DIGEST, prevDigest: null });
    const gb = run(g, '--signer', GENESIS_SIGNER);
    assertVerdictNotOverstated(gb);
    expect(gb.stdout.trimEnd().split('\n').pop()).toBe('VALID (record artifact only)');
  });

  it('fields outside the signature are named on a plain receipt too', () => {
    const a = clone(GENESIS_RECEIPT) as unknown as Record<string, unknown> & { payload: Record<string, unknown> };
    a.payload.amount = '1000000';
    a.acceptIndex = 0;
    const r = run(write('a.json', a), '--signer', GENESIS_SIGNER);
    assertVerdictNotOverstated(r);
    expect(r.stdout).toMatch(/^unsigned: {2}"payload\.amount", "acceptIndex" — /m);
  });

  it('a receipt with its action record: both signers are reported and bound by one --signer', async () => {
    const account = privateKeyToAccount(generatePrivateKey());
    const issued = await issueReceiptTool(
      { assure: new Assure({ signer: account, issuer: { name: 'T', jurisdiction: 'HK' } }), clock: () => 1751856000 },
      { network: 'eip155:8453', resourceUrl: 'https://api.example.com/data', payer: '0x857b06519E91e3A54538791bDbb0E22373e36b66', supplyDescription: 'd' },
    );
    const f = write('with-record.json', { receipt: issued.receipt, record: issued.compliance });
    const u = run(f);
    assertVerdictNotOverstated(u);
    expect(u.rc).toBe(0);
    expect(u.stdout).toMatch(/^record: {4}OK — bound to this receipt's digest; signed by 0x[0-9a-fA-F]{40}, signer UNAUTHENTICATED$/m);
    const b = run(f, '--signer', account.address);
    assertVerdictNotOverstated(b);
    expect(b.stdout.trimEnd().split('\n').pop()).toBe('VALID');
    expect(b.stdout).toMatch(/signer BOUND$/m);
    expect(run(f, '--signer', GENESIS_SIGNER).rc).toBe(1);
    // a record signed with a published test key qualifies the verdict even when the receipt's key does not
    const dev = mnemonicToAccount(DEV_MNEMONIC, { addressIndex: 2 });
    const byDev = await issueReceiptTool(
      { assure: new Assure({ signer: dev, issuer: { name: 'T', jurisdiction: 'HK' } }), clock: () => 1751856000 },
      { network: 'eip155:8453', resourceUrl: 'https://api.example.com/data', payer: '0x857b06519E91e3A54538791bDbb0E22373e36b66', supplyDescription: 'd' },
    );
    const t = run(write('dev-record.json', { receipt: byDev.receipt, record: byDev.compliance }), '--signer', dev.address);
    assertVerdictNotOverstated(t);
    expect(t.stdout.trimEnd().split('\n').pop()).toBe('VALID (published test key)');
    // only the RECORD is signed with a test key; the receipt's key is not one
    const mixed = await signComplianceRecord(issued.compliance.record, dev);
    const m = run(write('mixed.json', { receipt: issued.receipt, record: mixed }));
    assertVerdictNotOverstated(m);
    expect(m.rc).toBe(0);
    expect(m.stdout).toContain(`test key:  ${dev.address} is a PUBLISHED test key (Hardhat/Anvil default dev mnemonic, account #2)`);
    expect(m.stdout.trimEnd().split('\n').pop()).toBe('VALID (signer UNAUTHENTICATED, published test key)');
  });

  it('duplicate keys fail instead of checking the last value — escaped spellings included', () => {
    const text = JSON.stringify(GENESIS_RECEIPT);
    for (const [name, second] of [['d.json', '"resourceUrl":'], ['d2.json', '"resource\\u0055rl":']] as const) {
      const dup = text.replace('"resourceUrl":', `"resourceUrl": "https://attacker.example/seen-first", ${second}`);
      const r = run(write(name, dup), '--signer', GENESIS_SIGNER);
      assertVerdictNotOverstated(r);
      expect(r.rc).toBe(1);
      expect(r.stderr).toContain('duplicate key "resourceUrl"');
    }
  });

  it('a float token is refused even where the parse would collapse it to the integer', () => {
    // 1783761710.0 parses to 1783761710, so without the raw-token check this file verified with
    // the genesis digest itself, bytes the Python verifier and the ledger both refuse.
    const text = JSON.stringify(GENESIS_RECEIPT);
    for (const [name, token] of [['f1.json', '1783761710.0'], ['f2.json', '1.78376171e9']] as const) {
      const r = run(write(name, text.replace('1783761710', token)), '--signer', GENESIS_SIGNER);
      assertVerdictNotOverstated(r);
      expect(r.rc, token).toBe(1);
      expect(r.stderr).toContain(`number ${token} is not an integer`);
    }
  });

  it('a signed field in another JSON type is refused, not coerced to the signed number', () => {
    // version "1" and issuedAt " 1783761710 " recovered the genesis signer under a different
    // digest: BigInt() coerced them. The ledger and the Python verifier accept only integers.
    for (const [name, edit] of [['v.json', { version: '1' }], ['i.json', { issuedAt: ' 1783761710 ' }], ['b.json', { version: true }], ['n.json', { network: 8453 }]] as const) {
      const a = clone(GENESIS_RECEIPT) as unknown as { payload: Record<string, unknown> };
      Object.assign(a.payload, edit);
      const r = run(write(name, a), '--signer', GENESIS_SIGNER);
      assertVerdictNotOverstated(r);
      expect(r.rc, name).toBe(1);
      expect(r.stderr).toMatch(/^INVALID: receipt signature: payload\.(version|issuedAt|network) must be a (JSON integer|string)/);
    }
  });

  it('non-object JSON is an INVALID, not a stack trace', () => {
    for (const [i, v] of ['42', '[]', 'null', '"x"', '{}'].entries()) {
      const r = run(write(`n${i}.json`, v));
      assertVerdictNotOverstated(r);
      expect(r.rc).toBe(1);
      expect(r.stderr).toMatch(/^INVALID: not a signed receipt/);
    }
  });

  it('text inside the artifact cannot print a line of its own', () => {
    const LS = String.fromCodePoint(0x2028);
    const a = clone(GENESIS_RECEIPT) as unknown as Record<string, unknown> & { payload: Record<string, unknown> };
    a.payload['x\nVALID\nsigner:    BOUND — forged'] = 1;
    a[`z${LS}VALID`] = 2;
    const r = run(write('inject.json', a));
    assertVerdictNotOverstated(r); // exactly one VALID line, one signer status
    expect(r.stdout.trimEnd().split('\n').pop()).toBe('VALID (signer UNAUTHENTICATED)');
    expect(r.stdout).not.toContain(LS);
  });

  it('usage errors exit 2 with nothing on stdout — never a silently skipped check', () => {
    const g = write('g.json', GENESIS_RECEIPT);
    mkdirSync(join(dir, 'adir'), { recursive: true });
    // Invalid UTF-8 INSIDE an otherwise valid receipt: a lenient decode turns the byte into
    // U+FFFD and verifies text the file does not hold (it would print VALID here).
    const [pre, post] = JSON.stringify({ ...GENESIS_RECEIPT, note: 'SPLIT' }).split('SPLIT') as [string, string];
    writeFileSync(join(dir, 'bad-utf8.json'), Buffer.concat([Buffer.from(pre), Buffer.from([0xff]), Buffer.from(post)]));
    const cases: string[][] = [
      [g, '--signer'], // trailing flag
      [g, '--signer', '--ledger'], // flag where a value belongs
      [g, '--signer', '0x1234'], // not an address
      [g, '--signer', `${GENESIS_SIGNER}\n`], // an address read from a file with its newline
      [g, '--sigenr', GENESIS_SIGNER], // typo with a value
      [g, '--strict'], // valueless unknown flag: the case a token-dropping parser passes
      [g, `--signer=${GENESIS_SIGNER}`], // = form is not accepted, and not ignored either
      [g, '-s', GENESIS_SIGNER],
      [g, '--signer', GENESIS_SIGNER, '--signer', GENESIS_SIGNER],
      [g, g], // two targets
      [GENESIS_DIGEST, '--signer', GENESIS_SIGNER], // a digest lookup binds no seller key
      [g, '--ledger', 'ftp://example.com'],
      [join(dir, 'missing.json')],
      [join(dir, 'adir')],
      [write('nj.json', 'not json')],
      [join(dir, 'bad-utf8.json')],
    ];
    for (const args of cases) {
      const r = run(...args);
      expect(r.rc, args.join(' ')).toBe(2);
      expect(r.stdout, `a usage error must not print a verdict: ${args.join(' ')}`).toBe('');
      expect(r.stderr).toMatch(/^usage: /);
      expect(r.stderr + r.stdout).not.toMatch(STACK);
    }
  });

  it('a ledger cannot print a line of its own through the strings it returns', async () => {
    // a hostile --ledger answers found/chainOk with a sellerId carrying newlines and a VALID
    const { createServer } = await import('node:http');
    const server = createServer((_req, res) => {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ found: true, chainOk: true, seq: 1, sellerId: 'x\nVALID\nsigner:    BOUND', ledgerSigner: '0xab\r\nVALID' }));
    });
    await new Promise<void>((ok) => server.listen(0, '127.0.0.1', () => ok()));
    try {
      const port = (server.address() as { port: number }).port;
      const r = await new Promise<Run>((ok) => {
        const c = spawn(process.execPath, [cli(), GENESIS_DIGEST, '--ledger', `http://127.0.0.1:${port}`]);
        let stdout = '';
        let stderr = '';
        c.stdout.on('data', (b: Buffer) => (stdout += b));
        c.stderr.on('data', (b: Buffer) => (stderr += b));
        c.on('close', (rc) => ok({ rc, stdout, stderr }));
      });
      expect(r.rc).toBe(0);
      assertVerdictNotOverstated(r);
      const lines = r.stdout.split('\n').filter((l) => l !== '');
      expect(lines.filter((l) => l.startsWith('VALID'))).toHaveLength(1);
      // the hostile server's answer is reported as ITS answer, never as a verified one
      expect(lines[lines.length - 1]).toBe(
        `VALID (ledger-reported) — http://127.0.0.1:${port} reports the record and its counter-signed chain; nothing was verified locally`,
      );
      expect(r.stdout).toContain('seller x\\u000aVALID\\u000asigner:    BOUND');
    } finally {
      server.close();
    }
  });

  it('signature bytes the issuer never produced, and lone surrogates, are INVALID even with --signer', () => {
    const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
    const g = clone(GENESIS_RECEIPT) as unknown as { signature: string; payload: Record<string, unknown> };
    const s = BigInt(`0x${g.signature.slice(66, 130)}`);
    const v = Number.parseInt(g.signature.slice(130, 132), 16);
    const highS = { ...g, signature: `0x${g.signature.slice(2, 66)}${(N - s).toString(16).padStart(64, '0')}${(v === 27 ? 28 : 27).toString(16)}` };
    const obj = { ...g, signature: { r: `0x${g.signature.slice(2, 66)}`, s: `0x${g.signature.slice(66, 130)}`, v } };
    const lone = { ...g, payload: { ...g.payload, 'note\uD800': 'x' } };
    const loneLow = { ...g, payload: { ...g.payload, note: 'tx-\uDC00' } };
    const v01 = { ...g, signature: `${g.signature.slice(0, 130)}${(v - 27).toString(16).padStart(2, '0')}` };
    const upper = { ...g, signature: `0x${g.signature.slice(2).toUpperCase()}` };
    for (const [name, doc, why] of [
      ['high-s', highS, /high-s signature rejected/],
      ['object signature', obj, /not an object/],
      ['recovery-id twin v 0/1', v01, /recovery id [01] rejected \(non-canonical\)/],
      ['upper-case hex twin', upper, /signature hex must be lower-case/],
      ['lone surrogate in an unsigned key', lone, /lone UTF-16 surrogate/],
      ['lone LOW surrogate in an unsigned value', loneLow, /lone UTF-16 surrogate/],
    ] as const) {
      const r = run(write(`${name.replace(/\W+/g, '-')}.json`, doc), '--signer', GENESIS_SIGNER);
      expect(r.rc, name).toBe(1);
      expect(r.stderr, name).toMatch(why);
      assertVerdictNotOverstated(r);
    }
    // control: the untouched receipt is a bound VALID
    const ok = run(write('g-control.json', g), '--signer', GENESIS_SIGNER);
    expect(ok.rc).toBe(0);
    assertVerdictNotOverstated(ok);
    // ... and so it is for the same key written in lower case: checksum casing is display only, so
    // a lower-case --signer is BOUND, never a MISMATCH accusing a genuine receipt of tampering
    const lc = run(write('g-control-lc.json', g), '--signer', GENESIS_SIGNER.toLowerCase());
    expect(lc.rc).toBe(0);
    expect(lc.stdout.trim().split('\n').pop()).toBe('VALID');
  });

  it('--help exits 0; an unreachable ledger is an INVALID, not a stack trace', () => {
    expect(run('--help').rc).toBe(0);
    const r = run(write('g.json', GENESIS_RECEIPT), '--ledger', 'http://127.0.0.1:9');
    expect(r.rc).toBe(1);
    expect(r.stderr).toMatch(/^INVALID: could not get an answer from the ledger at http:\/\/127\.0\.0\.1:9/m);
    expect(r.stderr).not.toMatch(STACK);
    expect(r.stdout).not.toMatch(/^VALID/m);
  });
});
