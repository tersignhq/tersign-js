import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { privateKeyToAccount } from 'viem/accounts';
import { resolveSignerKey } from '../src/keystore.js';
import { envDeps } from '../src/mcp/server.js';

/** Hermetic: HOME is a temp directory for every test, and `security` (the macOS keychain CLI) is
 * replaced in process by a fake whose only stored entry is `keychain.stored`; it refuses every
 * write, so a generated key always lands in the temp keyfile. A stub `security` that exits 1 also
 * leads PATH, in case anything reaches the real command another way. */

const keychain = vi.hoisted(() => ({ stored: null as string | null, calls: [] as string[][] }));

vi.mock('node:child_process', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:child_process')>();
  return {
    ...real,
    execFileSync: ((file: string, ...rest: unknown[]) => {
      if (file === 'security') {
        const args = (rest[0] ?? []) as string[];
        keychain.calls.push(args);
        if (args[0] === 'find-generic-password' && keychain.stored !== null) return `${keychain.stored}\n`;
        throw new Error('fake security: no keychain in keystore.test.ts');
      }
      return (real.execFileSync as (...a: unknown[]) => unknown)(file, ...rest);
    }) as typeof real.execFileSync,
  };
});

const VALID = `0x${'a'.repeat(64)}`;
const KEYFILE_KEY = `0x${'b'.repeat(64)}`;
const KEYCHAIN_KEY = `0x${'c'.repeat(64)}`;
const address = (key: string) => privateKeyToAccount(key as `0x${string}`).address;
const CLEAR_ERROR = 'TERSIGN_SELLER_KEY must be a 0x-prefixed 32-byte hex key';
const WARNING = 'held the literal, unsubstituted text';

const PLACEHOLDERS = [
  '${TERSIGN_SELLER_KEY}',
  '${TERSIGN_SELLER_KEY:-}',
  '${TERSIGN_SELLER_KEY-}',
  '${TERSIGN_SELLER_KEY:-fallback}',
  '$TERSIGN_SELLER_KEY',
  '${_x9}',
];

let work = '';
let saved: { key: string | undefined; home: string | undefined; path: string | undefined };
let errors: string[];

const keyfile = () => join(work, 'home', '.tersign', 'signer.key');
function storeKeyfile(key: string) {
  mkdirSync(join(work, 'home', '.tersign'), { recursive: true });
  writeFileSync(keyfile(), `${key}\n`, { mode: 0o600 });
}
const placeholderWarnings = () => errors.filter((l) => l.includes(WARNING));

beforeEach(() => {
  saved = { key: process.env.TERSIGN_SELLER_KEY, home: process.env.HOME, path: process.env.PATH };
  work = mkdtempSync(join(tmpdir(), 'tersign-keystore-'));
  mkdirSync(join(work, 'home'));
  mkdirSync(join(work, 'shim'));
  writeFileSync(join(work, 'shim', 'security'), '#!/bin/sh\nexit 1\n');
  chmodSync(join(work, 'shim', 'security'), 0o755);
  process.env.HOME = join(work, 'home');
  process.env.PATH = [join(work, 'shim'), saved.path ?? ''].join(delimiter);
  delete process.env.TERSIGN_SELLER_KEY;
  keychain.stored = null;
  keychain.calls = [];
  errors = [];
  vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => {
    errors.push(a.map(String).join(' '));
  });
});
afterEach(() => {
  vi.restoreAllMocks();
  for (const [name, value] of [
    ['TERSIGN_SELLER_KEY', saved.key],
    ['HOME', saved.home],
    ['PATH', saved.path],
  ] as const) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  rmSync(work, { recursive: true, force: true });
});

describe('resolveSignerKey — env priority', () => {
  it('env wins over every other source and reports source env', () => {
    process.env.TERSIGN_SELLER_KEY = VALID;
    const r = resolveSignerKey();
    expect(r).toEqual({ key: VALID, source: 'env' });
  });

  it('rejects a malformed env key instead of falling through to weaker sources', () => {
    process.env.TERSIGN_SELLER_KEY = 'not-a-key';
    expect(() => resolveSignerKey()).toThrow(/TERSIGN_SELLER_KEY/);
  });

  it('a valid hex key in env still wins over the keychain and the keyfile, and nothing is printed', () => {
    keychain.stored = KEYCHAIN_KEY;
    storeKeyfile(KEYFILE_KEY);
    process.env.TERSIGN_SELLER_KEY = VALID;
    expect(resolveSignerKey({ create: true })).toEqual({ key: VALID, source: 'env' });
    expect(keychain.calls).toEqual([]);
    expect(errors).toEqual([]);
  });

  it('with placeholderAsUnset, still throws the clear error for a bare $, an empty ${}, a non-hex 0x value, a 31-byte key and partial or prefixed placeholders', () => {
    // A keyfile is stored, so a value wrongly treated as unset would resolve instead of throwing.
    // Each anchor of the placeholder pattern has a value here that only that anchor rejects:
    // 'x${…}' and 'x${…:-}' (first alternative's ^), '${…}x' (its $), 'x$NAME' (second
    // alternative's ^) and '$NAME.bak' (its $).
    storeKeyfile(KEYFILE_KEY);
    for (const value of [
      '$',
      '${}',
      `0x${'g'.repeat(64)}`,
      `0x${'a'.repeat(62)}`,
      'x${TERSIGN_SELLER_KEY}',
      'x${TERSIGN_SELLER_KEY:-}',
      '${TERSIGN_SELLER_KEY}x',
      '${TERSIGN_SELLER_KEY',
      'x$TERSIGN_SELLER_KEY',
      '$TERSIGN_SELLER_KEY.bak',
      '$1KEY',
    ]) {
      process.env.TERSIGN_SELLER_KEY = value;
      expect(() => resolveSignerKey({ create: true, placeholderAsUnset: true }), value).toThrow(CLEAR_ERROR);
    }
    expect(errors).toEqual([]);
  });

  it('without placeholderAsUnset (every entry point but the MCP server and intercept), a placeholder throws the clear error as in 0.6.2', () => {
    // A keyfile is stored, so a placeholder wrongly treated as unset would resolve instead.
    storeKeyfile(KEYFILE_KEY);
    for (const value of PLACEHOLDERS) {
      process.env.TERSIGN_SELLER_KEY = value;
      expect(() => resolveSignerKey({ create: true }), value).toThrow(CLEAR_ERROR);
      expect(() => resolveSignerKey({ create: true, env: { TERSIGN_SELLER_KEY: value } }), value).toThrow(CLEAR_ERROR);
    }
    expect(errors).toEqual([]);
  });

  it('reads TERSIGN_SELLER_KEY from opts.env when one is given, not from process.env', () => {
    storeKeyfile(KEYFILE_KEY);
    expect(resolveSignerKey({ env: { TERSIGN_SELLER_KEY: VALID } })).toEqual({ key: VALID, source: 'env' });
    process.env.TERSIGN_SELLER_KEY = VALID;
    expect(resolveSignerKey({ env: { TERSIGN_SELLER_KEY: '${TERSIGN_SELLER_KEY}' }, placeholderAsUnset: true })).toEqual({
      key: KEYFILE_KEY,
      source: 'keyfile',
    });
  });
});

describe('resolveSignerKey — with placeholderAsUnset, an unsubstituted placeholder counts as unset', () => {
  const unset = { placeholderAsUnset: true } as const;

  it('treats each placeholder form as unset, resolves the keyfile key, and says so in one stderr line', () => {
    storeKeyfile(KEYFILE_KEY);
    for (const value of PLACEHOLDERS) {
      errors = [];
      process.env.TERSIGN_SELLER_KEY = value;
      expect(resolveSignerKey(unset), value).toEqual({ key: KEYFILE_KEY, source: 'keyfile' });
      expect(errors, value).toHaveLength(1);
      const line = errors[0]!;
      expect(line).not.toContain('\n');
      expect(line).toContain(`TERSIGN_SELLER_KEY ${WARNING} `);
      expect(line).toContain('and was treated as unset');
      // It states what was observed, never a cause.
      expect(line).not.toContain('MCP client');
      expect(line).toContain(`the key from the keyfile ${keyfile()}`);
      expect(line).toContain(address(KEYFILE_KEY));
    }
  });

  it('with nothing stored and create on, generates a key and the warning names it newly generated', () => {
    process.env.TERSIGN_SELLER_KEY = '${TERSIGN_SELLER_KEY}';
    const r = resolveSignerKey({ create: true, ...unset });
    expect(r.source).toBe('keyfile');
    expect(existsSync(keyfile())).toBe(true);
    expect(readFileSync(keyfile(), 'utf8').trim()).toBe(r.key);
    const warnings = placeholderWarnings();
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain('${TERSIGN_SELLER_KEY}');
    expect(warnings[0]).toContain(`a newly generated key (kept in the keyfile ${keyfile()})`);
    expect(warnings[0]).toContain(address(r.key));
  });

  it.runIf(process.platform === 'darwin')('falls through to the OS keychain when it holds a key', () => {
    keychain.stored = KEYCHAIN_KEY;
    storeKeyfile(KEYFILE_KEY);
    process.env.TERSIGN_SELLER_KEY = '${TERSIGN_SELLER_KEY}';
    expect(resolveSignerKey(unset)).toEqual({ key: KEYCHAIN_KEY, source: 'keychain' });
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain('the key from the OS keychain');
    expect(errors[0]).toContain(address(KEYCHAIN_KEY));
  });

  it('with nothing stored and create off, throws the no-key error and names the placeholder', () => {
    process.env.TERSIGN_SELLER_KEY = '${TERSIGN_SELLER_KEY}';
    expect(() => resolveSignerKey(unset)).toThrow(
      'TERSIGN_SELLER_KEY held the unexpanded placeholder ${TERSIGN_SELLER_KEY} and was treated as unset; no signing key found',
    );
    expect(existsSync(keyfile())).toBe(false);
  });

  it('never prints a placeholder default, since a default can itself be a key', () => {
    storeKeyfile(KEYFILE_KEY);
    process.env.TERSIGN_SELLER_KEY = `\${TERSIGN_SELLER_KEY:-0x${'d'.repeat(64)}}`;
    expect(resolveSignerKey(unset)).toEqual({ key: KEYFILE_KEY, source: 'keyfile' });
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain('${TERSIGN_SELLER_KEY:-…}');
    expect(errors[0]).not.toContain('dddd');
  });
});

describe('envDeps — the MCP entry point resolves its key through the keystore', () => {
  const LEDGER_URL = 'http://127.0.0.1:9';

  it('a malformed TERSIGN_SELLER_KEY gets the keystore clear error, not a crypto-library error', () => {
    storeKeyfile(KEYFILE_KEY);
    // '0X…' (uppercase prefix) reached privateKeyToAccount in 0.6.2 and was accepted there.
    for (const value of ['not-a-key', `0x${'a'.repeat(62)}`, `0X${'a'.repeat(64)}`]) {
      expect(() => envDeps({ TERSIGN_SELLER_KEY: value }), value).toThrow(CLEAR_ERROR);
    }
  });

  it('a placeholder TERSIGN_SELLER_KEY signs with the stored key, even when process.env holds a key', () => {
    storeKeyfile(KEYFILE_KEY);
    const deps = envDeps({ TERSIGN_SELLER_KEY: '${TERSIGN_SELLER_KEY}' });
    expect(deps.signer?.address).toBe(address(KEYFILE_KEY));
    expect(placeholderWarnings()).toHaveLength(1);
    // The placeholder is a non-empty value, so it is the key read; the placeholder rule then
    // sends resolution to the keystore, not to process.env.
    process.env.TERSIGN_SELLER_KEY = VALID;
    expect(envDeps({ TERSIGN_SELLER_KEY: '${TERSIGN_SELLER_KEY}' }).signer?.address).toBe(address(KEYFILE_KEY));
  });

  it('a custom env without TERSIGN_SELLER_KEY, or with "", uses the key in process.env (0.6.2 precedence)', () => {
    // A keyfile is stored, so dropping the process.env fallback would sign with it instead.
    storeKeyfile(KEYFILE_KEY);
    process.env.TERSIGN_SELLER_KEY = VALID;
    expect(envDeps({ TERSIGN_LEDGER_URL: LEDGER_URL }).signer?.address).toBe(address(VALID));
    expect(envDeps({ TERSIGN_SELLER_KEY: '' }).signer?.address).toBe(address(VALID));
    expect(errors).toEqual([]);
  });

  it("a custom env's own TERSIGN_SELLER_KEY wins over process.env's", () => {
    process.env.TERSIGN_SELLER_KEY = VALID;
    expect(envDeps({ TERSIGN_SELLER_KEY: KEYCHAIN_KEY }).signer?.address).toBe(address(KEYCHAIN_KEY));
  });

  it('envDeps() with no argument reads process.env, placeholder rule included', () => {
    storeKeyfile(KEYFILE_KEY);
    process.env.TERSIGN_SELLER_KEY = VALID;
    expect(envDeps().signer?.address).toBe(address(VALID));
    process.env.TERSIGN_SELLER_KEY = '$TERSIGN_SELLER_KEY';
    expect(envDeps().signer?.address).toBe(address(KEYFILE_KEY));
    expect(placeholderWarnings()).toHaveLength(1);
  });

  it('a placeholder TERSIGN_LEDGER_API_KEY is treated as unset, with one stderr line naming it', () => {
    const deps = envDeps({
      TERSIGN_SELLER_KEY: VALID,
      TERSIGN_LEDGER_URL: LEDGER_URL,
      TERSIGN_LEDGER_API_KEY: '${TERSIGN_LEDGER_API_KEY}',
      TERSIGN_LEDGER_SELLER_ID: 's',
    });
    expect(deps.ledger).toBeUndefined();
    expect(deps.ledgerHttp).toEqual({ url: LEDGER_URL });
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain(`TERSIGN_LEDGER_API_KEY ${WARNING} \${TERSIGN_LEDGER_API_KEY} and was treated as unset`);
    expect(errors[0]).toContain('no API key is sent');
    expect(errors[0]).not.toContain('MCP client');
  });

  it('a real ledger API key is still used, with nothing printed (the control)', () => {
    const deps = envDeps({
      TERSIGN_SELLER_KEY: VALID,
      TERSIGN_LEDGER_URL: LEDGER_URL,
      TERSIGN_LEDGER_API_KEY: 'k',
      TERSIGN_LEDGER_SELLER_ID: 's',
    });
    expect(deps.ledger).toBeDefined();
    expect(deps.ledgerHttp).toEqual({ url: LEDGER_URL, apiKey: 'k' });
    expect(errors).toEqual([]);
  });

  it('an EMPTY TERSIGN_LEDGER_API_KEY keeps its meaning: no ledger client, "" passed through to ledgerHttp', () => {
    const deps = envDeps({
      TERSIGN_SELLER_KEY: VALID,
      TERSIGN_LEDGER_URL: LEDGER_URL,
      TERSIGN_LEDGER_API_KEY: '',
      TERSIGN_LEDGER_SELLER_ID: 's',
    });
    expect(deps.ledger).toBeUndefined();
    expect(deps.ledgerHttp).toEqual({ url: LEDGER_URL, apiKey: '' });
    expect(errors).toEqual([]);
  });
});
