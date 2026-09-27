/** The published-test-key table is DERIVED, not transcribed: every address is re-derived here
 * from its published secret with viem, so a typo fails instead of silently un-flagging a key.
 * The Python twin (sdk-py/tersign/known_keys.py) re-derives its own table with its own
 * secp256k1; where the monorepo carries both, the last test compares them entry by entry. */
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { mnemonicToAccount, privateKeyToAccount } from 'viem/accounts';
import { DEV_MNEMONIC, PUBLISHED_TEST_KEYS, publishedKeyLabel } from '../src/receipt/known-keys.js';

describe('published test keys', () => {
  it('dev-mnemonic accounts #0..#19 re-derive to the table, with their labels', () => {
    for (let i = 0; i < 20; i++) {
      const a = mnemonicToAccount(DEV_MNEMONIC, { addressIndex: i }).address;
      expect(publishedKeyLabel(a), a).toBe(`Hardhat/Anvil default dev mnemonic, account #${i}`);
    }
  });

  it('private keys 1, 2 and 3 re-derive to the table', () => {
    for (const k of [1, 2, 3]) {
      const a = privateKeyToAccount(`0x${k.toString(16).padStart(64, '0')}`).address;
      expect(publishedKeyLabel(a), a).toBe(`private key 0x${k.toString(16)} (a small scalar)`);
    }
    // and only those: the README says so, and a reader should not assume the class is wider
    expect(publishedKeyLabel(privateKeyToAccount(`0x${'4'.padStart(64, '0')}`).address)).toBeUndefined();
  });

  it('denominator is 20 + 3 and nothing else; lookup is case-insensitive and prototype-safe', () => {
    expect(PUBLISHED_TEST_KEYS.size).toBe(23);
    expect(publishedKeyLabel('0xF39FD6E51AAD88F6F4CE6AB8827279CFFFB92266')).toMatch(/account #0/);
    expect(publishedKeyLabel('0x36f82906859E5B0bd076069f8cdfAea355358b14')).toBeUndefined(); // the ledger's genesis key
    for (const v of [undefined, null, 42, 'constructor', '__proto__', 'toString']) expect(publishedKeyLabel(v)).toBeUndefined();
  });

  // Twin parity. Skipped only where the Python table is absent (the published npm mirror, or a
  // checkout that predates it); in the monorepo it runs and any one-sided edit fails here.
  const PY_ROOT = join(import.meta.dirname, '..', '..', 'sdk-py');
  const PY_TABLE = join(PY_ROOT, 'tersign', 'known_keys.py');
  it.skipIf(!existsSync(PY_TABLE))('matches the Python table entry by entry (address AND label)', () => {
    const out = execFileSync(
      'python3',
      ['-c', 'import json,sys; sys.path.insert(0, sys.argv[1]); from tersign.known_keys import PUBLISHED_TEST_KEYS as T; print(json.dumps(T))', PY_ROOT],
      { encoding: 'utf8', timeout: 30_000 },
    );
    const py = new Map(Object.entries(JSON.parse(out) as Record<string, string>));
    expect([...PUBLISHED_TEST_KEYS.entries()].sort()).toEqual([...py.entries()].sort());
  });
});
