import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { resolveSignerKey } from '../src/keystore.js';

/** Hermetic slice only: the env path sits ABOVE keychain/keyfile in the priority order, so
 * these tests never touch the host keychain or filesystem (CI has neither). */

const VALID = `0x${'a'.repeat(64)}`;
let saved: string | undefined;

beforeEach(() => {
  saved = process.env.TERSIGN_SELLER_KEY;
});
afterEach(() => {
  if (saved === undefined) delete process.env.TERSIGN_SELLER_KEY;
  else process.env.TERSIGN_SELLER_KEY = saved;
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
});
