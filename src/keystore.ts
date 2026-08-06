import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir, userInfo } from 'node:os';
import { join } from 'node:path';
import { generatePrivateKey } from 'viem/accounts';

/** Signer-key resolution for the CLI/MCP surfaces (Node-only — never imported by the
 * runtime-agnostic evidence modules). The key is the DEPLOYER's key: it signs records the
 * ledger only counter-signs, so it never leaves this machine — custody stays with the
 * deployer by construction.
 *
 * Priority (first hit wins):
 *   1. TERSIGN_SELLER_KEY env — explicit override; headless/CI/agent contract.
 *   2. macOS keychain, service `tersign-signer` — the at-rest default on darwin.
 *   3. keyfile ~/.tersign/signer.key (0600) — portable fallback; created with a warning
 *      recommending the env/keychain paths.
 *
 * All keychain access is execFileSync with an argv array — never shell-interpolated. */

export type SignerKeySource = 'env' | 'keychain' | 'keyfile';

const KEY_PATTERN = /^0x[0-9a-fA-F]{64}$/;
const KEYCHAIN_SERVICE = 'tersign-signer';

function keyfilePath(): string {
  return join(homedir(), '.tersign', 'signer.key');
}

function readKeychain(): string | null {
  if (process.platform !== 'darwin') return null;
  try {
    const out = execFileSync('security', ['find-generic-password', '-s', KEYCHAIN_SERVICE, '-w'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    return KEY_PATTERN.test(out) ? out : null;
  } catch {
    return null;
  }
}

function writeKeychain(key: string): boolean {
  if (process.platform !== 'darwin') return false;
  try {
    execFileSync(
      'security',
      ['add-generic-password', '-s', KEYCHAIN_SERVICE, '-a', userInfo().username, '-w', key, '-U'],
      { stdio: ['ignore', 'ignore', 'ignore'] },
    );
    return true;
  } catch {
    return false;
  }
}

export interface ResolvedSignerKey {
  key: `0x${string}`;
  source: SignerKeySource;
}

/** Resolve the deployer signing key. With `create: true`, a missing key is generated and
 * persisted (keychain on darwin, else a 0600 keyfile); without it, resolution failure throws
 * with the wiring instructions. */
export function resolveSignerKey(opts: { create?: boolean } = {}): ResolvedSignerKey {
  const env = process.env.TERSIGN_SELLER_KEY;
  if (env !== undefined && env !== '') {
    if (!KEY_PATTERN.test(env)) throw new Error('TERSIGN_SELLER_KEY must be a 0x-prefixed 32-byte hex key');
    return { key: env as `0x${string}`, source: 'env' };
  }

  const fromKeychain = readKeychain();
  if (fromKeychain) return { key: fromKeychain as `0x${string}`, source: 'keychain' };

  const file = keyfilePath();
  if (existsSync(file)) {
    const raw = readFileSync(file, 'utf8').trim();
    if (!KEY_PATTERN.test(raw)) throw new Error(`${file} does not contain a 0x-prefixed 32-byte hex key`);
    return { key: raw as `0x${string}`, source: 'keyfile' };
  }

  if (!opts.create) {
    throw new Error(
      'no signing key found — set TERSIGN_SELLER_KEY, store one in the macOS keychain ' +
        `(security add-generic-password -s ${KEYCHAIN_SERVICE} -a $USER -w 0x…), or rerun with key creation enabled`,
    );
  }

  const key = generatePrivateKey();
  if (writeKeychain(key)) return { key, source: 'keychain' };

  mkdirSync(join(homedir(), '.tersign'), { recursive: true, mode: 0o700 });
  writeFileSync(file, `${key}\n`, { mode: 0o600 });
  chmodSync(file, 0o600);
  console.error(
    `tersign: generated a new signing key at ${file} (0600). This key IS your evidence identity — ` +
      'back it up, and prefer TERSIGN_SELLER_KEY or the OS keychain on shared machines.',
  );
  return { key, source: 'keyfile' };
}
