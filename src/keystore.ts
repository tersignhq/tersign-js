import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir, userInfo } from 'node:os';
import { join } from 'node:path';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';

/** Signer-key resolution for the CLI/MCP surfaces (Node-only — never imported by the
 * runtime-agnostic evidence modules). The key is the DEPLOYER's key: it signs records the
 * ledger only counter-signs, so it never leaves this machine — custody stays with the
 * deployer by construction.
 *
 * Priority (first hit wins):
 *   1. TERSIGN_SELLER_KEY env — explicit override; headless/CI/agent contract. Empty counts as
 *      unset; so does an unsubstituted placeholder such as `${TERSIGN_SELLER_KEY}`, but only for a
 *      caller that passes `placeholderAsUnset` (a process an MCP client launches).
 *   2. macOS keychain, service `tersign-signer` — the at-rest default on darwin.
 *   3. keyfile ~/.tersign/signer.key (0600) — portable fallback; created with a warning
 *      recommending the env/keychain paths.
 *
 * All keychain access is execFileSync with an argv array — never shell-interpolated. */

export type SignerKeySource = 'env' | 'keychain' | 'keyfile';

const KEY_PATTERN = /^0x[0-9a-fA-F]{64}$/;
const KEYCHAIN_SERVICE = 'tersign-signer';

// A client config can carry `"TERSIGN_SELLER_KEY": "${TERSIGN_SELLER_KEY}"` for every secret a
// server declares. When that variable is not set where the client runs, a client can pass the
// text through unexpanded, so the server receives the placeholder itself.
// Only a WHOLE value of one of these shapes counts: `${NAME}`, `${NAME:-default}`,
// `${NAME-default}` or `$NAME`.
const PLACEHOLDER_PATTERN = /^\$\{[A-Za-z_][A-Za-z0-9_]*(:?-[^}]*)?\}$|^\$[A-Za-z_][A-Za-z0-9_]*$/;

/** True when an environment value is an unexpanded variable reference rather than a value. */
function isUnexpandedPlaceholder(value: string): boolean {
  return PLACEHOLDER_PATTERN.test(value);
}

/** The placeholder as it may be printed: a `:-default` / `-default` part is elided, since a
 * default can itself be a secret. */
function shownPlaceholder(value: string): string {
  const withDefault = /^\$\{([A-Za-z_][A-Za-z0-9_]*)(:?-)/.exec(value);
  return withDefault ? `\${${withDefault[1]}${withDefault[2]}…}` : value;
}

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
  // Preflight, added 2026-08-30. `security add-generic-password` does not merely FAIL when no
  // login keychain is reachable — it raises a MODAL macOS dialog ("A keychain cannot be found
  // to store …"), which blocks a headless run and ambushes anyone whose first command is
  // `npx tersign`. Seen for real while probing first-run behaviour with a sandboxed HOME; the
  // same shape hits a Mac CI runner, an ssh session with a locked keychain, and any sandbox.
  // `security default-keychain` answers the question silently, so ask it before writing and
  // fall through to the 0600 keyfile when the answer is no.
  try {
    execFileSync('security', ['default-keychain'], { stdio: ['ignore', 'ignore', 'ignore'] });
  } catch {
    return false;
  }
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
 * with the wiring instructions. `env` is where TERSIGN_SELLER_KEY is read (default
 * process.env). With `placeholderAsUnset: true` (passed only where an MCP client launches the
 * process: the MCP server and `tersign intercept`), an unsubstituted placeholder there is treated
 * as unset, and one stderr line says which key was used instead (stderr, never stdout: stdout is
 * the MCP stdio channel). Without it, a placeholder gets the clear error like any malformed key. */
export function resolveSignerKey(
  opts: { create?: boolean; env?: Record<string, string | undefined>; placeholderAsUnset?: boolean } = {},
): ResolvedSignerKey {
  const value = (opts.env ?? process.env).TERSIGN_SELLER_KEY;
  const placeholder =
    opts.placeholderAsUnset === true && value !== undefined && isUnexpandedPlaceholder(value) ? value : undefined;
  if (value !== undefined && value !== '' && placeholder === undefined) {
    if (!KEY_PATTERN.test(value)) throw new Error('TERSIGN_SELLER_KEY must be a 0x-prefixed 32-byte hex key');
    return { key: value as `0x${string}`, source: 'env' };
  }

  const resolved = resolveStoredOrNew(opts.create === true, placeholder);
  if (placeholder !== undefined) {
    const where =
      resolved.generated
        ? `a newly generated key (kept in the ${resolved.source === 'keychain' ? 'OS keychain' : `keyfile ${keyfilePath()}`})`
        : resolved.source === 'keychain'
          ? `the key from the OS keychain (service ${KEYCHAIN_SERVICE})`
          : `the key from the keyfile ${keyfilePath()}`;
    console.error(
      `tersign: TERSIGN_SELLER_KEY held the literal, unsubstituted text ${shownPlaceholder(placeholder)} and was ` +
        `treated as unset; signing with ${where}, address ${privateKeyToAccount(resolved.key).address}.`,
    );
  }
  return { key: resolved.key, source: resolved.source };
}

/** TERSIGN_LEDGER_API_KEY as given, except that an unsubstituted placeholder is treated as unset,
 * with one stderr line, so it is never sent as a credential. Only for processes an MCP client
 * launches (the MCP server and `tersign intercept`); `""` and every other value pass through. */
export function ledgerApiKeyUnlessPlaceholder(value: string | undefined): string | undefined {
  if (value === undefined || !isUnexpandedPlaceholder(value)) return value;
  console.error(
    `tersign: TERSIGN_LEDGER_API_KEY held the literal, unsubstituted text ${shownPlaceholder(value)} and was ` +
      'treated as unset; no API key is sent to the ledger.',
  );
  return undefined;
}

function resolveStoredOrNew(
  create: boolean,
  placeholder: string | undefined,
): ResolvedSignerKey & { generated: boolean } {
  const fromKeychain = readKeychain();
  if (fromKeychain) return { key: fromKeychain as `0x${string}`, source: 'keychain', generated: false };

  const file = keyfilePath();
  if (existsSync(file)) {
    const raw = readFileSync(file, 'utf8').trim();
    if (!KEY_PATTERN.test(raw)) throw new Error(`${file} does not contain a 0x-prefixed 32-byte hex key`);
    return { key: raw as `0x${string}`, source: 'keyfile', generated: false };
  }

  if (!create) {
    throw new Error(
      (placeholder !== undefined
        ? `TERSIGN_SELLER_KEY held the unexpanded placeholder ${shownPlaceholder(placeholder)} and was treated as unset; `
        : '') +
        'no signing key found — set TERSIGN_SELLER_KEY, store one in the macOS keychain ' +
        `(security add-generic-password -s ${KEYCHAIN_SERVICE} -a $USER -w 0x…), or rerun with key creation enabled`,
    );
  }

  const key = generatePrivateKey();
  if (writeKeychain(key)) return { key, source: 'keychain', generated: true };

  mkdirSync(join(homedir(), '.tersign'), { recursive: true, mode: 0o700 });
  writeFileSync(file, `${key}\n`, { mode: 0o600 });
  chmodSync(file, 0o600);
  console.error(
    `tersign: generated a new signing key at ${file} (0600). This key IS your evidence identity — ` +
      'back it up, and prefer TERSIGN_SELLER_KEY or the OS keychain on shared machines.',
  );
  return { key, source: 'keyfile', generated: true };
}
