#!/usr/bin/env node
/** tersign disclose — one-call counter-signed disclosure evidence.
 *
 *   tersign disclose "<text>" [--medium chat] [--agent-id my-agent] [--kind ai-interaction]
 *                    [--url <resourceUrl>] [--ledger https://tersign.ai]
 *
 * The text is digested LOCALLY (keccak256 over its canonical JSON form) — only the digest
 * travels. Key resolution: TERSIGN_SELLER_KEY env → macOS keychain (tersign-signer) →
 * ~/.tersign/signer.key; a key is created on first use. */
import { privateKeyToAccount } from 'viem/accounts';
import { recordDisclosure } from './evidence/disclose.js';
import { resolveSignerKey } from './keystore.js';

function arg(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i > 0 ? process.argv[i + 1] : undefined;
}

const text = process.argv[2];
if (text === undefined || text.startsWith('--')) {
  console.error(
    'usage: tersign disclose "<disclosure text>" [--medium chat] [--agent-id id] ' +
      '[--kind ai-interaction|synthetic-content] [--url resourceUrl] [--ledger url]',
  );
  process.exit(2);
}

const kind = arg('--kind') ?? 'ai-interaction';
if (kind !== 'ai-interaction' && kind !== 'synthetic-content') {
  console.error(`--kind must be ai-interaction or synthetic-content (got '${kind}')`);
  process.exit(2);
}

try {
  const { key, source } = resolveSignerKey({ create: true });
  const account = privateKeyToAccount(key);
  console.error(`signing key: ${account.address} (${source})`);

  const result = await recordDisclosure({
    text,
    kind,
    agentId: arg('--agent-id') ?? 'cli',
    ...(arg('--medium') !== undefined ? { medium: arg('--medium') as string } : {}),
    ...(arg('--url') !== undefined ? { resourceUrl: arg('--url') as string } : {}),
    ...(arg('--ledger') !== undefined ? { ledger: arg('--ledger') as string } : {}),
    account,
  });

  console.log(`digest           ${result.digest}`);
  console.log(`seq              ${result.seq}`);
  console.log(`countersignature ${result.countersignature.slice(0, 24)}…`);
  console.log(`tier             ${result.tier}`);
  console.log(`verify           ${result.verifyUrl}`);
} catch (e) {
  console.error(e instanceof Error ? e.message : String(e));
  process.exit(1);
}
