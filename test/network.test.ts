import { describe, expect, it } from 'vitest';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { Assure } from '../src/assure.js';
import { toCaip2Network, V1_EVM_NETWORK_CHAIN_IDS, V1_SOLANA_NETWORKS } from '../src/receipt/network.js';
import { verifyReceipt } from '../src/receipt/eip712.js';

/** The receipt payload carries CAIP-2 whatever the x402 version (offer-receipt extension, receipt
 * section: "Servers MUST convert v1 network identifiers … to CAIP-2"). Expected values are copied
 * from upstream, not derived from ours. */

/** x402-foundation/x402 typescript/packages/mechanisms/evm/src/constants.ts
 * `EVM_NETWORK_CHAIN_ID_MAP`, blob ab7db42cc1c0 (main 6b6ee91fee02 and its last change a9955ae5538e,
 * read 2026-09-29). These are the v1 names upstream's v1 EVM facilitator settles and reports back as
 * `network` (mechanisms/evm/src/exact/v1/facilitator/scheme.ts), so each one can reach a receipt. */
const UPSTREAM_V1_EVM: Record<string, number> = {
  ethereum: 1,
  sepolia: 11155111,
  abstract: 2741,
  'abstract-testnet': 11124,
  'base-sepolia': 84532,
  base: 8453,
  'avalanche-fuji': 43113,
  avalanche: 43114,
  iotex: 4689,
  sei: 1329,
  'sei-testnet': 1328,
  polygon: 137,
  'polygon-amoy': 80002,
  peaq: 3338,
  story: 1514,
  educhain: 41923,
  'skale-base-sepolia': 324705682,
  megaeth: 4326,
  monad: 143,
  'monad-testnet': 10143,
  stable: 988,
  'stable-testnet': 2201,
  celo: 42220,
  flare: 14,
};

/** x402-foundation/x402 typescript/packages/mechanisms/svm/src/constants.ts `V1_TO_V2_NETWORK_MAP`
 * and offer-receipt/signing.ts `V1_SOLANA_NETWORKS` (identical; main 6b6ee91fee02, read 2026-09-29). */
const UPSTREAM_V1_SOLANA: Record<string, string> = {
  solana: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
  'solana-devnet': 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1',
  'solana-testnet': 'solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z',
};

describe('the v1 network tables equal upstream exactly', () => {
  it('EVM: the same 24 names with the same chain ids, nothing added or missing', () => {
    expect(Object.keys(UPSTREAM_V1_EVM)).toHaveLength(24);
    expect({ ...V1_EVM_NETWORK_CHAIN_IDS }).toStrictEqual(UPSTREAM_V1_EVM);
  });

  it('Solana: the same 3 names with the same CAIP-2 ids, nothing added or missing', () => {
    expect({ ...V1_SOLANA_NETWORKS }).toStrictEqual(UPSTREAM_V1_SOLANA);
  });

  it('every upstream name converts, as written and upper-cased', () => {
    for (const [name, id] of Object.entries(UPSTREAM_V1_EVM)) {
      expect(toCaip2Network(name), name).toBe(`eip155:${id}`);
      expect(toCaip2Network(name.toUpperCase()), name.toUpperCase()).toBe(`eip155:${id}`);
    }
    for (const [name, caip2] of Object.entries(UPSTREAM_V1_SOLANA)) {
      expect(toCaip2Network(name), name).toBe(caip2);
      expect(toCaip2Network(name.toUpperCase()), name.toUpperCase()).toBe(caip2);
    }
  });
});

describe('toCaip2Network', () => {
  it('passes a CAIP-2 identifier through unchanged', () => {
    expect(toCaip2Network('eip155:8453')).toBe('eip155:8453');
    expect(toCaip2Network('solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp')).toBe('solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp');
  });

  it('converts x402 v1 EVM names, case-insensitively', () => {
    expect(toCaip2Network('base')).toBe('eip155:8453');
    expect(toCaip2Network('base-sepolia')).toBe('eip155:84532');
    expect(toCaip2Network('BASE')).toBe('eip155:8453');
    expect(toCaip2Network('ethereum')).toBe('eip155:1');
    expect(toCaip2Network('polygon-amoy')).toBe('eip155:80002');
    expect(toCaip2Network('skale-base-sepolia')).toBe('eip155:324705682');
  });

  it('converts x402 v1 Solana names', () => {
    expect(toCaip2Network('solana')).toBe('solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp');
    expect(toCaip2Network('solana-devnet')).toBe('solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1');
  });

  it('converts x402 v1 Solana names case-insensitively', () => {
    expect(toCaip2Network('SOLANA')).toBe('solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp');
    expect(toCaip2Network('Solana-Devnet')).toBe('solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1');
    expect(toCaip2Network('SOLANA-TESTNET')).toBe('solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z');
  });

  it('throws on a name it cannot convert, including inherited object keys', () => {
    expect(() => toCaip2Network('base-mainnet')).toThrow(/Unknown network identifier/);
    expect(() => toCaip2Network('')).toThrow(/Unknown network identifier/);
    expect(() => toCaip2Network('constructor')).toThrow(/Unknown network identifier/);
    expect(() => toCaip2Network('toString')).toThrow(/Unknown network identifier/);
  });
});

describe('Assure.issueFor signs the network as CAIP-2', () => {
  const account = privateKeyToAccount(generatePrivateKey());
  const assure = new Assure({ signer: account, issuer: { name: 'T', jurisdiction: 'HK' } });
  const ctx = {
    resourceUrl: 'https://api.example.com/v1/data',
    payer: '0x857b06519E91e3A54538791bDbb0E22373e36b66',
    settledAt: 1751856000,
    supplyDescription: 'data',
  };

  it('a v1 name becomes CAIP-2 in the signed payload, and the receipt verifies', async () => {
    const { receipt } = await assure.issueFor({ ...ctx, network: 'base-sepolia' });
    expect('payload' in receipt && receipt.payload.network).toBe('eip155:84532');
    expect((await verifyReceipt(receipt, account.address)).valid).toBe(true);
  });

  it('an unknown name is refused rather than signed', async () => {
    await expect(assure.issueFor({ ...ctx, network: 'not-a-network' })).rejects.toThrow(/Unknown network identifier/);
  });
});
