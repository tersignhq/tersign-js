/** x402 v1 network names → CAIP-2, for the receipt payload.
 *
 * The offer-receipt extension requires CAIP-2 in the signed payload whatever the protocol version:
 * "Servers MUST convert v1 network identifiers (e.g., "base-sepolia") to CAIP-2 format (e.g.,
 * "eip155:84532") in the receipt payload" (x402-foundation/x402 specs/extensions/
 * extension-offer-and-receipt.md, receipt section; present at main 6b6ee91fee02, read 2026-09-29).
 * A v1 settlement response carries the v1 name (`"base"`), so a receipt built from it without this
 * step signs a payload that fails the spec.
 *
 * The EVM table is upstream `@x402/evm`'s `EVM_NETWORK_CHAIN_ID_MAP`, copied as written
 * (typescript/packages/mechanisms/evm/src/constants.ts, blob ab7db42cc1c0: main 6b6ee91fee02, last
 * changed a9955ae5538e, read 2026-09-29). Those 24 names are the ones upstream's v1 EVM facilitator
 * settles and reports back as `network`, so each can reach a receipt. The offer-receipt reference's
 * own table (typescript/packages/extensions/src/offer-receipt/signing.ts `V1_EVM_NETWORK_CHAIN_IDS`,
 * same commit) holds 17 of them, with the same ids. The Solana table is signing.ts
 * `V1_SOLANA_NETWORKS`, identical to `@x402/svm`'s `V1_TO_V2_NETWORK_MAP`
 * (mechanisms/svm/src/constants.ts, same commit). The rules are signing.ts
 * `convertNetworkStringToCAIP2`'s: a string containing `:` passes through unchanged, a known v1 name
 * is looked up case-insensitively, anything else throws. One difference: the lookup reads own keys
 * only, so an inherited object key such as `constructor` throws instead of resolving. Re-check
 * against both upstream files when a v1 network is added there; test/network.test.ts pins both
 * tables by exact equality.
 *
 * The tables are exported for that test only; the package entry re-exports `toCaip2Network`, not
 * them. */

export const V1_EVM_NETWORK_CHAIN_IDS: Readonly<Record<string, number>> = {
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

export const V1_SOLANA_NETWORKS: Readonly<Record<string, string>> = {
  solana: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
  'solana-devnet': 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1',
  'solana-testnet': 'solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z',
};

/** A CAIP-2 identifier passes through; a known x402 v1 name (`"base"`, `"base-sepolia"`,
 * `"solana"`, …) becomes its CAIP-2 form; anything else throws, because a receipt cannot carry
 * it. */
export function toCaip2Network(network: string): string {
  if (network.includes(':')) return network;
  const key = network.toLowerCase();
  const chainId = Object.hasOwn(V1_EVM_NETWORK_CHAIN_IDS, key) ? V1_EVM_NETWORK_CHAIN_IDS[key] : undefined;
  if (chainId !== undefined) return `eip155:${chainId}`;
  const solana = Object.hasOwn(V1_SOLANA_NETWORKS, key) ? V1_SOLANA_NETWORKS[key] : undefined;
  if (solana !== undefined) return solana;
  throw new Error(
    `Unknown network identifier: "${network}". A receipt needs CAIP-2 (e.g. "eip155:8453") or an x402 v1 name (e.g. "base", "solana").`,
  );
}
