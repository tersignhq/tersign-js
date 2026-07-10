import { keccak256, toBytes } from 'viem';

/** Deterministic JSON: recursively key-sorted, no whitespace. Arrays keep order.
 * undefined properties are dropped (matches JSON.stringify semantics). */
export function canonicalStringify(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const v = (value as Record<string, unknown>)[key];
      if (v !== undefined) out[key] = sortValue(v);
    }
    return out;
  }
  return value;
}

export function digestOf(value: unknown): `0x${string}` {
  return keccak256(toBytes(canonicalStringify(value)));
}
