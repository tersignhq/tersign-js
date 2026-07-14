import { keccak256, toBytes } from 'viem';

/** Deterministic JSON — RFC 8785 (JCS) conformant for JSON-domain inputs: keys sorted by
 * UTF-16 code units, no whitespace, JSON.stringify scalar/escape semantics. Arrays keep
 * order; undefined properties are dropped (matches JSON.stringify semantics).
 *
 * The string is built directly, never via an object rebuild: JS engines hoist integer-like
 * keys ("1","2","10") into numeric order on insertion, which silently defeats a
 * sort-then-stringify round-trip (JCS orders them "1","10","2"). Byte-identical to the old
 * serializer for every shape without integer-like or control-char keys — the genesis receipt
 * digest and all pinned wire vectors are unchanged. */
export function canonicalStringify(value: unknown): string {
  return serialize(value) as string;
}

function serialize(value: unknown): string | undefined {
  if (value === null) return 'null';
  if (Array.isArray(value)) {
    return '[' + Array.from(value, (v) => serialize(v) ?? 'null').join(',') + ']';
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const parts: string[] = [];
    for (const key of Object.keys(obj).sort()) {
      const s = serialize(obj[key]);
      if (s !== undefined) parts.push(JSON.stringify(key) + ':' + s);
    }
    return '{' + parts.join(',') + '}';
  }
  // string/number/boolean serialize per JCS; undefined/function/symbol yield undefined (dropped)
  return JSON.stringify(value);
}

export function digestOf(value: unknown): `0x${string}` {
  return keccak256(toBytes(canonicalStringify(value)));
}
