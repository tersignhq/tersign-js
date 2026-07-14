import { describe, expect, it } from 'vitest';
import { canonicalStringify, digestOf } from '../src/canonical.js';

describe('canonical (cross-impl contract with @tersign/ledger)', () => {
  it('sorts keys recursively and is key-order invariant', () => {
    expect(canonicalStringify({ b: 'x', a: 1 })).toBe('{"a":1,"b":"x"}');
    expect(digestOf({ b: 'x', a: 1 })).toBe(digestOf({ a: 1, b: 'x' }));
  });
  it('matches the pinned cross-implementation vector (ledger pins the same)', () => {
    expect(digestOf({ b: 'x', a: 1 })).toBe('0x84fc3d9faf736ddfdb9baab9973656bd8d9bd142f1dfff8aa513a774fddfdd04');
  });
  it('drops undefined and function properties like JSON.stringify', () => {
    expect(canonicalStringify({ a: 1, u: undefined, f: () => 1 })).toBe('{"a":1}');
  });
  it('orders integer-like keys by UTF-16 code units, not numerically (RFC 8785)', () => {
    // JS engines hoist integer-like keys into numeric order on object rebuild — the class
    // of divergence this vector exists to catch. JCS order: "1" < "10" < "2".
    expect(canonicalStringify({ '10': 'a', '2': 'b', '1': 'c' })).toBe('{"1":"c","10":"a","2":"b"}');
    expect(digestOf({ '10': 'a', '2': 'b', '1': 'c' })).toBe('0x426b770f81b8ad5e307bcfb767deb02f8d32cd340d81a946be88bb184857e81b');
  });
  it('orders control-char keys before digits (RFC 8785)', () => {
    expect(canonicalStringify({ '1': 'One', '\r': 'CR' })).toBe('{"\\r":"CR","1":"One"}');
  });
});
