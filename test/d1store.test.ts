import { describe, expect, it } from 'vitest';
import { D1IdempotencyStore, type D1Like } from '../src/idempotency/d1.js';
import { checkIdempotency, fingerprint } from '../src/idempotency/middleware.js';

/** In-memory D1Like that emulates the three SQL statements the store issues, including
 * INSERT OR IGNORE change-count semantics (the reservation atomicity contract). */
function fakeD1(): D1Like {
  const rows = new Map<string, { fingerprint: string; response_json: string | null }>();
  return {
    prepare(query: string) {
      return {
        bind(...values: unknown[]) {
          return {
            async first<T>() {
              const [scope, key] = values as [string, string];
              const row = rows.get(`${scope} ${key}`);
              return (row ? { fingerprint: row.fingerprint, response_json: row.response_json } : null) as T | null;
            },
            async run() {
              if (query.startsWith('INSERT OR IGNORE')) {
                const [scope, key, fp] = values as [string, string, string];
                const k = `${scope} ${key}`;
                if (rows.has(k)) return { meta: { changes: 0 } };
                rows.set(k, { fingerprint: fp, response_json: null });
                return { meta: { changes: 1 } };
              }
              // UPDATE ... SET response_json = ? WHERE scope = ? AND key = ?
              const [json, scope, key] = values as [string, string, string];
              const row = rows.get(`${scope} ${key}`);
              if (row) row.response_json = json;
              return { meta: { changes: row ? 1 : 0 } };
            },
          };
        },
      };
    },
  };
}

const fp = fingerprint({ method: 'POST', path: '/premium' });
const opts = (store: D1IdempotencyStore) => ({ store, required: true, scope: 'seller-1 POST /premium' });

describe('D1IdempotencyStore behavior table', () => {
  it('new id → process; completed → replay with identical response', async () => {
    const store = new D1IdempotencyStore(fakeD1());
    const first = await checkIdempotency(opts(store), 'id_0000000000000001', fp);
    expect(first.kind).toBe('process');
    if (first.kind !== 'process') return;
    await first.onComplete({ status: 200, headers: { 'content-type': 'application/json' }, body: '{"n":1}' });

    const second = await checkIdempotency(opts(store), 'id_0000000000000001', fp);
    expect(second.kind).toBe('replay');
    if (second.kind !== 'replay') return;
    expect(second.response.body).toBe('{"n":1}');
    expect(second.response.headers['content-type']).toBe('application/json');
  });

  it('same id + different fingerprint → conflict', async () => {
    const store = new D1IdempotencyStore(fakeD1());
    const first = await checkIdempotency(opts(store), 'id_0000000000000002', fp);
    if (first.kind === 'process') await first.onComplete({ status: 200, headers: {}, body: 'x' });
    const other = fingerprint({ method: 'POST', path: '/premium', amount: '999' });
    expect((await checkIdempotency(opts(store), 'id_0000000000000002', other)).kind).toBe('conflict');
  });

  it('reserved but uncompleted → in-flight (both via get and via lost reservation race)', async () => {
    const store = new D1IdempotencyStore(fakeD1());
    const first = await checkIdempotency(opts(store), 'id_0000000000000003', fp);
    expect(first.kind).toBe('process'); // reserved, not completed
    expect((await checkIdempotency(opts(store), 'id_0000000000000003', fp)).kind).toBe('in-flight');
  });

  it('scopes isolate sellers — same id in another scope processes fresh', async () => {
    const store = new D1IdempotencyStore(fakeD1());
    const a = await checkIdempotency(opts(store), 'id_0000000000000004', fp);
    if (a.kind === 'process') await a.onComplete({ status: 200, headers: {}, body: 'a' });
    const b = await checkIdempotency({ store, required: true, scope: 'seller-2 POST /premium' }, 'id_0000000000000004', fp);
    expect(b.kind).toBe('process');
  });
});
