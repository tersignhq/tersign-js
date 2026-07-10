import type { CachedResponse, IdempotencyStore } from './middleware.js';

/** Structural subset of Cloudflare's D1Database — declared locally so the SDK carries no
 * @cloudflare/workers-types dependency; a real D1 binding satisfies it as-is. */
export interface D1Like {
  prepare(query: string): {
    bind(...values: unknown[]): {
      first<T = unknown>(): Promise<T | null>;
      run(): Promise<{ meta?: { changes?: number } }>;
    };
  };
}

/** DDL for the table this store expects. Run once per database (idempotent). */
export const D1_IDEMPOTENCY_DDL = `CREATE TABLE IF NOT EXISTS assure_idempotency (
  scope TEXT NOT NULL,
  key TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  response_json TEXT,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (scope, key)
);`;

/** Durable IdempotencyStore on Cloudflare D1 for sellers running on Workers — the
 * MemoryIdempotencyStore resets on every isolate recycle, which silently re-executes
 * paid work on retry. Reservation atomicity rides on the primary key: INSERT OR IGNORE
 * reports 0 changes when another request holds the id, which maps to `in-flight`. */
export class D1IdempotencyStore implements IdempotencyStore {
  constructor(
    private readonly db: D1Like,
    private readonly table = 'assure_idempotency',
  ) {}

  async get(scope: string, id: string): Promise<{ fingerprint: string; response: CachedResponse | null } | undefined> {
    const row = await this.db
      .prepare(`SELECT fingerprint, response_json FROM ${this.table} WHERE scope = ? AND key = ?`)
      .bind(scope, id)
      .first<{ fingerprint: string; response_json: string | null }>();
    if (!row) return undefined;
    return {
      fingerprint: row.fingerprint,
      response: row.response_json === null ? null : (JSON.parse(row.response_json) as CachedResponse),
    };
  }

  async reserve(scope: string, id: string, fingerprint: string): Promise<boolean> {
    const result = await this.db
      .prepare(
        `INSERT OR IGNORE INTO ${this.table} (scope, key, fingerprint, response_json, created_at) VALUES (?, ?, ?, NULL, ?)`,
      )
      .bind(scope, id, fingerprint, Math.floor(Date.now() / 1000))
      .run();
    return (result.meta?.changes ?? 0) === 1;
  }

  async complete(scope: string, id: string, response: CachedResponse): Promise<void> {
    await this.db
      .prepare(`UPDATE ${this.table} SET response_json = ? WHERE scope = ? AND key = ?`)
      .bind(JSON.stringify(response), scope, id)
      .run();
  }
}
