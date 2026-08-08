import { appendFile, mkdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { SignedActionRecord } from '../evidence/action.js';

/** Non-blocking evidence sink — records queue here and flush sequentially in the
 * background, so evidence I/O never delays the proxied traffic.
 *
 * Ledger mode (apiKey + sellerId configured): POST each signed record to
 * {ledger}/v1/evidence — bearer-key authed, the ledgerClient.ts convention; an HTTP or
 * network failure (each POST capped at 10s) falls back to the local file so no record is
 * dropped. The ledger's /v1/evidence gate only accepts the seller's REGISTERED signing key,
 * so a mismatched signer is warned on the first rejection. Local mode: one
 * JSON line per record appended to <dir>/intercepts-YYYY-MM-DD.jsonl (0600, dir 0700 —
 * the keyfile conventions from keystore.ts). close() drains the queue fully. */

/** default cap on a single ledger POST — a hung request must never wedge close() */
const LEDGER_TIMEOUT_MS = 10_000;

export interface EvidenceSinkOptions {
  /** ledger base URL (used only when apiKey + sellerId are both set) */
  ledgerUrl: string;
  apiKey?: string;
  sellerId?: string;
  /** local sink directory — defaults to ~/.tersign; injectable for tests */
  dir?: string;
  fetchImpl?: typeof fetch;
  now?: () => Date;
  /** per-POST cap in ms before falling back to the local file (default 10s) */
  ledgerTimeoutMs?: number;
  /** diagnostic line sink — defaults to stderr */
  warn?: (line: string) => void;
}

export class EvidenceSink {
  private readonly ledgerUrl: string;
  private readonly dir: string;
  private readonly warn: (line: string) => void;
  private tail: Promise<void> = Promise.resolve();
  private closed = false;

  /** records the ledger accepted */
  ledgerCount = 0;
  /** records written to the local file (including ledger fallbacks) */
  localCount = 0;
  /** records lost to both paths (local append failed) */
  failedCount = 0;
  /** non-ok ledger responses — the first is warned with status + body excerpt, the rest count silently */
  ledgerRejectCount = 0;
  /** the local file, once anything was written there (for the exit summary) */
  localPath: string | null = null;

  constructor(private readonly opts: EvidenceSinkOptions) {
    this.ledgerUrl = opts.ledgerUrl.replace(/\/$/, '');
    this.dir = opts.dir ?? join(homedir(), '.tersign');
    this.warn = opts.warn ?? ((line) => console.error(line));
  }

  /** Queue one signed record. Returns immediately; never throws. */
  push(signed: SignedActionRecord): void {
    if (this.closed) return;
    this.tail = this.tail.then(() => this.write(signed));
  }

  /** Stop accepting and flush everything queued. */
  async close(): Promise<void> {
    this.closed = true;
    await this.tail;
  }

  private async write(signed: SignedActionRecord): Promise<void> {
    if (this.opts.apiKey !== undefined && this.opts.sellerId !== undefined) {
      try {
        const f = this.opts.fetchImpl ?? fetch;
        const signal = AbortSignal.timeout(this.opts.ledgerTimeoutMs ?? LEDGER_TIMEOUT_MS);
        // Raced explicitly against the abort: even a fetch impl that ignores the signal must
        // not wedge close() — the record falls back to the local file instead.
        const res = await Promise.race([
          f(`${this.ledgerUrl}/v1/evidence`, {
            method: 'POST',
            headers: { 'content-type': 'application/json', authorization: `Bearer ${this.opts.apiKey}` },
            body: JSON.stringify({ sellerId: this.opts.sellerId, artifact: signed }),
            signal,
          }),
          new Promise<never>((_, reject) => {
            signal.addEventListener('abort', () => reject(new Error('ledger request timed out')), { once: true });
          }),
        ]);
        // Always consume the body — an unread body pins the connection in undici's pool.
        const body = await res.text().catch(() => '');
        if (res.ok) {
          this.ledgerCount += 1;
          return;
        }
        this.ledgerRejectCount += 1;
        if (this.ledgerRejectCount === 1) {
          const excerpt = body.replace(/\s+/g, ' ').trim().slice(0, 160);
          this.warn(
            `tersign intercept: ledger rejected the record (HTTP ${res.status}${excerpt !== '' ? ` — ${excerpt}` : ''}); ` +
              'writing to the local file instead. Hosted mode requires your registered signer key — ' +
              'set TERSIGN_SELLER_KEY to the key registered for this sellerId.',
          );
        }
      } catch {
        // network failure or timeout — fall through to the local file
      }
    }
    try {
      await this.appendLocal(signed);
      this.localCount += 1;
    } catch {
      this.failedCount += 1;
    }
  }

  private async appendLocal(signed: SignedActionRecord): Promise<void> {
    if (this.localPath === null) {
      await mkdir(this.dir, { recursive: true, mode: 0o700 });
      const day = (this.opts.now ?? (() => new Date()))().toISOString().slice(0, 10);
      this.localPath = join(this.dir, `intercepts-${day}.jsonl`);
    }
    await appendFile(this.localPath, `${JSON.stringify(signed)}\n`, { mode: 0o600 });
  }
}
