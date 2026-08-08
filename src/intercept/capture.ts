import type { Account } from 'viem/accounts';
import { digestOf } from '../canonical.js';
import { signActionRecord, type ActionRecordV1, type SignedActionRecord } from '../evidence/action.js';
import { tryParseFrame } from './frames.js';

/** Direction-aware JSON-RPC pairing → signed, digest-only ActionRecordV1 evidence.
 *
 * JSON-RPC ids are independent per direction in MCP v1 — client→server requests and
 * server→client requests (sampling, elicitation) coexist, so the same id can be in flight
 * both ways at once. Pending requests key on (request direction, id); a response observed
 * in direction D answers the request that travelled in the OPPOSITE direction.
 *
 * The prototype captures client→server requests only, and notifications (no id) are not
 * captured. DIGESTS ONLY: a record carries digestOf(arguments) and digestOf(result ?? error),
 * never the content itself — the data-minimized posture of evidence/action.ts. */

export type Direction = 'client' | 'server';

export const DEFAULT_EVENTS: readonly string[] = ['tools/call'];

/** pending-map ceiling — cancelled-and-lost or never-answered requests must not grow memory
 * forever; on overflow the oldest entry is evicted (counted, warned once via onError) */
const MAX_PENDING = 4096;

export interface McpCaptureOptions {
  /** agent identity stamped on every record */
  agentId: string;
  /** deployer signing account (keystore-resolved on the CLI path) */
  account: Account;
  /** captured client→server request methods; '*' captures every method */
  events?: readonly string[];
  clock?: () => number;
  /** receives each signed record — wire this to the sink */
  onRecord: (signed: SignedActionRecord) => void;
  /** signing failures land here; the observer never throws into the proxy path */
  onError?: (err: unknown) => void;
}

interface PendingRequest {
  /** JSON-RPC method — kept so the migration to per-event interceptor hooks (SEP-2624)
   * can shape records per method without re-parsing the stream */
  method: string;
  toolName?: string;
  inputDigest: `0x${string}`;
  at: number;
}

export class McpCapture {
  private readonly events: ReadonlySet<string>;
  private readonly clock: () => number;
  private readonly pending = new Map<string, PendingRequest>();
  private tail: Promise<void> = Promise.resolve();
  private stopped = false;
  private emitted = 0;
  private evicted = 0;
  private collided = 0;

  constructor(private readonly opts: McpCaptureOptions) {
    this.events = new Set(opts.events ?? DEFAULT_EVENTS);
    this.clock = opts.clock ?? (() => Math.floor(Date.now() / 1000));
  }

  /** signed records emitted so far (for the exit summary) */
  get recordCount(): number {
    return this.emitted;
  }

  /** pending entries evicted at the MAX_PENDING cap — each is a request that can no longer pair */
  get evictedCount(): number {
    return this.evicted;
  }

  /** same-direction id collisions — each dropped a stale pending request without emitting */
  get collisionCount(): number {
    return this.collided;
  }

  /** Observe one complete frame (a COPY — the proxied bytes are already on their way). */
  onFrame(direction: Direction, line: Buffer): void {
    if (this.stopped) return;
    const msg = tryParseFrame(line);
    if (msg === undefined || msg === null || typeof msg !== 'object' || Array.isArray(msg)) return;
    const frame = msg as { id?: unknown; method?: unknown; params?: unknown; result?: unknown; error?: unknown };

    // MCP cancellation: the request this direction sent will not be answered — drop its
    // pending entry so cancelled calls cannot accumulate forever.
    if (frame.method === 'notifications/cancelled') {
      const params =
        typeof frame.params === 'object' && frame.params !== null && !Array.isArray(frame.params)
          ? (frame.params as { requestId?: unknown })
          : {};
      const requestId = params.requestId;
      if (typeof requestId === 'string' || typeof requestId === 'number') {
        this.pending.delete(pendingKey(direction, requestId));
      }
      return;
    }

    const id = frame.id;
    if (typeof id !== 'string' && typeof id !== 'number') return; // notifications / null-id errors

    if (typeof frame.method === 'string') {
      if (direction !== 'client') return; // prototype: client→server requests only
      if (!this.events.has('*') && !this.events.has(frame.method)) return;
      const params =
        typeof frame.params === 'object' && frame.params !== null && !Array.isArray(frame.params)
          ? (frame.params as { name?: unknown; arguments?: unknown })
          : {};
      const key = pendingKey('client', id);
      if (this.pending.has(key)) {
        // Same-direction id reuse while the first request is still pending (a JSON-RPC
        // violation): the stale entry can no longer be paired truthfully — drop it WITHOUT
        // emitting a record (never fabricate a pairing). The delete keeps insertion order
        // honest for cap eviction.
        this.pending.delete(key);
        this.collided += 1;
        this.opts.onError?.(
          new Error(`duplicate in-flight JSON-RPC id ${String(id)} (client) — dropped the stale pending request without emitting a record`),
        );
      } else if (this.pending.size >= MAX_PENDING) {
        const oldest = this.pending.keys().next().value;
        if (oldest !== undefined) this.pending.delete(oldest);
        this.evicted += 1;
        if (this.evicted === 1) {
          this.opts.onError?.(
            new Error(`pending-request map hit its ${MAX_PENDING}-entry cap — evicting oldest unanswered requests (counted, warned once)`),
          );
        }
      }
      this.pending.set(key, {
        method: frame.method,
        ...(typeof params.name === 'string' ? { toolName: params.name } : {}),
        inputDigest: digestOf(params.arguments ?? null),
        at: this.clock(),
      });
      return;
    }

    if (!('result' in frame) && !('error' in frame)) return;
    // A response in direction D answers the request that travelled the opposite way.
    const key = pendingKey(direction === 'server' ? 'client' : 'server', id);
    const entry = this.pending.get(key);
    if (entry === undefined) return;
    this.pending.delete(key);
    // JSON-RPC error responses still produce a record — the digest covers the error object.
    const outputDigest = digestOf(frame.result ?? frame.error ?? null);
    this.tail = this.tail
      .then(async () => {
        const record: ActionRecordV1 = {
          version: 1,
          agent: { id: this.opts.agentId },
          action: {
            kind: 'tool-call',
            ...(entry.toolName !== undefined ? { name: entry.toolName } : {}),
            inputDigest: entry.inputDigest,
            outputDigest,
          },
          occurredAt: entry.at,
        };
        const signed = await signActionRecord(record, this.opts.account);
        this.emitted += 1;
        this.opts.onRecord(signed);
      })
      .catch((err) => this.opts.onError?.(err));
  }

  /** Stop observing new frames (shutdown began); already-queued signings still complete. */
  stop(): void {
    this.stopped = true;
  }

  /** Resolves once every queued record has been signed and delivered to onRecord. */
  async settle(): Promise<void> {
    await this.tail;
  }
}

/** ids are string-or-number and independent per direction — 1 and '1' must not collide. */
function pendingKey(direction: Direction, id: string | number): string {
  return `${direction}:${typeof id}:${String(id)}`;
}
