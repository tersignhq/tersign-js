import type { Assure, SettlementContext } from '../assure.js';
import { attachToExtensions } from '../assure.js';
import {
  checkIdempotency,
  extractPaymentId,
  fingerprint,
  REPLAY_HEADER,
  type IdempotencyStore,
} from '../idempotency/middleware.js';

/** Adapter for x402-protected fetch-style handlers ((Request) => Response) — this is the
 * shape of a Hono app (`app.fetch`), a Workers export, and Next.js route handlers, so one
 * wrapper covers the common seller stacks. An adapter pinned to the official x402 SDK's
 * middleware internals is deliberately deferred until we integrate against a pinned
 * version (its surface is still churning); this wrapper only touches the WIRE contract:
 * the payment payload request header and the settlement response header. */

/** x402 v2 header names, with v1 fallbacks. Re-verify at integration (CLAUDE.md rule 1). */
const PAYMENT_PAYLOAD_HEADERS = ['payment-signature', 'x-payment'];
const SETTLEMENT_HEADERS = ['payment-response', 'x-payment-response'];

export interface SettlementInfo {
  success: boolean;
  transaction?: string | undefined;
  network?: string | undefined;
  payer?: string | undefined;
}

function b64json(value: string): unknown {
  try {
    return JSON.parse(atob(value));
  } catch {
    return undefined;
  }
}

export function extractPaymentPayload(headers: Headers): unknown {
  for (const name of PAYMENT_PAYLOAD_HEADERS) {
    const raw = headers.get(name);
    if (raw) return b64json(raw);
  }
  return undefined;
}

export function extractSettlement(headers: Headers): SettlementInfo | undefined {
  for (const name of SETTLEMENT_HEADERS) {
    const raw = headers.get(name);
    if (!raw) continue;
    const parsed = b64json(raw) as Record<string, unknown> | undefined;
    if (!parsed || typeof parsed !== 'object') continue;
    return {
      success: parsed.success === true,
      transaction: str(parsed.transaction) ?? str(parsed.txHash),
      network: str(parsed.network) ?? str(parsed.networkId),
      payer: str(parsed.payer) ?? str(parsed.from),
    };
  }
  return undefined;
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

export interface WithAssureConfig {
  assure: Assure;
  /** describe the supply for the receipt; defaults to the request path */
  describeSupply?: (req: Request) => string;
  /** override receipt fields derived from the settlement header */
  toSettlementContext?: (req: Request, info: SettlementInfo) => Partial<SettlementContext>;
  clock?: () => number;
  idempotency?: {
    store: IdempotencyStore;
    required: boolean;
    scope: string;
  };
}

type FetchHandler = (req: Request) => Response | Promise<Response>;

/** Wrap an x402-protected handler: enforce idempotency on the way in, issue the signed
 * receipt + compliance record on the way out (only when the settlement header reports
 * success and the response body is JSON). */
export function withAssure(handler: FetchHandler, cfg: WithAssureConfig): FetchHandler {
  const now = cfg.clock ?? (() => Math.floor(Date.now() / 1000));
  return async (req: Request): Promise<Response> => {
    let onComplete: ((r: { status: number; headers: Record<string, string>; body: string }) => Promise<void>) | undefined;

    if (cfg.idempotency) {
      const id = extractPaymentId(extractPaymentPayload(req.headers));
      const url = new URL(req.url);
      const fp = fingerprint({ method: req.method, path: url.pathname });
      const outcome = await checkIdempotency(cfg.idempotency, id, fp);
      switch (outcome.kind) {
        case 'missing':
          return Response.json({ error: 'payment-identifier id required' }, { status: 400 });
        case 'conflict':
          return Response.json({ error: 'payment id reused with a different request' }, { status: 409 });
        case 'in-flight':
          return Response.json({ error: 'request with this payment id is in flight' }, { status: 409 });
        case 'replay': {
          const headers = new Headers(outcome.response.headers);
          headers.set(REPLAY_HEADER, 'true');
          return new Response(outcome.response.body, { status: outcome.response.status, headers });
        }
        case 'process':
          onComplete = outcome.onComplete;
      }
    }

    let res = await handler(req);

    const settlement = extractSettlement(res.headers);
    if (settlement?.success && (res.headers.get('content-type') ?? '').includes('application/json')) {
      const url = new URL(req.url);
      const overrides = cfg.toSettlementContext?.(req, settlement) ?? {};
      const ctx: SettlementContext = {
        network: settlement.network ?? 'eip155:8453',
        resourceUrl: url.origin + url.pathname,
        payer: settlement.payer ?? 'unknown',
        settledAt: now(),
        supplyDescription: cfg.describeSupply?.(req) ?? url.pathname,
        ...(settlement.transaction !== undefined ? { txHash: settlement.transaction } : {}),
        ...overrides,
      };
      const issued = await cfg.assure.issueFor(ctx);
      const body = (await res.json()) as Record<string, unknown>;
      const decorated = attachToExtensions(body, issued);
      const headers = new Headers(res.headers);
      headers.delete('content-length');
      res = new Response(JSON.stringify(decorated), { status: res.status, headers });
    }

    if (onComplete) {
      const body = await res.clone().text();
      const headerRecord: Record<string, string> = {};
      res.headers.forEach((v, k) => (headerRecord[k] = v));
      await onComplete({ status: res.status, headers: headerRecord, body });
    }
    return res;
  };
}
