import type { Assure, SettlementContext } from '../assure.js';
import { attachToExtensions, attachToSettlementResponse } from '../assure.js';
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
 * the payment payload request header, the payment-required header and the settlement
 * response header. */

/** x402 HTTP transport headers, v2 names first with v1 fallbacks. Verified 2026-09-29 against
 * x402-foundation/x402 specs/transports-v2/http.md (main 5eee1e3c35): `PAYMENT-REQUIRED`
 * (server → client, PaymentRequired), `PAYMENT-SIGNATURE` (client → server, PaymentPayload),
 * `PAYMENT-RESPONSE` (server → client, SettlementResponse), each base64 over UTF-8 JSON; "All
 * x402 protocol information is communicated through headers". Re-verify at integration
 * (CLAUDE.md rule 1). */
const PAYMENT_PAYLOAD_HEADERS = ['payment-signature', 'x-payment'];
const SETTLEMENT_HEADERS = ['payment-response', 'x-payment-response'];
const PAYMENT_REQUIRED_HEADER = 'payment-required';

export interface SettlementInfo {
  success: boolean;
  transaction?: string | undefined;
  network?: string | undefined;
  payer?: string | undefined;
}

/** base64 → UTF-8 text, as the upstream reference decodes (`safeBase64Decode`), so a record
 * carrying a non-ASCII issuer name or supply description survives the header round trip. Unlike
 * the reference, invalid UTF-8 is refused rather than replaced with U+FFFD: a header this
 * wrapper rewrites must decode exactly, or it is left alone. */
function b64decodeUtf8(value: string): string {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

/** UTF-8 text → base64, as the upstream reference encodes (`safeBase64Encode`). Plain `btoa`
 * throws on any character above U+00FF. */
function b64encodeUtf8(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function b64json(value: string): unknown {
  try {
    return JSON.parse(b64decodeUtf8(value));
  } catch {
    return undefined;
  }
}

/** Encode a JSON value the way an x402 HTTP header carries it (base64 over UTF-8 JSON). */
export function encodeX402Header(value: unknown): string {
  return b64encodeUtf8(JSON.stringify(value));
}

/** Decode an x402 HTTP header value; `undefined` when it is not base64 over UTF-8 JSON. */
export function decodeX402Header(value: string): unknown {
  return b64json(value);
}

export function extractPaymentPayload(headers: Headers): unknown {
  for (const name of PAYMENT_PAYLOAD_HEADERS) {
    const raw = headers.get(name);
    if (raw) return b64json(raw);
  }
  return undefined;
}

function findSettlement(headers: Headers): { name: string; response: Record<string, unknown> } | undefined {
  for (const name of SETTLEMENT_HEADERS) {
    const raw = headers.get(name);
    if (!raw) continue;
    const parsed = b64json(raw);
    if (!isPlainRecord(parsed)) continue;
    return { name, response: parsed };
  }
  return undefined;
}

export function extractSettlement(headers: Headers): SettlementInfo | undefined {
  const found = findSettlement(headers);
  return found ? settlementInfo(found.response) : undefined;
}

function settlementInfo(parsed: Record<string, unknown>): SettlementInfo {
  return {
    success: parsed.success === true,
    transaction: str(parsed.transaction) ?? str(parsed.txHash),
    network: str(parsed.network) ?? str(parsed.networkId),
    payer: str(parsed.payer) ?? str(parsed.from),
  };
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

function isPlainRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** What a 402 advertises under `extensions["compliance-fields"].info`. Each member is a claim
 * about the records this server emits, so set one only when it is true of every record:
 * `tiers: ['minimal']` needs every record to carry each MINIMAL member, including `tax.amount`
 * whenever `tax.scheme` is not `none`. The default advertises the extension with no tier or
 * jurisdiction claim. */
export interface ComplianceAdvertisement {
  tiers?: ReadonlyArray<'minimal' | 'full'>;
  jurisdictions?: ReadonlyArray<string>;
}

/** JSON Schema for the advertised `info` (the core v2 spec makes `schema` a required member of
 * every PaymentRequired extension entry). */
export const COMPLIANCE_FIELDS_ADVERTISEMENT_SCHEMA = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  type: 'object',
  properties: {
    tiers: { type: 'array', items: { type: 'string', enum: ['minimal', 'full'] } },
    jurisdictions: { type: 'array', items: { type: 'string' } },
  },
} as const;

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
  /** Advertise `compliance-fields` in a 402's `PAYMENT-REQUIRED` header (x402 v2). Default: on,
   * with an empty claim set. `false` leaves 402 responses untouched. An entry the handler
   * already put there is kept as it is. */
  advertise?: false | ComplianceAdvertisement;
  /** @deprecated Also decorate a JSON response BODY with the receipt and record (the ≤0.5
   * placement). The `PAYMENT-RESPONSE` header carries them either way. Scheduled for removal in
   * the next minor release after the one that introduced header placement. A body that does not
   * parse as a JSON object is left as it is. */
  legacyBodyPlacement?: boolean;
  /** Called when a settled call's receipt cannot be issued: a settlement network that is neither
   * CAIP-2 nor in the v1 table (`toCaip2Network`), a ledger error, a throwing `toSettlementContext`
   * or `describeSupply`. The paid response then goes out exactly as the handler returned it, with
   * no receipt or record in it. Default: one `console.error` line per failure. An error thrown by
   * this callback, or a rejection of a promise it returns, is ignored. */
  onError?: (err: unknown) => void;
}

type FetchHandler = (req: Request) => Response | Promise<Response>;

function reportIssueError(err: unknown): void {
  let message: string;
  try {
    message = String(err instanceof Error ? err.message : err);
  } catch {
    message = 'unprintable error';
  }
  console.error(`tersign withAssure: receipt not issued, response delivered unchanged: ${message.replace(/\s+/g, ' ')}`);
}

/** The legacy body placement reads a clone, so a body that is not a JSON object stays readable
 * and goes out as it came. */
async function jsonObjectBody(res: Response): Promise<Record<string, unknown> | undefined> {
  try {
    const parsed: unknown = await res.clone().json();
    return isPlainRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function withHeaders(res: Response, headers: Headers, body: BodyInit | null = res.body): Response {
  return new Response(body, { status: res.status, statusText: res.statusText, headers });
}

function advertiseCompliance(res: Response, adv: ComplianceAdvertisement): Response {
  if (res.status !== 402) return res;
  const raw = res.headers.get(PAYMENT_REQUIRED_HEADER);
  if (!raw) return res;
  const required = b64json(raw);
  if (!isPlainRecord(required)) return res;
  const prior = isPlainRecord(required.extensions) ? required.extensions : {};
  if (prior['compliance-fields'] !== undefined) return res;
  const info: Record<string, unknown> = {};
  if (adv.tiers !== undefined) info.tiers = [...adv.tiers];
  if (adv.jurisdictions !== undefined) info.jurisdictions = [...adv.jurisdictions];
  const decorated = {
    ...required,
    extensions: { ...prior, 'compliance-fields': { info, schema: COMPLIANCE_FIELDS_ADVERTISEMENT_SCHEMA } },
  };
  const headers = new Headers(res.headers);
  headers.set(PAYMENT_REQUIRED_HEADER, encodeX402Header(decorated));
  return withHeaders(res, headers);
}

/** Wrap an x402-protected handler: enforce idempotency on the way in; on the way out, advertise
 * `compliance-fields` on a 402, and — when the settlement header reports success — issue the
 * signed receipt + compliance-fields record and merge both into that same settlement header
 * (`PAYMENT-RESPONSE`, or `X-PAYMENT-RESPONSE` for v1), where x402 wallets read them. The
 * response body is left untouched unless `legacyBodyPlacement` is set.
 *
 * Once the settlement header reports success the buyer has paid, so a failure to issue does not
 * throw: the response goes out exactly as the handler returned it, the error goes to `onError`,
 * and with idempotency on the payment id is completed with that delivered response, so a retry
 * replays it instead of finding the id stuck in flight. */
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

    if (cfg.advertise !== false) res = advertiseCompliance(res, cfg.advertise ?? {});

    const found = findSettlement(res.headers);
    const settlement = found ? settlementInfo(found.response) : undefined;
    if (found && settlement?.success) {
      // Paid: nothing from here may cost the buyer the response. On any failure `res` stays the
      // handler's own, and the idempotency entry below is completed with it.
      try {
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
        const headers = new Headers(res.headers);
        headers.set(found.name, encodeX402Header(attachToSettlementResponse(found.response, issued)));
        const body =
          cfg.legacyBodyPlacement && (res.headers.get('content-type') ?? '').includes('application/json')
            ? await jsonObjectBody(res)
            : undefined;
        if (body) {
          headers.delete('content-length');
          res = withHeaders(res, headers, JSON.stringify(attachToExtensions(body, issued)));
        } else {
          res = withHeaders(res, headers);
        }
      } catch (err) {
        try {
          // An async reporter's rejection is caught too: left unhandled it would end the process.
          void Promise.resolve((cfg.onError ?? reportIssueError)(err)).catch(() => {});
        } catch {
          // a throwing reporter must not cost the paid response either
        }
      }
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
