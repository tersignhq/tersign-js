# tersign

**The evidence layer for the agent economy.** When software buys from software, someone has to keep the records straight — this SDK gives agent-commerce sellers counter-signed receipts, tamper-evident action records, and jury-ready evidence envelopes on top of x402 settlement.

```sh
npm install tersign
```

## What it does

- **Signed receipts** — implements the merged x402 `offer-receipt` extension (EIP-712), plus **compliance records** (tax/audit-grade fields: EU Art-226b minimal tier / EN 16931 full tier / HK IRO s.51C retention) bound to the base receipt by digest.
- **Agent action records** — `ActionRecordV1`: digest-bound, GDPR-minimized evidence of agent actions and disclosures, mapped to EU AI Act Art-50 obligations.
- **Idempotency enforcement** — the x402 `payment-identifier` extension ships the key; this ships the semantics (replay cache, `Idempotent-Replayed`, 409 in-flight/conflict) with pluggable stores (memory, Cloudflare D1).
- **Refund orchestration** — corrective records hash-chained via `refundOf` (ViDA-style), ACP/UCP adjustment vocabulary verbatim.
- **Disputes** — signed dispute/evidence/acceptance-criteria artifacts with objective reason codes; deterministic triage upstream of any arbitration venue.
- **Evidence envelopes** — package any counter-signed record into a jury-ready submission for external venues (Internet Court slot format, Kleros ERC-1497, UMA claims): digests + a public verify URL, never raw evidence, with party statements structurally segregated from ledger-attested content.
- **Ledger client** — counter-signature + sequential hash-chaining + evidence-pack exports via the hosted Tersign ledger (optional; the SDK works standalone).
- **MCP server** — `npx tersign-mcp` exposes the full loop (issue / verify / refund / dispute) as Model Context Protocol tools for agent frameworks.
- **Third-party verification** — `npx tersign verify <receipt.json | 0xdigest>` recovers signatures and checks the public chain with no account and no trust in Tersign. (Installed: `tersign-verify` works directly.)

## Quick start

```ts
import { privateKeyToAccount } from 'viem/accounts';
import { Assure, attachToExtensions } from 'tersign';

const assure = new Assure({
  signer: privateKeyToAccount(process.env.SELLER_KEY as `0x${string}`),
  issuer: { name: 'Example API Ltd', jurisdiction: 'HK', taxId: 'BR-12345678' },
  // ledger: { url: 'https://tersign-ledger.kevinn-zhang.workers.dev', apiKey: '…', sellerId: '…' },
});

// after your x402 middleware reports settlement:
const issued = await assure.issueFor({
  network: 'eip155:8453',
  resourceUrl: 'https://api.example.com/data',
  payer: settlement.payer,
  settledAt: Math.floor(Date.now() / 1000),
  txHash: settlement.transaction,
  supplyDescription: 'Market data, per call',
});
return Response.json(attachToExtensions(body, issued));
```

## Why not just the official x402 SDK?

The official extension gives you the receipt *format*. This gives you the *operation*: replay enforcement (x402 #452 punts it to the app layer), refund records, compliance-grade fields your accountant recognizes, dispute-ready evidence — and third-party verifiability via counter-signed hash chains, so your receipts are exhibits, not testimony.

## Verify without trusting anyone

Every counter-signed record is publicly checkable: [live ledger + verification](https://tersign-ledger.kevinn-zhang.workers.dev/verify) — no account, no API key. Venues rotate; the transcript endures.

## Status

v0.1 — EIP-712 receipts, MINIMAL-tier compliance records, action records, disputes v0, evidence envelopes (Internet Court / Kleros / UMA), memory + D1 idempotency stores, MCP server, verify CLI. Wire formats are digest-bound and schema-evolvable; cross-implementation vectors are pinned in CI. MIT.
