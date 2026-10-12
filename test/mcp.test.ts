import { afterEach, describe, expect, it, vi } from 'vitest';
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import { Assure } from '../src/assure.js';
import { verifyDispute } from '../src/dispute/sign.js';
import type { SignedDispute } from '../src/dispute/types.js';
import {
  adjudicateDisputeTool,
  getDisputeTool,
  issueReceiptTool,
  openDisputeTool,
  recordDisclosureTool,
  recordRefundTool,
  submitEvidenceTool,
  verifyReceiptTool,
  verifyRecordTool,
} from '../src/mcp/tools.js';
import { LedgerClient } from '../src/ledgerClient.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { buildServer, envDeps, MCP_SERVER_IDENTITY } from '../src/mcp/server.js';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const account = privateKeyToAccount(generatePrivateKey());
const deps = {
  assure: new Assure({ signer: account, issuer: { name: 'T', jurisdiction: 'HK' } }),
  clock: () => 1751856000,
};

describe('MCP tools', () => {
  it('issue_receipt → verify_receipt + verify_compliance_record roundtrip', async () => {
    const issued = await issueReceiptTool(deps, {
      network: 'eip155:8453',
      resourceUrl: 'https://api.example.com/data',
      payer: '0x857b06519E91e3A54538791bDbb0E22373e36b66',
      supplyDescription: 'data call',
    });
    expect((await verifyReceiptTool(issued.receipt, account.address)).valid).toBe(true);
    expect(
      (await verifyRecordTool(issued.compliance.record, issued.compliance.attestation, account.address)).valid,
    ).toBe(true);
  });

  it('buildServer registers without a transport (wiring smoke test)', () => {
    expect(() => buildServer(deps)).not.toThrow();
  });
});

describe('MCP tool descriptions promise only what the ledger does', () => {
  async function descriptions(): Promise<Map<string, string>> {
    const server = buildServer(deps);
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    await server.connect(serverSide);
    const client = new Client({ name: 'probe', version: '0' });
    await client.connect(clientSide);
    const { tools } = await client.listTools();
    await client.close();
    return new Map(tools.map((t) => [t.name, t.description ?? '']));
  }

  it('record_refund: returns exactly the members /v1/refunds answers with, and claims no chain entry', async () => {
    const desc = (await descriptions()).get('record_refund') ?? '';
    // /v1/refunds inserts a pending row with no digest and no chain append, and answers { id, status }.
    const ledgerAnswer = { id: 'f1', status: 'pending' };
    const fetchImpl = (async () => Response.json(ledgerAnswer, { status: 201 })) as unknown as typeof fetch;
    const ledger = new LedgerClient({ url: 'https://ledger.invalid', apiKey: 'k', sellerId: 's', fetchImpl });
    const result = await recordRefundTool({ ...deps, ledger }, ('0x' + 'ab'.repeat(32)) as `0x${string}`, '1.00', 'r');
    const returns = /Returns \{ ([^}]*) \}/.exec(desc)?.[1] ?? '';
    const promised = returns.split(',').map((m) => m.trim().split(':')[0]!.trim());
    expect(promised).toEqual(Object.keys(result));
    expect(desc).toMatch(/PENDING/);
    expect(desc).toMatch(/NOT counter-signed/);
    expect(desc).not.toMatch(/becomes its own counter-signed entry|counter-signature and sequence number/);
  });

  it('adjudicate_dispute: no claim that the rulebook is public; the refund side effect is a pending entry', async () => {
    const desc = (await descriptions()).get('adjudicate_dispute') ?? '';
    expect(desc).not.toMatch(/rulebook is public|recomputable by anyone/i);
    expect(desc).toMatch(/PENDING refund entry/);
  });
});

describe('MCP dispute tools', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('open_dispute posts a valid payer-signed SignedDispute to the public endpoint', async () => {
    let captured: { url: string; init: RequestInit } | undefined;
    vi.stubGlobal('fetch', async (url: string, init: RequestInit) => {
      captured = { url, init };
      return new Response(JSON.stringify({ id: '0xdeadbeef', status: 'open' }), { status: 201 });
    });

    const result = await openDisputeTool(
      { ...deps, signer: account, ledgerHttp: { url: 'https://ledger.example.com/' } },
      { receiptDigest: `0x${'ab'.repeat(32)}`, reason: 'duplicate_charge', claimAmount: '1.25' },
    );
    expect(result).toMatchObject({ status: 'open' });
    expect(captured?.url).toBe('https://ledger.example.com/v1/disputes');
    expect(captured?.init.headers).not.toHaveProperty('authorization'); // public endpoint, no key leak

    const body = JSON.parse(String(captured?.init.body)) as { artifact: SignedDispute };
    const verified = await verifyDispute(body.artifact, account.address);
    expect(verified.valid).toBe(true);
    expect(body.artifact.dispute.openedAt).toBe(1751856000); // injected clock, deterministic
  });

  it('open_dispute refuses to run half-configured', async () => {
    await expect(
      openDisputeTool({ ...deps, signer: account }, { receiptDigest: `0x${'ab'.repeat(32)}`, reason: 'not_delivered', claimAmount: '1' }),
    ).rejects.toThrow('TERSIGN_LEDGER_URL');
  });

  it('MCP handshake identity matches package.json (name + version cannot drift on release)', () => {
    const pkg = JSON.parse(readFileSync(fileURLToPath(new URL('../package.json', import.meta.url)), 'utf8')) as {
      name: string;
      version: string;
      bin: Record<string, string>;
    };
    expect(MCP_SERVER_IDENTITY.name).toBe(pkg.name);
    expect(MCP_SERVER_IDENTITY.version).toBe(pkg.version);
    // npx resolves the package-name-matching bin — the registry listing depends on it existing;
    // the dispatcher defaults to the MCP server so bare `npx tersign` keeps the registry contract
    expect(pkg.bin[pkg.name]).toBe('dist/cli.js');
  });
});

describe('envDeps key resolution', () => {
  const src = readFileSync(fileURLToPath(new URL('../src/mcp/server.ts', import.meta.url)), 'utf8');

  it('an explicit TERSIGN_SELLER_KEY still wins', () => {
    const key = generatePrivateKey();
    const deps = envDeps({ TERSIGN_SELLER_KEY: key });
    expect(deps.signer?.address).toBe(privateKeyToAccount(key).address);
  });

  // Tripwire, not behavioural: exercising the fallback would create a real key in the OS
  // keychain or ~/.tersign on whoever runs the suite. What must never come back is the hard
  // throw — it made `npx tersign` die on first run for anyone without the env var exported,
  // left every directory and sandbox unable to introspect the server, and contradicted
  // record_disclosure's own published promise that the first call self-provisions.
  it('falls back to the shared keystore instead of throwing when the env var is absent', () => {
    expect(src).toContain('resolveSignerKey({ create: true, env: { TERSIGN_SELLER_KEY: sellerKey }, placeholderAsUnset: true })');
    expect(src).not.toContain("throw new Error('TERSIGN_SELLER_KEY");
  });
});

async function listedTools() {
  const server = buildServer(deps);
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await server.connect(serverSide);
  const client = new Client({ name: 'probe', version: '0' });
  await client.connect(clientSide);
  const { tools } = await client.listTools();
  await client.close();
  return tools;
}

describe('MCP tool annotations', () => {
  // Pinned so that a change is deliberate. readOnlyHint: the verify tools and get_dispute only read.
  // destructiveHint false everywhere: no tool deletes or overwrites a record. idempotentHint: a
  // repeated adjudicate_dispute gets 409 and changes nothing; every other writer adds a new entry.
  // openWorldHint: every tool that can reach the ledger; the verify tools are fully offline.
  const PINNED = {
    issue_receipt: { title: 'Issue signed receipt', readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    verify_receipt: { title: 'Verify signed receipt', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    record_disclosure: { title: 'Record counter-signed disclosure', readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    verify_compliance_record: { title: 'Verify compliance record', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    record_refund: { title: 'Record refund', readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    open_dispute: { title: 'Open dispute', readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    submit_dispute_evidence: { title: 'Submit dispute evidence', readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    adjudicate_dispute: { title: 'Adjudicate dispute', readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    get_dispute: { title: 'Get dispute record', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  };

  it('every tool carries exactly the pinned annotations, and its annotation title is its title', async () => {
    const tools = await listedTools();
    expect(Object.fromEntries(tools.map((t) => [t.name, t.annotations]))).toEqual(PINNED);
    for (const t of tools) expect(t.annotations?.title, t.name).toBe(t.title);
  });
});

describe('MCP texts name both places a setting can come from', () => {
  const ROUTE = "the Tersign plugin's settings in Claude Code";

  it('every tool description that names a TERSIGN_ variable also names the plugin settings', async () => {
    const tools = await listedTools();
    const naming = tools.filter((t) => /TERSIGN_/.test(t.description ?? ''));
    expect(naming.map((t) => t.name).sort()).toEqual(['issue_receipt', 'record_refund', 'submit_dispute_evidence']);
    for (const t of naming) expect(t.description, t.name).toContain(ROUTE);
  });

  it('every missing-configuration error names the plugin settings and the variable', async () => {
    const bare = { assure: deps.assure };
    const d = `0x${'ab'.repeat(32)}` as const;
    const cases: [string, Promise<unknown>, string][] = [
      ['record_refund', recordRefundTool(bare, d, '1', 'r'), 'TERSIGN_LEDGER_URL / _API_KEY / _SELLER_ID'],
      ['open_dispute (key)', openDisputeTool(bare, { receiptDigest: d, reason: 'not_delivered', claimAmount: '1' }), 'TERSIGN_SELLER_KEY'],
      ['open_dispute (url)', openDisputeTool({ ...bare, signer: account }, { receiptDigest: d, reason: 'not_delivered', claimAmount: '1' }), 'TERSIGN_LEDGER_URL'],
      ['submit_dispute_evidence (key)', submitEvidenceTool(bare, { disputeDigest: d, role: 'claimant', artifacts: [] }), 'TERSIGN_SELLER_KEY'],
      ['submit_dispute_evidence (url)', submitEvidenceTool({ ...bare, signer: account }, { disputeDigest: d, role: 'claimant', artifacts: [] }), 'TERSIGN_LEDGER_URL'],
      ['adjudicate_dispute', adjudicateDisputeTool(bare, d), 'TERSIGN_LEDGER_URL'],
      ['get_dispute', getDisputeTool(bare, d), 'TERSIGN_LEDGER_URL'],
      ['record_disclosure', recordDisclosureTool(bare, { text: 'x', agentId: 'a' }), 'TERSIGN_SELLER_KEY'],
    ];
    for (const [name, p, variable] of cases) {
      const message = await p.then(
        () => 'resolved',
        (e: unknown) => (e instanceof Error ? e.message : String(e)),
      );
      expect(message, name).toContain(ROUTE);
      expect(message, name).toContain(variable);
    }
  });
});
