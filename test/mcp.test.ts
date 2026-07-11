import { afterEach, describe, expect, it, vi } from 'vitest';
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import { Assure } from '../src/assure.js';
import { verifyDispute } from '../src/dispute/sign.js';
import type { SignedDispute } from '../src/dispute/types.js';
import { issueReceiptTool, openDisputeTool, verifyReceiptTool, verifyRecordTool } from '../src/mcp/tools.js';
import { buildServer, MCP_SERVER_IDENTITY } from '../src/mcp/server.js';
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
