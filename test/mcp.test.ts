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
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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
  // destructiveHint true only for adjudicate_dispute, which closes the dispute to evidence; no tool
  // deletes a record. idempotentHint: a
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
    adjudicate_dispute: { title: 'Run dispute triage', readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
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

// Triage is not adjudication (Terms section 12: a Triage Result is data, not an adjudication,
// award or judgment). The tool keeps its wire name, adjudicate_dispute, because clients call it by
// that name; every text a client or a directory reviewer reads says what the ledger route does:
// fixed rules (R1 duplicate charge from the ledger's own receipts, R2 the seller's silence through
// the evidence window), anything else escalated, a recorded result that moves no money. The texts
// are pinned whole so a change to them is deliberate; the word scan covers every tool, its title
// and every input description, so a new tool or a new parameter cannot bring the words back.
describe('MCP texts describe dispute triage as triage, and no tool as moving money', () => {
  type Listed = Awaited<ReturnType<typeof listedTools>>[number];

  function inputDescriptions(node: unknown): string[] {
    if (Array.isArray(node)) return node.flatMap(inputDescriptions);
    if (node === null || typeof node !== 'object') return [];
    return Object.entries(node as Record<string, unknown>).flatMap(([k, v]) =>
      k === 'description' && typeof v === 'string' ? [v] : inputDescriptions(v),
    );
  }

  const texts = (t: Listed): string[] => [t.title ?? '', t.annotations?.title ?? '', t.description ?? '', ...inputDescriptions(t.inputSchema)];

  // What may contain the word: the wire identifiers that cannot change (the tool name, the
  // response field that carries the rule inputs, the status value, each only in the form the texts
  // quote it) and the one disclaimer the texts must make. Everything else is scanned.
  const ALLOWED = [/\badjudicate_dispute\b/g, /\badjudicationInputs\b/g, /"adjudicated"/g, /\bnot an adjudication\b/g];
  const prose = (s: string) => ALLOWED.reduce((acc, re) => acc.replace(re, ''), s);

  // `verdict` is a wire field (the dispute response's triage result; the verify tools' one-line
  // summary). It may appear only where a tool quotes that field, each form once per text and only
  // in the tool that returns it; prose that calls a triage result a verdict fails.
  const VERDICT_WIRE: Record<string, string[]> = {
    verify_receipt: ['{ verdict, valid', 'Read verdict first'],
    verify_compliance_record: ['{ verdict, valid', 'Read verdict first'],
    adjudicate_dispute: ['verdict: "refund" | "uphold" | null', 'verdictDigest'],
    get_dispute: ['verdict: refund, uphold, or null when escalated'],
  };
  const withoutVerdictWire = (tool: string, s: string) => (VERDICT_WIRE[tool] ?? []).reduce((acc, form) => acc.replace(form, ''), s);
  // The one disclaimer that may name an award.
  const AWARD_DISCLAIMER = 'not an adjudication, award or legal conclusion';

  it('no tool text calls our triage an adjudication, an arbiter, a judgment or a ruling', async () => {
    const tools = await listedTools();
    expect(tools.length).toBe(9);
    let scanned = 0;
    for (const t of tools) {
      for (const s of texts(t)) {
        scanned++;
        expect(prose(s), `${t.name}: ${s}`).not.toMatch(/adjudicat/i);
        expect(prose(s), `${t.name}: ${s}`).not.toMatch(/\barbit(?:er|ers|rat\w*)\b|\bjudg\w*|\brulings?\b/i);
        expect(s.replace(AWARD_DISCLAIMER, ''), `${t.name}: ${s}`).not.toMatch(/\barbitra\w*|\baward\w*|\btribunal\w*/i);
        expect(withoutVerdictWire(t.name, s), `${t.name}: ${s}`).not.toMatch(/\bverdicts?\b/i);
      }
    }
    // Not an empty net: titles, descriptions and the input descriptions of all nine tools.
    expect(scanned).toBeGreaterThan(40);
  });

  // The JSDoc ships in the package's .d.ts, which editors show as hover text. Built fresh from src
  // (sdk/dist may be stale or absent; CI tests before it builds), every .d.ts is read whole, with the
  // comment markers stripped so a phrase broken across JSDoc lines reads as one sentence, then the
  // wire names (the same ALLOWED forms, plus the status type's 'adjudicated', a backticked
  // `adjudicated` and the function adjudicateDisputeTool, which follows the wire route) are removed.
  it('no declaration or JSDoc in the shipped .d.ts calls triage an adjudication', () => {
    const out = mkdtempSync(join(tmpdir(), 'tersign-dts-'));
    try {
      const sdk = fileURLToPath(new URL('..', import.meta.url));
      const tsc = createRequire(import.meta.url).resolve('typescript/bin/tsc');
      execFileSync(process.execPath, [tsc, '-p', join(sdk, 'tsconfig.build.json'), '--outDir', out, '--emitDeclarationOnly'], {
        cwd: sdk,
        stdio: 'pipe',
        timeout: 180_000,
      });
      const files = (readdirSync(out, { recursive: true }) as string[]).filter((f) => f.endsWith('.d.ts'));
      expect(files.length).toBeGreaterThan(20);
      const DTS_ALLOWED = [...ALLOWED, /'adjudicated'/g, /`adjudicated`/g, /\badjudicateDisputeTool\b/g];
      let reached = 0;
      for (const f of files) {
        const flat = readFileSync(join(out, f), 'utf8')
          .replace(/\n\s*(?:\*(?!\/)|\/\/)\s?/g, ' ')
          .replace(/\s+/g, ' ');
        if (/adjudicateDisputeTool|'adjudicated'/.test(flat)) reached++;
        expect(DTS_ALLOWED.reduce((acc, re) => acc.replace(re, ''), flat), f).not.toMatch(/adjudicat/i);
      }
      // Not an empty net: the dispute types and the MCP tool declarations were both read.
      expect(reached).toBeGreaterThanOrEqual(2);
    } finally {
      rmSync(out, { recursive: true, force: true });
    }
  }, 200_000);

  it('adjudicate_dispute and the dispute tools carry exactly the pinned texts', async () => {
    const byName = new Map((await listedTools()).map((t) => [t.name, t]));
    const adjudicate = byName.get('adjudicate_dispute');
    expect(adjudicate?.title).toBe('Run dispute triage');
    expect(adjudicate?.description).toBe(
      'Run deterministic triage on an open dispute and record the result. Triage applies fixed rules, stated here, to the dispute record: ' +
        'R1 (duplicate_charge) looks up the receipts the ledger counter-signed for the same seller, payer and settlement transaction hash, reading the hash only in 0x-prefixed 64-hex-digit form and the payer only in 0x-prefixed 40-hex-digit form (either letter case), and lists at most 16 of those receipts, the earliest ones and the disputed one (on a settlement of more than 16 the rationale says "more than 16 receipts" and which are listed, and adjudicationInputs carries sameSettlementTruncated: true), and classifies the disputed receipt refund when an earlier one shares that hash and uphold otherwise; ' +
        'R2 (not_delivered, wrong_content) classifies the claim refund when the seller filed no evidence before the evidence deadline; ' +
        'anything else, including a duplicate_charge receipt without a settlement transaction hash or a payer in those forms, is marked escalated with no result, for an external venue the parties choose. ' +
        'R1 reads receipts from one seller to one payer that share one settlement transaction as one payment. ' +
        "The rules never read the content, kind or note of any evidence, or the claimant's statement; no discretion and no model are involved, and the same inputs always produce the same result and rationale. " +
        'The result is a triage classification recorded as data: it is not an adjudication, award or legal conclusion, it decides no legal claim, and it binds no one unless the parties separately agree. ' +
        'Side effects: writes the result to the dispute record, signed by the ledger; a refund result also logs a PENDING refund entry against the receipt for the claimed amount (not counter-signed into the chain; no payment is checked and no money moves). ' +
        'Runs once: the first successful call closes the dispute to evidence, and every later call returns 409. ' +
        'This tool sends no API key, so a not_delivered or wrong_content dispute can be triaged only after its evidence deadline (before it the ledger answers 409 or 401); a duplicate_charge dispute can be triaged at any time. ' +
        'Returns { id, status: "adjudicated" (the wire name for a dispute a rule classified) | "escalated", verdict: "refund" | "uphold" | null (the triage result), rationale (names the rule applied), adjudicationInputs (the exact inputs the rules ran on), verdictDigest, ledgerSignature, ledgerSigner, decidedAt }.',
    );
    expect(inputDescriptions(adjudicate?.inputSchema)).toEqual(['0x-prefixed digest of the open dispute to triage, as returned by open_dispute']);

    expect(byName.get('open_dispute')?.description).toBe(
      'Open an objective dispute against a counter-signed receipt as the PAYER (the configured key must be the receipt payer). Reasons: not_delivered, wrong_content, duplicate_charge. ' +
        'Recording only: the ledger records your signed claim and opens an evidence window; it moves no money. ' +
        "The ledger opens a dispute only with room reserved in its dispute capacity for the claim, its triage and each party's first evidence item, the same on every plan; while that capacity is full it opens none (HTTP 503). " +
        "adjudicate_dispute later runs deterministic triage on it, which classifies a duplicate_charge from the ledger's own receipts only when the disputed receipt carries a settlement transaction hash in 0x-prefixed 64-hex-digit form (either letter case), and escalates it otherwise; classifies an unanswered claim from the seller's silence; and marks anything else escalated, for an external venue the parties choose. " +
        "Triage's duplicate_charge rule, R1, reads receipts from one seller to one payer that share one settlement transaction as one payment.",
    );
    expect(inputDescriptions(byName.get('open_dispute')?.inputSchema)).toEqual([
      '0x-prefixed keccak256 digest of the counter-signed receipt being disputed',
      "grounds: 'not_delivered' nothing arrived · 'wrong_content' delivered but not what was bought · 'duplicate_charge' the same supply was billed twice (classified by triage from the ledger's own receipts only when the disputed receipt carries a settlement transaction hash in 0x-prefixed 64-hex-digit form (either letter case), and escalated otherwise; no party evidence is read; R1, the rule that classifies it, reads receipts from one seller to one payer that share one settlement transaction as one payment)",
      'amount claimed back, as a decimal STRING in the receipt\'s settlement currency, e.g. "12.50". The ledger records it as stated and checks it against no payment; a refund triage result logs this amount as a pending refund entry',
      'for humans reading the record — never an input to the triage rules',
    ]);

    expect(byName.get('submit_dispute_evidence')?.description).toBe(
      "Submit signed evidence to an open dispute before its evidence deadline. Claimant evidence must be signed by the payer key; respondent evidence additionally requires the seller API key (the Tersign plugin's settings in Claude Code, or the TERSIGN_* environment variables). " +
        'Each artifact is sent as its digest and kind, plus its time and note when given; its content never leaves your side. Triage (adjudicate_dispute) uses only whether each side filed, never the content, kind or note of what was filed; the evidence stays on the record for the parties and any external venue. It moves no money. ' +
        "Each party's first item on a dispute always fits the room reserved for it when the dispute opened; a later item is refused (HTTP 503) while the ledger's dispute capacity is full.",
    );
    expect(inputDescriptions(byName.get('submit_dispute_evidence')?.inputSchema)).toEqual(
      expect.arrayContaining([
        'what this artifact is; recorded for the parties and any external venue — the triage rules do not read it',
        'short human-readable label for whoever reads the record; never an input to the triage rules',
        'at least one evidence reference; submit every artifact you want on the record in a single call',
      ]),
    );

    expect(byName.get('get_dispute')?.description).toBe(
      "Fetch a dispute in full: its status, claim and evidence deadline, both sides' signed evidence references, and, once triage has run, the triage result (verdict: refund, uphold, or null when escalated), its rationale, the inputs the rules ran on, and the ledger signature over the result. " +
        'Read-only — one network read, no key required, and safe to poll while a dispute is open.',
    );
  });

  it('every tool that touches money says it records and moves none', async () => {
    const byName = new Map((await listedTools()).map((t) => [t.name, t.description ?? '']));
    expect(byName.get('issue_receipt')).toContain('Recording only: it moves no money and executes no payment.');
    // The ledger refuses no receipt for sharing a settlement with others (ledger fix round 7, HQ ruling 1): no per-settlement limit.
    expect(byName.get('issue_receipt')).not.toMatch(/settlement transaction hash|HTTP 409|17th/);
    expect(byName.get('record_refund')).toContain('This RECORDS a refund you have already made: it moves no money and executes no payment or refund.');
    expect(byName.get('open_dispute')).toContain('Recording only: the ledger records your signed claim and opens an evidence window; it moves no money.');
    expect(byName.get('adjudicate_dispute')).toContain('no payment is checked and no money moves');
    expect(byName.get('submit_dispute_evidence')).toContain('It moves no money.');
    expect(byName.get('record_disclosure')).toContain('It moves no money.');
  });

  it('the README and llms.txt (both ship in the package and the mirror) say the same', () => {
    for (const file of ['../README.md', '../llms.txt']) {
      const text = readFileSync(fileURLToPath(new URL(file, import.meta.url)), 'utf8');
      expect(text.length, file).toBeGreaterThan(1000);
      expect(prose(text), file).not.toMatch(/adjudicat/i);
      // Court words in every inflection. The one exemption is the exact tool-text disclaimer
      // (AWARD_DISCLAIMER), removed once if a file quotes it; neither file does today, so the
      // replace is a no-op and every occurrence of these words fails.
      expect(text.replace(AWARD_DISCLAIMER, ''), file).not.toMatch(/\barbit(?:ers?|ra\w*)\b|\brulings?\b|\bjudg\w*|\baward\w*|\btribunal\w*/i);
      expect(text.replace(/\s+/g, ' '), file).toContain('the result is data, not an adjudication, and decides no legal claim');
      expect(text.replace(/\s+/g, ' '), file).toContain('No tool moves money');
    }
  });

  it('adjudicate_dispute sends no API key, as its description says, even when one is configured', async () => {
    let captured: { url: string; init: RequestInit } | undefined;
    vi.stubGlobal('fetch', async (url: string, init: RequestInit) => {
      captured = { url, init };
      return new Response(JSON.stringify({ id: '0x', status: 'escalated', verdict: null }), { status: 200 });
    });
    try {
      const d = `0x${'cd'.repeat(32)}` as const;
      await adjudicateDisputeTool({ ...deps, ledgerHttp: { url: 'https://ledger.example.com', apiKey: 'seller-key' } }, d);
      expect(captured?.url).toBe(`https://ledger.example.com/v1/disputes/${d}/adjudicate`);
      expect(captured?.init.method).toBe('POST');
      expect(captured?.init.headers).not.toHaveProperty('authorization');
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
