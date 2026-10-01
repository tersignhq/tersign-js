import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { privateKeyToAccount } from 'viem/accounts';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { buildServer, envDeps } from '../src/mcp/server.js';
import { verifyReceipt } from '../src/receipt/eip712.js';
import type { SignedReceipt } from '../src/types.js';

/** The registry listing (server.json), the README and llms.txt describe the MCP server to people
 * and directories that never run it. Each claim they make about configuration or tools is checked
 * here against what the server actually does: a published requirement must be one the code
 * enforces, and a published promise must be one the code keeps.
 *
 * Why this exists (2026-09-27): since 0.4.7, `npx tersign` (the command the listing runs) starts
 * with no key and self-provisions one, yet the registry listing kept `TERSIGN_SELLER_KEY` at
 * isRequired:true through 0.4.11 — so every directory rendering it told readers a private key was
 * needed before first use — and its tool list never gained record_disclosure.
 *
 * Two measurements, and which claim each one licenses:
 *   1. THE REGISTRY COMMAND. server.json says `npx <identifier>` over stdio with no arguments; npx
 *      runs package.json `bin[<identifier>]` (dist/cli.js) with node. So src/ is built exactly as
 *      `npm run build` builds it, into a temp directory, and that file is started with NO
 *      subcommand, stdin piped and a scrubbed env, then driven by the SDK's own stdio MCP client —
 *      the same transport an MCP client uses. The key gate in cli.ts sits above envDeps; an
 *      in-process envDeps/buildServer measurement cannot see it.
 *   2. TOOL BEHAVIOUR, in process with fetch stubbed: which env each tool actually needs, and
 *      whether it counter-signs. The listing's per-variable text is held to these.
 *
 * Hermetic: the spawned server gets a throwaway HOME and a PATH whose first `security` is a stub
 * that logs and fails (macOS keychain off); in process, only the `security` command is blocked.
 * Every key generated lands in the temp directory, which is removed afterwards.
 *
 * What this cannot see: prose that states a requirement in words the vocabulary checks below
 * do not know ("has to be", "cannot start without"). The structured fields (server.json
 * isRequired, the README Required column, the tool lists) are compared exactly; the prose checks
 * are a vocabulary net over the one sentence per surface that describes each variable. */

vi.mock('node:child_process', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:child_process')>();
  return {
    ...real,
    execFileSync: ((file: string, ...rest: unknown[]) => {
      if (file === 'security') throw new Error('OS keychain disabled in listing.test.ts');
      return (real.execFileSync as (...a: unknown[]) => unknown)(file, ...rest);
    }) as typeof real.execFileSync,
  };
});

const SDK = fileURLToPath(new URL('..', import.meta.url));
const read = (rel: string) => readFileSync(join(SDK, rel), 'utf8');

interface EnvVar {
  name: string;
  description: string;
  isRequired?: boolean;
}
interface ListedPackage {
  registryType: string;
  identifier: string;
  runtimeHint?: string;
  transport: { type: string };
  environmentVariables: EnvVar[];
  packageArguments?: unknown[];
  runtimeArguments?: unknown[];
}
const listing = JSON.parse(read('server.json')) as {
  packages: ListedPackage[];
  _meta: Record<string, { tools?: string[]; summary?: string }>;
};
const pkg = JSON.parse(read('package.json')) as { name: string; version: string; bin: Record<string, string> };
const entry = listing.packages[0]!;
const declared = entry.environmentVariables;
const declaredNames = declared.map((v) => v.name).sort();
const listedRequired = declared.filter((v) => v.isRequired === true).map((v) => v.name);
const publisher = listing._meta['io.modelcontextprotocol.registry/publisher-provided'] ?? {};
const listedTools = [...(publisher.tools ?? [])].sort();

const readme = read('README.md');
const llms = read('llms.txt');
const llmsMcp = llms.split(/^## MCP server configuration$/m)[1]?.split(/^## /m)[0] ?? '';

// Words that state a requirement. Checked only inside the text that describes one variable,
// after negated forms ("not required", "never mandatory") are removed — those deny one.
const REQUIREMENT = /\b(must|required|requires?|mandatory|necessary)\b/i;
const statesRequirement = (t: string) =>
  REQUIREMENT.test(t.replace(/\b(?:not|never|no longer)\s+(?:required|mandatory|necessary)\b/gi, ''));
// Measured below: the registry command starts with every declared variable absent.
const REQUIRED_BY_CODE: string[] = [];

// ---------------------------------------------------------------------------------------------
// Measurement 1: the registry command, started the way a registry client starts it.

let work = '';
let home = '';
let shimLog = '';
let registryCli = '';

interface Started {
  serverInfo: { name: string; version: string } | undefined;
  tools: { name: string; description?: string | undefined }[];
  signer: string | undefined;
  stderr: string;
}

async function startRegistryCommand(env: Record<string, string>, issue: boolean): Promise<Started> {
  // No subcommand: `npx tersign` passes no arguments, and the listing declares none (asserted).
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [registryCli],
    env: {
      PATH: [join(work, 'shim'), dirname(process.execPath), '/usr/bin', '/bin'].join(delimiter),
      HOME: home,
      TMPDIR: join(work, 'tmp'),
      ...env,
    },
    stderr: 'pipe',
  });
  let stderr = '';
  transport.stderr?.on('data', (d: Buffer) => (stderr += d.toString()));
  const client = new Client({ name: 'listing-test', version: '0' });
  try {
    await client.connect(transport);
    const tools = (await client.listTools()).tools;
    let signer: string | undefined;
    if (issue) {
      // issue_receipt with no ledger configured signs locally and makes no network call.
      const res = await client.callTool({
        name: 'issue_receipt',
        arguments: {
          network: 'eip155:8453',
          resourceUrl: 'https://example.com/r',
          payer: '0x1111111111111111111111111111111111111111',
          supplyDescription: 'listing test',
          settledAt: 1_750_000_000,
        },
      });
      const text = (res.content as { text: string }[])[0]!.text;
      if (res.isError) throw new Error(`issue_receipt failed: ${text}`);
      const verified = await verifyReceipt((JSON.parse(text) as { receipt: SignedReceipt }).receipt);
      signer = verified.valid ? verified.signer : undefined;
    }
    return { serverInfo: client.getServerVersion(), tools, signer, stderr };
  } catch (err) {
    // Recorded, not thrown: a start that fails must fail the tests that depend on it, each with
    // this message, rather than abort beforeAll and leave every other check skipped and silent.
    return { serverInfo: undefined, tools: [], signer: undefined, stderr: `did not answer: ${String(err)}\nserver stderr:\n${stderr}` };
  } finally {
    await client.close().catch(() => {});
  }
}

const keyfile = () => join(home, '.tersign', 'signer.key');
const keyfileAddress = () => privateKeyToAccount(readFileSync(keyfile(), 'utf8').trim() as `0x${string}`).address;

let bare: Started;
let emptyKey: Started;
let ledgerConfigured: Started;
let keyfileAfterBare = '';

beforeAll(async () => {
  work = mkdtempSync(join(tmpdir(), 'tersign-listing-'));
  home = join(work, 'home');
  mkdirSync(home);
  mkdirSync(join(work, 'tmp'));
  mkdirSync(join(work, 'shim'));
  shimLog = join(work, 'shim.log');
  const shim = join(work, 'shim', 'security');
  writeFileSync(shim, `#!/bin/sh\necho "$*" >> '${shimLog}'\nexit 1\n`);
  chmodSync(shim, 0o755);

  // Build exactly what ships (tsconfig.build.json = the `npm run build` config), fresh, so a
  // stale sdk/dist can never stand in for the source under test.
  const out = join(work, 'dist');
  const tsc = createRequire(import.meta.url).resolve('typescript/bin/tsc');
  execFileSync(process.execPath, [tsc, '-p', join(SDK, 'tsconfig.build.json'), '--outDir', out, '--declaration', 'false'], {
    cwd: SDK,
    stdio: 'pipe',
    timeout: 180_000,
  });
  // The built files are ESM and import their dependencies by bare name: give the temp tree the
  // package's module type and its node_modules, as an installed package has.
  writeFileSync(join(work, 'package.json'), JSON.stringify({ type: 'module' }));
  symlinkSync(join(SDK, 'node_modules'), join(work, 'node_modules'), process.platform === 'win32' ? 'junction' : 'dir');

  const binRel = pkg.bin[entry.identifier];
  if (!binRel?.startsWith('dist/')) throw new Error(`package.json bin["${entry.identifier}"] is ${binRel}, not a dist/ file`);
  registryCli = join(work, binRel);
  if (!existsSync(registryCli)) throw new Error(`build did not produce ${registryCli}`);

  bare = await startRegistryCommand({}, true);
  keyfileAfterBare = existsSync(keyfile()) ? keyfileAddress() : '';
  emptyKey = await startRegistryCommand({ TERSIGN_SELLER_KEY: '' }, true);
  // The configuration the old caveat named: a seller id set, no key. Nothing here touches the
  // network — the unroutable URL is only ever read by a tool call, and none is made.
  ledgerConfigured = await startRegistryCommand(
    { TERSIGN_LEDGER_URL: 'http://127.0.0.1:9', TERSIGN_LEDGER_API_KEY: 'k', TERSIGN_LEDGER_SELLER_ID: 's' },
    false,
  );
}, 240_000);

afterAll(() => {
  if (work) rmSync(work, { recursive: true, force: true });
});

const toolNames = (s: Started) => s.tools.map((t) => t.name).sort();

describe('the registry command (npx <identifier>, no arguments) with zero configuration', () => {
  it('is the command the listing declares: npm package, stdio, npx, no arguments', () => {
    expect(entry.registryType).toBe('npm');
    expect(entry.identifier).toBe(pkg.name);
    expect(entry.transport.type).toBe('stdio');
    expect(entry.runtimeHint).toBe('npx');
    // Arguments would change what npx runs; this measurement starts it with none.
    expect(entry.packageArguments ?? []).toEqual([]);
    expect(entry.runtimeArguments ?? []).toEqual([]);
  });

  it('starts, identifies itself, lists its tools, and signs with a key it generated', () => {
    expect(bare.serverInfo, bare.stderr).toEqual({ name: pkg.name, version: pkg.version });
    expect(bare.tools.length).toBeGreaterThan(0);
    expect(keyfileAfterBare).toMatch(/^0x[0-9a-fA-F]{40}$/);
    expect(bare.signer).toBe(keyfileAfterBare);
    if (process.platform !== 'win32') expect(statSync(keyfile()).mode & 0o777).toBe(0o600);
  });

  it('treats an EMPTY TERSIGN_SELLER_KEY as unset: starts, and signs with the same stored key', () => {
    expect(emptyKey.serverInfo, emptyKey.stderr).toEqual({ name: pkg.name, version: pkg.version });
    expect(toolNames(emptyKey)).toEqual(toolNames(bare));
    expect(emptyKey.signer).toBe(keyfileAfterBare);
  });

  it('starts without a key when a ledger seller id is configured too', () => {
    expect(ledgerConfigured.serverInfo, ledgerConfigured.stderr).toEqual({ name: pkg.name, version: pkg.version });
    expect(toolNames(ledgerConfigured)).toEqual(toolNames(bare));
  });

  it('never reached the real keychain (hermetic)', () => {
    // On macOS the keystore asks `security` first; the stub must be what answered.
    if (process.platform === 'darwin') expect(readFileSync(shimLog, 'utf8')).toContain('find-generic-password');
  });
});

// ---------------------------------------------------------------------------------------------
// Measurement 2: what each tool needs and does, in process with fetch stubbed.

interface Call {
  url: string;
  method: string;
  auth: boolean;
}

async function callTool(env: Record<string, string>, name: string, args: Record<string, unknown>) {
  const calls: Call[] = [];
  vi.stubGlobal('fetch', async (url: string, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    calls.push({ url: String(url), method: init?.method ?? 'GET', auth: headers.has('authorization') });
    return new Response(JSON.stringify({}), { status: 200, headers: { 'content-type': 'application/json' } });
  });
  const savedHome = process.env.HOME;
  const savedKey = process.env.TERSIGN_SELLER_KEY;
  process.env.HOME = home;
  delete process.env.TERSIGN_SELLER_KEY;
  const quiet = vi.spyOn(console, 'error').mockImplementation(() => {});
  try {
    const server = buildServer(envDeps(env));
    const [serverSide, clientSide] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'listing-test', version: '0' });
    await Promise.all([server.connect(serverSide), client.connect(clientSide)]);
    const res = await client.callTool({ name, arguments: args });
    await client.close();
    return { calls, isError: res.isError === true, text: (res.content as { text: string }[])[0]?.text ?? '' };
  } finally {
    quiet.mockRestore();
    if (savedHome === undefined) delete process.env.HOME;
    else process.env.HOME = savedHome;
    if (savedKey !== undefined) process.env.TERSIGN_SELLER_KEY = savedKey;
  }
}

afterEach(() => {
  vi.unstubAllGlobals();
});

const LEDGER = { TERSIGN_LEDGER_URL: 'https://ledger.test', TERSIGN_LEDGER_API_KEY: 'k', TERSIGN_LEDGER_SELLER_ID: 's' };
const DIGEST = `0x${'ab'.repeat(32)}`;
const TOOL_ARGS: Record<string, Record<string, unknown>> = {
  record_disclosure: { text: 'You are talking to an AI.', agentId: 'listing-test' },
  issue_receipt: {
    network: 'eip155:8453',
    resourceUrl: 'https://example.com/r',
    payer: '0x1111111111111111111111111111111111111111',
    supplyDescription: 'listing test',
    settledAt: 1_750_000_000,
  },
  record_refund: { originalDigest: DIGEST, amount: '1.00', reason: 'test' },
  submit_dispute_evidence: {
    disputeDigest: DIGEST,
    role: 'respondent',
    artifacts: [{ kind: 'content-digest', digest: DIGEST }],
  },
};
/** Does this tool, with this env, send a write to a ledger? (The measured sense of "counter-signs".) */
async function ledgerWrites(env: Record<string, string>, tool: string) {
  const args = TOOL_ARGS[tool];
  if (!args) throw new Error(`no measurement arguments for tool ${tool}`);
  const r = await callTool(env, tool, args);
  return r.calls.filter((c) => c.method === 'POST');
}

describe('tool behaviour the listing text describes', () => {
  it('record_disclosure counter-signs with ZERO configuration, and sends no API key', async () => {
    const writes = await ledgerWrites({}, 'record_disclosure');
    expect(writes).toEqual([{ url: 'https://tersign.ai/v1/disclose', method: 'POST', auth: false }]);
  });

  it('issue_receipt with zero configuration makes no ledger call (it returns an unchained receipt)', async () => {
    expect(await ledgerWrites({}, 'issue_receipt')).toEqual([]);
  });

  it('issue_receipt and record_refund write to the ledger once URL, API key and seller id are all set', async () => {
    expect(await ledgerWrites(LEDGER, 'issue_receipt')).toEqual([{ url: 'https://ledger.test/v1/receipts', method: 'POST', auth: true }]);
    expect(await ledgerWrites(LEDGER, 'record_refund')).toEqual([{ url: 'https://ledger.test/v1/refunds', method: 'POST', auth: true }]);
    const { TERSIGN_LEDGER_SELLER_ID: _omit, ...noSellerId } = LEDGER;
    expect(await ledgerWrites(noSellerId, 'record_refund')).toEqual([]);
  });

  it('respondent dispute evidence carries the API key when URL and API key are set', async () => {
    const { TERSIGN_LEDGER_SELLER_ID: _omit, ...urlAndKey } = LEDGER;
    expect(await ledgerWrites(urlAndKey, 'submit_dispute_evidence')).toEqual([
      { url: `https://ledger.test/v1/disputes/${DIGEST}/evidence`, method: 'POST', auth: true },
    ]);
  });
});

// ---------------------------------------------------------------------------------------------
// The listing, the README and llms.txt, held to the two measurements.

/** The text each surface uses to describe one variable. */
function describedAs(name: string): Record<string, string> {
  const row = readme.match(new RegExp(`^\\|\\s*\`${name}\`\\s*\\|([^\\n]*)$`, 'm'))?.[1] ?? '';
  // llms.txt: the parenthetical that follows the variable in the MCP section (balanced).
  let paren = '';
  const at = llmsMcp.search(new RegExp(`\`?${name}\`?\\s*\\(`));
  if (at >= 0) {
    const open = llmsMcp.indexOf('(', at);
    let depth = 0;
    for (let i = open; i < llmsMcp.length; i++) {
      if (llmsMcp[i] === '(') depth++;
      if (llmsMcp[i] === ')' && --depth === 0) {
        paren = llmsMcp.slice(open, i + 1);
        break;
      }
    }
  }
  return {
    'server.json': declared.find((v) => v.name === name)?.description ?? '',
    'README row': row,
    'llms.txt': paren,
  };
}

describe('registry listing (server.json) matches the server', () => {
  it('marks required exactly the variables the server cannot start without', () => {
    expect(listedRequired).toEqual(REQUIRED_BY_CODE);
  });

  it('lists every tool the registry command serves, and no other', () => {
    expect(listedTools).toEqual(toolNames(bare));
  });

  it('the self-provisioning promise states the conditions under which the ledger refuses it', () => {
    // The hosted ledger answers /v1/disclose with 409 when the key is already registered to an
    // API-key account and 429 when the daily provisioning caps are reached (its own route tests
    // pin both). A sentence that promises self-provisioning must name both.
    const summary = publisher.summary ?? '';
    const disclosure = bare.tools.find((t) => t.name === 'record_disclosure')?.description ?? '';
    const promises = [...summary.split(/(?<=\.)\s+/), disclosure].filter((s) => /self-provision/i.test(s));
    expect(promises.length).toBeGreaterThanOrEqual(2);
    for (const sentence of promises) {
      expect(sentence).toMatch(/\b409\b/);
      expect(sentence).toMatch(/\b429\b/);
    }
  });

  it('so does every other self-provisioning promise: the README, llms.txt and the CLI greeting', () => {
    // Found 2026-09-27: the listing and the tool description were fixed while README (the
    // disclose paragraph and the Machine Surfaces row), llms.txt and the TTY greeting still made
    // the promise unconditionally. A promise is the verb form, "self-provisions"; the noun
    // ("self-provisioned accounts") names the account class and promises nothing.
    const cli = read('src/cli.ts')
      .split('\n')
      .filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)) // code comments explain history; they promise nothing
      .join('\n')
      .replace(/'\s*\+\s*\n\s*['"]|"\s*\+\s*\n\s*['"]|\\n/g, ' ');
    const chunks = (t: string) => t.split(/(?<=[.;])\s+|\n(?=\S)|\n\s*\n|\|/).map((x) => x.replace(/\s+/g, ' '));
    const promises = [...chunks(readme), ...chunks(llms), ...chunks(cli)].filter((x) => /self-provisions\b/i.test(x));
    expect(promises.length).toBeGreaterThanOrEqual(4);
    for (const sentence of promises) {
      expect(sentence, sentence).toMatch(/\b409\b/);
      expect(sentence, sentence).toMatch(/\b429\b/);
    }
  });
});

describe('README matches the listing and the server', () => {
  const rows = [...readme.matchAll(/^\|\s*`(TERSIGN_[A-Z_]+)`\s*\|\s*([^|]*?)\s*\|/gm)].map((m) => ({
    name: m[1]!,
    required: m[2]!,
  }));

  it('env table covers every declared variable', () => {
    expect(rows.map((r) => r.name).sort()).toEqual(declaredNames);
  });

  it('env table Required column is exactly "yes" for what the code requires and "no" for the rest', () => {
    expect(rows.length).toBeGreaterThan(0);
    for (const r of rows) expect([r.name, r.required]).toEqual([r.name, REQUIRED_BY_CODE.includes(r.name) ? 'yes' : 'no']);
  });

  it('tools line names every tool the registry command serves', () => {
    const line = readme.match(/^\*\*Tools\*\*[^\n]*$/m)?.[0] ?? '';
    expect([...line.matchAll(/`([a-z_]+)`/g)].map((m) => m[1]).sort()).toEqual(toolNames(bare));
  });

  it('the "cold to counter-signed" path counter-signs with no configuration', async () => {
    const line = readme.match(/^Cold to counter-signed[^\n]*$/m)?.[0] ?? '';
    const tool = line.match(/call `([a-z_]+)`/)?.[1];
    expect(tool, 'README has a "Cold to counter-signed" line naming the tool to call').toBeDefined();
    expect(await ledgerWrites({}, tool!)).toHaveLength(1);
  });
});

describe('llms.txt matches the listing and the server', () => {
  it('has an MCP server configuration section', () => {
    expect(llmsMcp.length).toBeGreaterThan(0);
  });

  it('names every declared variable and calls none required that the code does not require', () => {
    expect([...new Set(llmsMcp.match(/TERSIGN_[A-Z_]+/g) ?? [])].sort()).toEqual(declaredNames);
    // Unconditional "(required …" / "is required" in any spelling or case. A requirement scoped
    // by what follows it ("(required by the dispute tools") is a conditional, and stays legal for
    // variables other than the key, whose text is held to a stricter check below.
    const unconditional = /(TERSIGN_[A-Z_]+)`?\s*(?:\(\s*|(?:is|are)\s+)(?:required|mandatory)\b(?!\s+(?:by|for|only|if|when|with|to|unless)\b)/gi;
    const calledRequired = [...llms.matchAll(unconditional)].map((m) => m[1]!);
    expect(calledRequired).toEqual(REQUIRED_BY_CODE);
  });

  it('tools line names every tool the registry command serves', () => {
    const tools = llmsMcp.match(/^Tools:([^.]*)\./m)?.[1] ?? '';
    expect(tools.split(',').map((t) => t.trim()).filter(Boolean).sort()).toEqual(toolNames(bare));
  });
});

describe('per-variable text states only what the code enforces', () => {
  it('TERSIGN_SELLER_KEY is described without a requirement on every surface', () => {
    // Measured above: the registry command starts without it with nothing set, with it set to
    // "", and with a ledger seller id configured. So no surface may attach a requirement to it
    // under any condition — the listing once said a seller id made a registered key mandatory,
    // which nothing on the server's path enforces.
    const text = describedAs('TERSIGN_SELLER_KEY');
    for (const [surface, t] of Object.entries(text)) {
      expect(t.length, `${surface} describes TERSIGN_SELLER_KEY`).toBeGreaterThan(0);
      expect(statesRequirement(t), `${surface}: ${t}`).toBe(false);
    }
  });

  it('no surface makes the ledger API key or seller id a condition of counter-signing', () => {
    // Measured above: record_disclosure counter-signs with neither.
    for (const name of ['TERSIGN_LEDGER_API_KEY', 'TERSIGN_LEDGER_SELLER_ID']) {
      for (const [surface, t] of Object.entries(describedAs(name))) {
        expect(t, `${surface} / ${name}`).not.toMatch(/\b(required|requires?|needed|only if)\b[^.;|]*counter-?sign/i);
      }
    }
  });
});

// What the ledger counter-signs on a paid call. The ledger signs the chain link
// keccak256(receiptDigest ‖ prevDigest ‖ uint64be(seq)) over the RECEIPT (src/canonical.ts
// chainLinkDigest is the verifier's copy of that construction: three inputs, none of them the
// compliance record). The record travels to the ledger beside the receipt and its digest is
// stored, but nothing is signed over it; its only tie to the receipt is the seller's own
// attestation, whose signed payload names receiptDigest (src/compliance/record.ts). The first
// test below reads these surfaces: the README, llms.txt, the server.json summary, the package.json
// description, every MCP tool description, and the two JSDoc blocks that ship in the .d.ts and
// describe the paid-call path (the `Assure` class and `withAssure`). Other JSDoc is not read.
//
// What this cannot see: a paraphrase that avoids "compliance record", "both" and "records are
// counter-signed" — an added sentence saying the ledger counter-signs "the record" passes (checked
// by mutation, 2026-09-29). The second test pins the four paragraphs that describe the paid-call
// path, so the correct statement cannot be removed from any of them.
describe('what the ledger counter-signs on a paid call, as each surface states it', () => {
  const sentences = (t: string) => t.split(/(?<=[.;])\s+|\n(?=\S)|\n\s*\n|\|/).map((x) => x.replace(/\s+/g, ' '));
  const assureDoc = (read('src/assure.ts').match(/\/\*\*((?:(?!\*\/)[\s\S])*)\*\/\s*export class Assure\b/)?.[1] ?? '')
    .replace(/\n\s*\*\s?/g, ' ')
    .replace(/\s+/g, ' ');
  const withAssureDoc = (
    read('src/adapter/x402.ts').match(/\/\*\*((?:(?!\*\/)[\s\S])*)\*\/\s*export function withAssure\b/)?.[1] ?? ''
  )
    .replace(/\n\s*\*\s?/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  const surfaces = (): Record<string, string> => ({
    README: readme,
    'llms.txt': llms,
    'server.json summary': publisher.summary ?? '',
    'package.json description': (JSON.parse(read('package.json')) as { description: string }).description,
    'Assure JSDoc (ships in the .d.ts)': assureDoc,
    'withAssure JSDoc (ships in the .d.ts)': withAssureDoc,
    ...Object.fromEntries(bare.tools.map((t) => [`${t.name} description`, t.description ?? ''])),
  });

  it('no sentence puts the compliance record, or "both" artifacts, under the ledger counter-signature', () => {
    expect(bare.tools.length).toBeGreaterThan(0);
    expect(assureDoc.length).toBeGreaterThan(0);
    expect(withAssureDoc).toMatch(/^Wrap an x402-protected handler/);
    let netted = 0;
    for (const [surface, text] of Object.entries(surfaces())) {
      for (const s of sentences(text)) {
        if (!/counter-?sign/i.test(s)) continue;
        if (!/compliance(?:-fields)? record|\bboth\b|\brecords are counter-signed\b/i.test(s)) continue;
        netted++;
        expect(s, `${surface}: ${s}`).toMatch(/compliance-fields record is not counter-signed/i);
      }
    }
    // The four paid-call surfaces each carry one such sentence: the net is not empty.
    expect(netted).toBeGreaterThanOrEqual(4);
  });

  it('the paid-call paragraphs name the receipt as counter-signed and the seller signature as the record binding', () => {
    const paragraphs: Record<string, string> = {
      'README withAssure': readme.match(/^`withAssure\(\)` wraps[^\n]*$/m)?.[0] ?? '',
      'llms.txt withAssure': llms.split(/^`withAssure\(handler/m)[1]?.split(/\n\s*\n/)[0] ?? '',
      'issue_receipt description': bare.tools.find((t) => t.name === 'issue_receipt')?.description ?? '',
      'Assure JSDoc': assureDoc,
    };
    for (const [surface, t] of Object.entries(paragraphs)) {
      const flat = t.replace(/\s+/g, ' ');
      expect(flat.length, surface).toBeGreaterThan(0);
      expect(flat, surface).toMatch(/the ledger counter-signs the receipt/);
      expect(flat, surface).toMatch(/the compliance-fields record is not counter-signed/);
      expect(flat, surface).toMatch(/bound to its receipt only by (your|the seller's) own signature/);
    }
  });

  it('the Assure JSDoc points at the header placement, not the legacy body helper', () => {
    expect(assureDoc).toMatch(/`attachToSettlementResponse`/);
    expect(assureDoc).not.toMatch(/attachToExtensions/);
  });
});
