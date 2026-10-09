import { execFileSync, spawn } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';

/** Which CLI entry points treat an unsubstituted placeholder (`${TERSIGN_SELLER_KEY}`) as unset.
 * Only processes an MCP client launches do: the MCP server (keystore.test.ts, listing.test.ts) and
 * `tersign intercept` (here). `tersign disclose` keeps the 0.6.2 behaviour: the clear error, and no
 * request, before anything is signed.
 *
 * src/ is built with the build config into a temp directory and run as the published bin runs it
 * (node dist/cli.js <subcommand>), with a throwaway HOME per run, a `security` stub that exits 1
 * first on PATH (the OS keychain is never reached), and a local HTTP server that records every
 * request and answers 503. Each placeholder case has a control that reaches the server, so "no
 * request" is a measurement, not an unreachable URL. */

const SDK = fileURLToPath(new URL('..', import.meta.url));
const VALID = `0x${'a'.repeat(64)}`;
const STORED = `0x${'b'.repeat(64)}`;
const CLEAR_ERROR = 'TERSIGN_SELLER_KEY must be a 0x-prefixed 32-byte hex key';
const WARNING = 'held the literal, unsubstituted text';
const address = (key: string) => privateKeyToAccount(key as `0x${string}`).address;

// Answers every JSON-RPC request with its own raw line, then exits when stdin closes.
const RESPONDER = `
let buf = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (d) => {
  buf += d;
  let i;
  while ((i = buf.indexOf('\\n')) !== -1) {
    const line = buf.slice(0, i);
    buf = buf.slice(i + 1);
    let msg;
    try { msg = JSON.parse(line); } catch { continue; }
    if (msg.id === undefined || msg.method === undefined) continue;
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { echo: line } }) + '\\n');
  }
});
`;
const TOOL_CALL = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'echo', arguments: { a: 1 } } });

let work = '';
let cli = '';
let server: Server;
let ledgerUrl = '';
let homes = 0;
const requests: { method: string; url: string; authorization: string | undefined }[] = [];

function freshHome(stored?: string): string {
  const home = join(work, `home-${homes++}`);
  mkdirSync(home);
  if (stored !== undefined) {
    mkdirSync(join(home, '.tersign'), { mode: 0o700 });
    writeFileSync(join(home, '.tersign', 'signer.key'), `${stored}\n`, { mode: 0o600 });
  }
  return home;
}

interface Run {
  code: number | null;
  stdout: string;
  stderr: string;
}

/** Runs `node dist/cli.js <args>` with only the given env. With `request`, writes it as one line
 * and closes stdin after the first stdout line (the proxied reply); otherwise closes stdin at once. */
function run(args: string[], env: Record<string, string>, home: string, request?: string): Promise<Run> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, ...args], {
      env: {
        PATH: [join(work, 'shim'), dirname(process.execPath), '/usr/bin', '/bin'].join(delimiter),
        HOME: home,
        TMPDIR: join(work, 'tmp'),
        ...env,
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let ended = false;
    const endStdin = () => {
      if (!ended) {
        ended = true;
        child.stdin.end();
      }
    };
    child.stdin.on('error', () => {}); // a process that exits early closes its stdin first
    child.stdout.on('data', (d: Buffer) => {
      stdout += d.toString();
      if (stdout.includes('\n')) endStdin();
    });
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString()));
    const timer = setTimeout(() => child.kill('SIGKILL'), 30_000);
    child.on('error', reject);
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
    if (request !== undefined) child.stdin.write(`${request}\n`);
    else endStdin();
  });
}

const warnings = (r: Run) => r.stderr.split('\n').filter((l) => l.includes(WARNING));

beforeAll(async () => {
  work = mkdtempSync(join(tmpdir(), 'tersign-entrypoints-'));
  mkdirSync(join(work, 'tmp'));
  mkdirSync(join(work, 'shim'));
  writeFileSync(join(work, 'shim', 'security'), '#!/bin/sh\nexit 1\n');
  chmodSync(join(work, 'shim', 'security'), 0o755);

  const out = join(work, 'dist');
  const tsc = createRequire(import.meta.url).resolve('typescript/bin/tsc');
  execFileSync(process.execPath, [tsc, '-p', join(SDK, 'tsconfig.build.json'), '--outDir', out, '--declaration', 'false'], {
    cwd: SDK,
    stdio: 'pipe',
    timeout: 180_000,
  });
  writeFileSync(join(work, 'package.json'), JSON.stringify({ type: 'module' }));
  symlinkSync(join(SDK, 'node_modules'), join(work, 'node_modules'), process.platform === 'win32' ? 'junction' : 'dir');
  cli = join(out, 'cli.js');
  if (!existsSync(cli)) throw new Error(`build did not produce ${cli}`);

  server = createServer((req, res) => {
    requests.push({ method: req.method ?? '', url: req.url ?? '', authorization: req.headers.authorization });
    req.resume();
    req.on('end', () => {
      res.writeHead(503, { 'content-type': 'application/json' });
      res.end('{"error":"capture server"}');
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  ledgerUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}, 200_000);

afterAll(async () => {
  if (server) await new Promise<void>((r) => server.close(() => r()));
  if (work) rmSync(work, { recursive: true, force: true });
});

beforeEach(() => {
  requests.length = 0;
});

describe('tersign disclose — a placeholder TERSIGN_SELLER_KEY keeps the 0.6.2 clear error', () => {
  it('exits non-zero with the clear error and sends no request, with a stored key present', async () => {
    for (const value of ['${TERSIGN_SELLER_KEY}', '$TERSIGN_SELLER_KEY']) {
      const r = await run(['disclose', 'hello', '--ledger', ledgerUrl], { TERSIGN_SELLER_KEY: value }, freshHome(STORED));
      expect(r.code, `${value}\n${r.stderr}`).toBe(1);
      expect(r.stderr, value).toContain(CLEAR_ERROR);
      expect(r.stderr, value).not.toContain('signing key:');
      expect(warnings(r), value).toEqual([]);
    }
    expect(requests).toEqual([]);
  });

  it('control: a valid key signs and reaches the ledger', async () => {
    const r = await run(['disclose', 'hello', '--ledger', ledgerUrl], { TERSIGN_SELLER_KEY: VALID }, freshHome(STORED));
    expect(r.stderr).toContain(`signing key: ${address(VALID)} (env)`);
    expect(requests.length, r.stderr).toBeGreaterThan(0);
  });
});

describe('tersign intercept — an MCP client launches it, so a placeholder counts as unset', () => {
  const ledgerEnv = (apiKey: string) => ({
    TERSIGN_SELLER_KEY: VALID,
    TERSIGN_LEDGER_URL: ledgerUrl,
    TERSIGN_LEDGER_API_KEY: apiKey,
    TERSIGN_LEDGER_SELLER_ID: 's',
  });
  const intercept = ['intercept', '--', process.execPath, '-e', RESPONDER];

  it('a placeholder TERSIGN_LEDGER_API_KEY sends no Authorization header; the record lands locally', async () => {
    const home = freshHome();
    const r = await run(intercept, ledgerEnv('${TERSIGN_LEDGER_API_KEY}'), home, TOOL_CALL);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toContain('"echo"');
    expect(requests.filter((q) => q.authorization !== undefined)).toEqual([]);
    expect(requests).toEqual([]);
    expect(r.stderr).toContain('1 tool-call records (0 ledger, 1 local)');
    expect(readdirSync(join(home, '.tersign')).filter((f) => f.startsWith('intercepts-'))).toHaveLength(1);
    const w = warnings(r);
    expect(w, r.stderr).toHaveLength(1);
    expect(w[0]).toContain(`TERSIGN_LEDGER_API_KEY ${WARNING} \${TERSIGN_LEDGER_API_KEY} and was treated as unset`);
    expect(w[0]).toContain('no API key is sent');
  });

  it('control: a real TERSIGN_LEDGER_API_KEY is sent as the bearer credential', async () => {
    const r = await run(intercept, ledgerEnv('tsk_test_control'), freshHome(), TOOL_CALL);
    expect(r.code, r.stderr).toBe(0);
    expect(requests, r.stderr).toContainEqual({ method: 'POST', url: '/v1/evidence', authorization: 'Bearer tsk_test_control' });
    expect(warnings(r)).toEqual([]);
  });

  it('a placeholder TERSIGN_SELLER_KEY starts with the stored key', async () => {
    const r = await run(intercept, { TERSIGN_SELLER_KEY: '${TERSIGN_SELLER_KEY}' }, freshHome(STORED), TOOL_CALL);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stderr).toContain(`signing key: ${address(STORED)} (keyfile)`);
    const w = warnings(r);
    expect(w, r.stderr).toHaveLength(1);
    expect(w[0]).toContain('the key from the keyfile');
    expect(w[0]).toContain(address(STORED));
  });

  it('a placeholder TERSIGN_SELLER_KEY with nothing stored starts with a generated key', async () => {
    const home = freshHome();
    const r = await run(intercept, { TERSIGN_SELLER_KEY: '$TERSIGN_SELLER_KEY' }, home, TOOL_CALL);
    expect(r.code, r.stderr).toBe(0);
    const generated = readFileSync(join(home, '.tersign', 'signer.key'), 'utf8').trim();
    expect(r.stderr).toContain(`signing key: ${address(generated)} (keyfile)`);
    const w = warnings(r);
    expect(w, r.stderr).toHaveLength(1);
    expect(w[0]).toContain('a newly generated key');
  });
});
