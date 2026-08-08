/** The published one-liner is the signature demo and appears in every README, the npm page
 * and the ARD catalog, so its behaviour is a public contract. These pin the two halves of it:
 * a bare digest resolves to the default ledger, and a receipt FILE still verifies with no
 * network unless a ledger is explicitly named. */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, beforeAll } from 'vitest';

// NOT imported from ../src/verify-bin.js: that module is a script — it calls process.exit(2)
// on import when argv carries no target, which kills the whole run. The contract is pinned
// through the CLI's own output below, which is the surface third parties actually see.
const DEFAULT_LEDGER = 'https://tersign.ai';

const GENESIS = '0xe5874f1ffe87f0a6dd9eb157730f67b86ee4538b125fe30fcc4e165213dd3fc4';

describe('verify CLI ledger resolution', () => {
  // CI runs `npm test` BEFORE `npm run build`, so dist/ does not exist there. Build it once
  // rather than skipping when it is missing — a test that quietly disappears in CI is worse
  // than no test, and this one first passed locally only because a stale dist/ happened to be
  // sitting there from an earlier manual build.
  beforeAll(() => {
    if (!existsSync(cli())) {
      execFileSync('npx', ['tsc', '-p', 'tsconfig.build.json'], {
        cwd: join(import.meta.dirname, '..'),
        stdio: 'inherit',
        timeout: 180_000,
      });
    }
    if (!existsSync(cli())) throw new Error(`build did not produce ${cli()}`);
  }, 200_000);

  it('usage names the default ledger — third parties script against this', () => {
    let stderr = '';
    try {
      execFileSync(process.execPath, [cli()], { encoding: 'utf8', timeout: 30_000, stdio: 'pipe' });
    } catch (e) {
      stderr = String((e as { stderr?: string }).stderr ?? '');
    }
    expect(stderr).toContain(`a bare digest checks against ${DEFAULT_LEDGER}`);
  });

  // The digest is the frozen genesis receipt; the assertion is about WHICH ledger is
  // consulted, not about the network, so a run without connectivity fails loudly rather
  // than passing vacuously.
  it('a bare digest with no --ledger consults the default and says so', () => {
    const out = execFileSync(process.execPath, [cli(), GENESIS], { encoding: 'utf8', timeout: 30_000 });
    expect(out).toContain(DEFAULT_LEDGER);
    expect(out).toContain('(default; override with --ledger)');
    expect(out).toMatch(/counter-signed OK/);
    expect(out.trimEnd().endsWith('VALID')).toBe(true);
  });

  it('an explicit --ledger wins and drops the default note', () => {
    const out = execFileSync(process.execPath, [cli(), GENESIS, '--ledger', DEFAULT_LEDGER], {
      encoding: 'utf8',
      timeout: 30_000,
    });
    expect(out).toContain(DEFAULT_LEDGER);
    expect(out).not.toContain('default; override');
  });

  it('a receipt file without --ledger stays offline — no chain call', () => {
    // A receipt whose signature cannot recover fails at the signature step. If the CLI had
    // started defaulting a ledger call for FILES too, the failure text would name a ledger.
    const dir = mkdtempSync(join(tmpdir(), 'tersign-verify-'));
    const file = join(dir, 'bad.json');
    writeFileSync(file, JSON.stringify({ payload: { schema: 'x' }, signature: '0x00' }));
    let stderr = '';
    try {
      execFileSync(process.execPath, [cli(), file], { encoding: 'utf8', timeout: 30_000, stdio: 'pipe' });
    } catch (e) {
      stderr = String((e as { stderr?: string }).stderr ?? '');
    }
    expect(stderr).toMatch(/INVALID/);
    expect(stderr).not.toContain(DEFAULT_LEDGER);
  });
});

/** Built output, so the test exercises what actually ships rather than the source. */
function cli(): string {
  return join(import.meta.dirname, '..', 'dist', 'verify-bin.js');
}
