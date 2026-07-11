#!/usr/bin/env node
/** tersign — the package-default bin, dispatching subcommands:
 *
 *   npx tersign            → MCP server on stdio (what MCP clients invoke; registry contract)
 *   npx tersign mcp        → same, explicit
 *   npx tersign verify …   → third-party receipt verification (same as tersign-verify)
 *
 * Why a dispatcher: `npx tersign-verify` resolves 'tersign-verify' as a PACKAGE name (E404 —
 * npx only maps bare bin names for installed packages), so the uninstalled one-liner must go
 * through the package-name bin. The dedicated tersign-verify / tersign-mcp bins still exist
 * for installed use. */
export {};

const sub = process.argv[2];

if (sub === undefined || sub === 'mcp') {
  if (sub === 'mcp') process.argv.splice(2, 1);
  await import('./mcp/bin.js');
} else if (sub === 'verify') {
  process.argv.splice(2, 1);
  await import('./verify-bin.js');
} else if (sub === 'help' || sub === '--help' || sub === '-h') {
  console.log(
    'tersign — evidence layer for the agent economy\n\n' +
      '  tersign                 start the MCP server (stdio)\n' +
      '  tersign mcp             same, explicit\n' +
      '  tersign verify <receipt.json | 0xdigest> [--signer 0xaddr] [--ledger url]\n' +
      '                          verify a receipt: local signature recovery + public chain check\n',
  );
} else {
  console.error(`unknown subcommand '${sub}' — did you mean: tersign verify ${sub}\nrun 'tersign help' for usage`);
  process.exit(2);
}
