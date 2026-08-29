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
  // Bare `npx tersign` at a prompt is almost always a curious human, not an MCP client — greet
  // them rather than sitting mute on a stdio transport they are not speaking. The discriminator
  // is the TTY, NOT the presence of a key: an MCP client, a directory's sandbox and a CI probe
  // all arrive with stdin piped, and until 2026-08-29 every one of them hit a hard exit here.
  // That made `npx tersign` fail on first run for anyone who had not already exported a key,
  // left the server impossible to introspect or demonstrate anywhere, and contradicted
  // record_disclosure's own published promise that the first call self-provisions. The key is
  // no longer required — envDeps resolves through the shared keystore — so the greeting is now
  // a courtesy for humans instead of a gate on everyone.
  if (process.stdin.isTTY && !process.env.TERSIGN_SELLER_KEY) {
    console.error(
      'tersign: this starts the MCP server, which speaks JSON-RPC over stdin — nothing to see\n' +
        'at a prompt. Wire it into your MCP client config:\n\n' +
        '  { "mcpServers": { "tersign": { "command": "npx", "args": ["tersign"] } } }\n\n' +
        'No key needed: the first call self-provisions a signer-keyed account (OS keychain,\n' +
        'else ~/.tersign/signer.key). Set TERSIGN_SELLER_KEY to use your own.\n\n' +
        "Just exploring? Try:  tersign help   ·   tersign verify <receipt.json | 0xdigest> [--ledger url]",
    );
    process.exit(1);
  }
  await import('./mcp/bin.js');
} else if (sub === 'verify') {
  process.argv.splice(2, 1);
  await import('./verify-bin.js');
} else if (sub === 'disclose') {
  process.argv.splice(2, 1);
  await import('./disclose-bin.js');
} else if (sub === 'intercept') {
  process.argv.splice(2, 1);
  await import('./intercept-bin.js');
} else if (sub === 'help' || sub === '--help' || sub === '-h') {
  console.log(
    'tersign — evidence layer for the agent economy\n\n' +
      '  tersign                 start the MCP server (stdio)\n' +
      '  tersign mcp             same, explicit\n' +
      '  tersign verify <receipt.json | 0xdigest> [--signer 0xaddr] [--ledger url]\n' +
      '                          verify a receipt: local signature recovery + public chain check\n' +
      '  tersign disclose "<text>" [--medium chat] [--agent-id id] [--url resourceUrl]\n' +
      '                          counter-signed disclosure evidence — text digested locally,\n' +
      '                          only the digest travels; key created on first use\n' +
      '  tersign intercept [--events m1,m2] [--agent-id id] [--ledger url] -- <server cmd…>\n' +
      '                          byte-faithful MCP stdio proxy — signed, digest-only\n' +
      '                          tool-call evidence for the wrapped server (experimental).\n' +
      '                          Hosted ledger mode requires the signer key registered for\n' +
      '                          the sellerId (TERSIGN_SELLER_KEY); rejected records fall\n' +
      "                          back to ~/.tersign. Exits with the child's code; 1 if\n" +
      '                          evidence was lost while the child exited 0\n',
  );
} else {
  console.error(`unknown subcommand '${sub}' — did you mean: tersign verify ${sub}\nrun 'tersign help' for usage`);
  process.exit(2);
}
