/** The base every ledger path is joined to: the ledger URL as given, minus every trailing '/'.
 * Every surface that takes a ledger URL joins its paths through this one function:
 * TERSIGN_LEDGER_URL, LedgerClient's `url`, the MCP tools' ledger access, recordDisclosure's
 * `ledger`, `tersign intercept` and `tersign verify --ledger`. So "https://tersign.ai/" and
 * "https://tersign.ai//" reach the same routes as "https://tersign.ai"; a base that kept its
 * slash would send "//v1/…", which the ledger answers with 404. No other part of the URL is
 * touched. Runtime-agnostic: no Node imports. */
export function ledgerBase(url: string): string {
  let end = url.length;
  while (end > 0 && url.charCodeAt(end - 1) === 0x2f /* '/' */) end -= 1;
  return url.slice(0, end);
}
