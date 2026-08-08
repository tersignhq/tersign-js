/** Flag parsing for `tersign intercept` — the tokens strictly BEFORE '--' (everything after
 * belongs to the child verbatim). Supports both '--flag value' and '--flag=value'; unknown
 * flags and flags missing their value are errors, never silent misreads (a bare '--agent-id'
 * must not consume a following '--ledger' as its value — that once signed records with
 * agent.id '--ledger'). Split out of intercept-bin so tests can drive it directly. */

export interface InterceptFlags {
  events?: string;
  agentId?: string;
  ledger?: string;
}

export type ParsedInterceptFlags = { ok: true; flags: InterceptFlags } | { ok: false; error: string };

const FLAG_KEYS: ReadonlyMap<string, keyof InterceptFlags> = new Map([
  ['--events', 'events'],
  ['--agent-id', 'agentId'],
  ['--ledger', 'ledger'],
]);

export function parseInterceptFlags(tokens: readonly string[]): ParsedInterceptFlags {
  const flags: InterceptFlags = {};
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i]!;
    const eq = token.indexOf('=');
    const name = eq === -1 ? token : token.slice(0, eq);
    const key = FLAG_KEYS.get(name);
    if (key === undefined) {
      return {
        ok: false,
        error: name.startsWith('--')
          ? `unknown flag '${name}'`
          : `unexpected argument '${token}' — flags go before '--', the server command after`,
      };
    }
    if (eq !== -1) {
      flags[key] = token.slice(eq + 1);
      continue;
    }
    const next = tokens[i + 1];
    if (next === undefined || next.startsWith('--')) {
      return { ok: false, error: `flag '${name}' requires a value` };
    }
    flags[key] = next;
    i += 1;
  }
  return { ok: true, flags };
}
