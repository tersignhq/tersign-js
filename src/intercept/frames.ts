/** Newline-delimited JSON-RPC framing for the MCP stdio transport.
 *
 * Observation only: the proxied byte path never flows through this module — the proxy pipes
 * raw bytes straight through and feeds COPIES here, so the child receives exactly the bytes
 * the client sent and vice versa (parse a copy, never a re-serialization). Frames may arrive
 * split across reads or coalesced several-per-chunk, and can be arbitrarily large (buffered
 * until the newline arrives). */

/** Splits a byte stream into newline-delimited frames. Yielded lines exclude the trailing
 * `\n` (a trailing `\r` is left in place — `tryParseFrame` tolerates it). Partial pieces
 * accumulate as an array and concatenate once per completed line, so a large frame fed in
 * many chunks costs O(bytes), not O(bytes²). */
export class LineSplitter {
  private pending: Buffer[] = [];

  feed(chunk: Buffer): Buffer[] {
    const lines: Buffer[] = [];
    let start = 0;
    let nl: number;
    while ((nl = chunk.indexOf(0x0a, start)) !== -1) {
      const piece = chunk.subarray(start, nl);
      if (this.pending.length > 0) {
        this.pending.push(piece);
        lines.push(Buffer.concat(this.pending));
        this.pending = [];
      } else {
        lines.push(piece);
      }
      start = nl + 1;
    }
    if (start < chunk.length) this.pending.push(chunk.subarray(start));
    return lines;
  }
}

/** Parse one frame for observation. Returns the parsed JSON value, or undefined for empty
 * and non-JSON lines — those pass through the proxy untouched and are never captured.
 * Never throws into the proxy path. */
export function tryParseFrame(line: Buffer): unknown {
  let end = line.length;
  if (end > 0 && line[end - 1] === 0x0d) end -= 1; // CRLF tolerance
  if (end === 0) return undefined;
  try {
    return JSON.parse(line.subarray(0, end).toString('utf8')) as unknown;
  } catch {
    return undefined;
  }
}
