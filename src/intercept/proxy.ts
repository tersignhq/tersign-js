import { spawn, type ChildProcess } from 'node:child_process';
import type { Readable, Writable } from 'node:stream';
import type { McpCapture } from './capture.js';
import { LineSplitter } from './frames.js';
import type { EvidenceSink } from './sink.js';

/** The byte-faithful proxy core: spawn the MCP server, pipe raw bytes straight through in
 * both directions, and tee COPIES into the frame splitter → capture. The proxy is a pure
 * observer — it never injects, reorders, delays, or modifies frames; the child receives
 * exactly the bytes the client sent and vice versa. Split out of intercept-bin so tests can
 * drive it with in-memory streams while spawning a real child. */

export interface StartInterceptOptions {
  command: string;
  args: readonly string[];
  capture: McpCapture;
  sink: EvidenceSink;
  /** client→server bytes (process.stdin on the CLI path) */
  stdin: Readable;
  /** server→client bytes (process.stdout on the CLI path) */
  stdout: Writable;
  /** child stderr disposition: 'inherit' passes it through to our stderr */
  stderr: 'inherit' | 'ignore';
}

export interface RunningIntercept {
  child: ChildProcess;
  /** resolves with the child's exit code after the outbound writable has drained, capture
   * settles and the sink is flushed; rejects if the child could not be spawned (the sink is
   * still flushed first) */
  done: Promise<number>;
}

export function startIntercept(opts: StartInterceptOptions): RunningIntercept {
  const child = spawn(opts.command, [...opts.args], { stdio: ['pipe', 'pipe', opts.stderr] });
  const clientFrames = new LineSplitter();
  const serverFrames = new LineSplitter();

  // Byte path: raw pipes. Observer path: 'data' taps feeding frame COPIES to capture —
  // parsing never touches the proxied bytes, and a malformed frame changes nothing.
  opts.stdin.on('data', (chunk: Buffer) => {
    for (const line of clientFrames.feed(chunk)) opts.capture.onFrame('client', line);
  });
  opts.stdin.pipe(child.stdin!);
  child.stdout!.on('data', (chunk: Buffer) => {
    for (const line of serverFrames.feed(chunk)) opts.capture.onFrame('server', line);
  });
  // end: false — process.stdout cannot be closed; the exit path decides when we are done
  child.stdout!.pipe(opts.stdout, { end: false });
  // EPIPE when the child exits mid-write — the close path below reports the outcome
  child.stdin!.on('error', () => {});

  // Exit-path drain: the child's 'close' means its output has been READ into Node userspace —
  // not that the outbound writable has flushed it. For a slow reader the tail of a large final
  // response is still queued here, and resolving 'done' before it drains lets the CLI exit and
  // discard it mid-frame. Wait until the writable holds nothing before settling.
  const drainOutbound = async (): Promise<void> => {
    while (!opts.stdout.destroyed && opts.stdout.writableLength > 0) {
      await new Promise<void>((resolve) => {
        const settle = (): void => {
          clearTimeout(timer);
          opts.stdout.off('drain', settle);
          opts.stdout.off('close', settle);
          opts.stdout.off('error', settle);
          resolve();
        };
        // 'drain' only fires after a write returned false; the timer covers bytes queued
        // below the high-water mark, and 'close'/'error' cover a reader that went away.
        const timer = setTimeout(settle, 20);
        opts.stdout.once('drain', settle);
        opts.stdout.once('close', settle);
        opts.stdout.once('error', settle);
      });
    }
  };

  const done = new Promise<number>((resolve, reject) => {
    const finish = async (): Promise<void> => {
      opts.capture.stop();
      await drainOutbound();
      await opts.capture.settle();
      await opts.sink.close();
    };
    child.once('error', (err) => {
      void finish().then(() => reject(err));
    });
    child.once('close', (code, signal) => {
      void finish().then(() => resolve(code ?? (signal !== null ? 1 : 0)));
    });
  });
  return { child, done };
}
