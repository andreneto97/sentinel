/**
 * A `CliContext` whose streams are strings.
 *
 * Every verb writes through the context rather than to `process.stdout`, which
 * is what lets a test assert on the exact bytes a command printed. The clock and
 * the randomness are fixed for the same reason: a test that asserts on output
 * must not depend on the minute it runs in.
 */

import type { CliContext, OutputFlags } from "../index.ts";

/** A captured run of a verb: its streams, and the context it wrote them to. */
export interface CapturedCli {
  readonly context: CliContext;
  /** Everything written to stdout so far. */
  stdout(): string;
  /** Everything written to stderr so far. */
  stderr(): string;
}

/** Builds a context that writes into strings; `cwd` defaults to `/work`. */
export function captureCli(cwd = "/work"): CapturedCli {
  let out = "";
  let err = "";
  return {
    context: {
      write: (text: string) => {
        out += text;
      },
      writeError: (text: string) => {
        err += text;
      },
      cwd,
      env: {},
      clock: { now: () => 0, sleep: async () => undefined },
      random: { hex: (bytes: number) => "0".repeat(bytes * 2) },
      version: "0.0.1-test",
    },
    stdout: () => out,
    stderr: () => err,
  };
}

/** The three reporting flags, all off unless named. */
export function outputFlags(overrides: Partial<OutputFlags> = {}): OutputFlags {
  return {
    json: overrides.json ?? false,
    verbose: overrides.verbose ?? false,
    quiet: overrides.quiet ?? false,
  };
}
