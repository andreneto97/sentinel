#!/usr/bin/env bun
import { EXIT, runCli } from "../src/cli/index.ts";

/**
 * Process entry point. It owns the three things `runCli` deliberately does not:
 * reading `process.argv`, translating a signal into exit code 130, and calling
 * `process.exit`.
 */

let interrupted = false;

/** Exit with 130 on the first signal; a second one is the user insisting. */
function onSignal(): void {
  if (interrupted) process.exit(EXIT.interrupted);
  interrupted = true;
  process.stderr.write("\nsentinel: interrupted\n");
  process.exit(EXIT.interrupted);
}

process.on("SIGINT", onSignal);
process.on("SIGTERM", onSignal);

const code = await runCli(process.argv.slice(2));
process.exit(code);
