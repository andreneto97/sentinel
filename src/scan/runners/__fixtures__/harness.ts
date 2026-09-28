/**
 * Test harness for the dependency and dead-code runners.
 *
 * Reads go through the real filesystem port against the fixture repositories in
 * this directory, so every snippet in an asserted finding was extracted from a
 * file that actually exists; writes are captured in memory, so a test run never
 * leaves a run directory behind.
 */

import { join } from "node:path";
import { createFileSystem } from "../../../ports/file-system.ts";
import type {
  RunnerFileSystem,
  RunnerProcessExecutor,
  RunnerProcessOptions,
  RunnerProcessResult,
  RunnerToolResolver,
} from "../_runner-support.ts";

/** Absolute path of a fixture repository in this directory. */
export function fixtureRepo(name: string): string {
  return join(import.meta.dir, name);
}

/** One captured write, so a test can assert what a runner generated. */
export interface RecordedWrite {
  readonly path: string;
  readonly content: string;
}

/** A filesystem that reads the real fixtures and remembers what was written. */
export interface HarnessFileSystem extends RunnerFileSystem {
  readonly writes: RecordedWrite[];
  readonly mkdirs: string[];
}

/** Builds a filesystem whose reads are real and whose writes go nowhere. */
export function harnessFileSystem(): HarnessFileSystem {
  const real = createFileSystem();
  const writes: RecordedWrite[] = [];
  const mkdirs: string[] = [];
  return {
    writes,
    mkdirs,
    readFile: (path) => real.readFile(path),
    readFileBytes: (path) => real.readFileBytes(path),
    realpath: (path) => real.realpath(path),
    exists: (path) => real.exists(path),
    async writeFile(path: string, data: string | Uint8Array): Promise<void> {
      writes.push({
        path,
        content: typeof data === "string" ? data : new TextDecoder().decode(data),
      });
    },
    async mkdirp(path: string): Promise<void> {
      mkdirs.push(path);
    },
  };
}

/** One spawned command, as the runner asked for it. */
export interface RecordedRun {
  readonly command: string;
  readonly args: readonly string[];
  readonly options: RunnerProcessOptions;
}

/** Decides what a stubbed command "prints"; anything omitted is a clean success. */
export type RunHandler = (
  command: string,
  args: readonly string[],
  options: RunnerProcessOptions,
) => Partial<RunnerProcessResult>;

/** An executor that spawns nothing and remembers every call. */
export interface HarnessExecutor extends RunnerProcessExecutor {
  readonly runs: RecordedRun[];
}

/** Builds an executor whose output a test scripts. */
export function harnessExecutor(handler: RunHandler): HarnessExecutor {
  const runs: RecordedRun[] = [];
  return {
    runs,
    async run(
      command: string,
      args: readonly string[] = [],
      options: RunnerProcessOptions = {},
    ): Promise<RunnerProcessResult> {
      runs.push({ command, args: [...args], options });
      const stub = handler(command, [...args], options);
      return {
        exitCode: stub.exitCode ?? 0,
        stdout: stub.stdout ?? "",
        stderr: stub.stderr ?? "",
        timedOut: stub.timedOut ?? false,
        truncated: stub.truncated ?? false,
        notFound: stub.notFound ?? false,
      };
    },
  };
}

/** A resolver that knows exactly the tools a test says are installed. */
export function harnessResolver(paths: Readonly<Record<string, string>>): RunnerToolResolver {
  return {
    async resolve(name: string): Promise<string | null> {
      return paths[name] ?? null;
    },
  };
}
