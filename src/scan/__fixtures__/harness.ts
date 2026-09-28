/**
 * Test harness for the scan engine.
 *
 * Reads go through the real filesystem port against `__fixtures__/target`, so
 * every snippet in an asserted finding was extracted from a file that really
 * exists; writes are captured in memory, so a test run leaves no run directory
 * behind. Commands are replayed from output captured off the pinned binaries
 * rather than invented, so a payload shape can never drift from what the tools
 * actually print.
 */

import { join } from "node:path";
import { type FileSystem, createFileSystem } from "../../ports/file-system.ts";
import { type Logger, silentLogger } from "../../ports/logger.ts";
import type {
  KillSignal,
  ProcessExecutor,
  ProcessResult,
  ProcessRunOptions,
} from "../../ports/process-executor.ts";
import type { ScanContext, ScanToolResolver } from "../types.ts";

/** Absolute path of the fixture repository these tests analyse. */
export const FIXTURE_TARGET = join(import.meta.dir, "target");

/** Where a fixture run pretends to write; nothing reaches this path. */
export const FIXTURE_RUN_DIR = "/tmp/sentinel-scan-fixture/20240101T000000-0000abcd";

/** A run id shaped like the real ones, so the document looks like a real document. */
export const FIXTURE_RUN_ID = "20240101T000000-0000abcd";

/**
 * Real output of `hadolint --no-fail --no-color --format json Dockerfile`,
 * hadolint 2.15.1, against `target/Dockerfile`.
 */
export const HADOLINT_OUTPUT = await Bun.file(
  join(import.meta.dir, "hadolint-dockerfile.json"),
).text();

/**
 * Real output of `actionlint -format '{{json .}}' -no-color
 * .github/workflows/ci.yml`, actionlint 1.7.12, against the same repository.
 */
export const ACTIONLINT_OUTPUT = await Bun.file(
  join(import.meta.dir, "actionlint-workflows.json"),
).text();

/** A filesystem that reads the real fixtures and remembers what was written. */
export interface RecordingFileSystem extends FileSystem {
  readonly written: Map<string, string>;
  readonly mkdirs: string[];
}

/** Builds a filesystem whose reads are real and whose writes go nowhere. */
export function recordingFileSystem(): RecordingFileSystem {
  const real = createFileSystem();
  const written = new Map<string, string>();
  const mkdirs: string[] = [];
  return {
    ...real,
    written,
    mkdirs,
    async writeFile(path: string, data: string | Uint8Array): Promise<void> {
      written.set(path, typeof data === "string" ? data : new TextDecoder().decode(data));
    },
    async mkdirp(path: string): Promise<void> {
      mkdirs.push(path);
    },
  };
}

/** One spawned command, as the step asked for it. */
export interface RecordedRun {
  readonly command: string;
  readonly args: readonly string[];
  readonly options: ProcessRunOptions;
}

/** Decides what a replayed command "prints"; anything omitted is a clean success. */
export type ReplayHandler = (
  command: string,
  args: readonly string[],
) => Partial<ProcessResult> | undefined;

/** An executor that spawns nothing, remembers every call, and records kills. */
export interface RecordingExecutor extends ProcessExecutor {
  readonly runs: RecordedRun[];
  readonly kills: KillSignal[];
}

/**
 * Replays the captured payloads: hadolint and actionlint get their real output,
 * anything else exits 127 the way a binary that is not installed does.
 */
export function defaultReplay(command: string): Partial<ProcessResult> | undefined {
  if (command.includes("hadolint")) return { stdout: HADOLINT_OUTPUT };
  if (command.includes("actionlint")) return { stdout: ACTIONLINT_OUTPUT };
  return undefined;
}

/** Builds an executor whose output a test scripts, defaulting to the real captures. */
export function recordingExecutor(handler: ReplayHandler = defaultReplay): RecordingExecutor {
  const runs: RecordedRun[] = [];
  const kills: KillSignal[] = [];
  return {
    runs,
    kills,
    async run(
      command: string,
      args: readonly string[] = [],
      options: ProcessRunOptions = {},
    ): Promise<ProcessResult> {
      runs.push({ command, args: [...args], options });
      const stub = handler(command, [...args]) ?? {
        exitCode: 127,
        notFound: true,
        stderr: `${command}: command not found\n`,
      };
      return {
        command,
        args: [...args],
        exitCode: stub.exitCode ?? 0,
        signal: stub.signal ?? null,
        stdout: stub.stdout ?? "",
        stderr: stub.stderr ?? "",
        timedOut: stub.timedOut ?? false,
        truncated: stub.truncated ?? false,
        notFound: stub.notFound ?? false,
        killed: stub.killed ?? false,
        durationMs: stub.durationMs ?? 0,
      };
    },
    async killAll(signal: KillSignal = "SIGTERM"): Promise<void> {
      kills.push(signal);
    },
  };
}

/** A resolver that knows exactly the tools a test says are installed. */
export function fixtureResolver(paths: Readonly<Record<string, string>>): ScanToolResolver {
  return {
    async resolve(name: string): Promise<string | null> {
      return paths[name] ?? null;
    },
  };
}

/** The two tools whose real output this fixture carries. */
export const INSTALLED_TOOLS: Readonly<Record<string, string>> = {
  hadolint: "/opt/sentinel/hadolint",
  actionlint: "/opt/sentinel/actionlint",
};

/** Everything a test may want to swap out of the context. */
export interface FixtureContextOverrides {
  readonly fs?: FileSystem;
  readonly exec?: ProcessExecutor;
  readonly tools?: ScanToolResolver;
  readonly targetDir?: string;
  readonly logger?: Logger;
  readonly signal?: AbortSignal;
}

/** Builds a `ScanContext` pointed at the fixture repository. */
export function fixtureContext(overrides: FixtureContextOverrides = {}): ScanContext {
  return {
    fs: overrides.fs ?? recordingFileSystem(),
    exec: overrides.exec ?? recordingExecutor(),
    tools: overrides.tools ?? fixtureResolver(INSTALLED_TOOLS),
    targetDir: overrides.targetDir ?? FIXTURE_TARGET,
    runDir: FIXTURE_RUN_DIR,
    runId: FIXTURE_RUN_ID,
    logger: overrides.logger ?? silentLogger,
    ...(overrides.signal === undefined ? {} : { signal: overrides.signal }),
  };
}
