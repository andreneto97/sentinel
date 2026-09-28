/**
 * Process seam.
 *
 * The only module allowed to import `node:child_process` or call `Bun.spawn`.
 * Every external analyzer (trivy, gitleaks, knip, ...) runs through here, which
 * is where the timeout, the output cap and the process-group kill live.
 */

import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";

/** Signals Sentinel sends; deliberately narrow so callers cannot invent one. */
export type KillSignal = "SIGINT" | "SIGTERM" | "SIGKILL";

/** Default wall-clock budget for a single external tool run. */
export const DEFAULT_TIMEOUT_MS = 600_000;

/** Default cap on captured output, per stream. Analyzer JSON can be large; memory is not free. */
export const DEFAULT_MAX_OUTPUT_BYTES = 256 * 1024 * 1024;

/** How long a killed child gets to exit on SIGTERM before it is SIGKILLed. */
export const DEFAULT_KILL_GRACE_MS = 2_000;

/** Exit code convention for a binary that is not on PATH (shell convention). */
export const EXIT_NOT_FOUND = 127;

/** Exit code convention for a binary that exists but cannot be executed. */
export const EXIT_NOT_EXECUTABLE = 126;

/** Options for a single {@link ProcessExecutor.run}. */
export interface ProcessRunOptions {
  /** Working directory for the child. Defaults to Sentinel's own cwd. */
  readonly cwd?: string;
  /**
   * Environment overrides. A key mapped to `undefined` is removed from the
   * inherited environment, which is how a tool is denied a token it must not see.
   */
  readonly env?: Readonly<Record<string, string | undefined>>;
  /** Start from `process.env` before applying `env`. Default true. */
  readonly inheritEnv?: boolean;
  /** Wall-clock budget in ms; 0 disables the timeout. Default {@link DEFAULT_TIMEOUT_MS}. */
  readonly timeoutMs?: number;
  /** Per-stream capture cap in bytes. Default {@link DEFAULT_MAX_OUTPUT_BYTES}. */
  readonly maxOutputBytes?: number;
  /** Grace period between SIGTERM and SIGKILL. Default {@link DEFAULT_KILL_GRACE_MS}. */
  readonly killGraceMs?: number;
  /** Data to write to the child's stdin; stdin is closed when omitted. */
  readonly stdin?: string | Uint8Array;
  /** Cancels this run; the child's whole process group is killed. */
  readonly signal?: AbortSignal;
}

/** The outcome of one child process. */
export interface ProcessResult {
  readonly command: string;
  readonly args: readonly string[];
  /**
   * Exit status. A child killed by a signal reports 128 + signal number
   * (SIGTERM -> 143, SIGKILL -> 137), a missing binary reports 127 and a
   * non-executable one 126, so `exitCode !== 0` always means "did not succeed".
   */
  readonly exitCode: number;
  /** Signal that killed the child, when one did. */
  readonly signal: string | null;
  readonly stdout: string;
  readonly stderr: string;
  /** The run exceeded `timeoutMs` and was killed. */
  readonly timedOut: boolean;
  /** Output exceeded the cap; what is here is a prefix, the rest was discarded. */
  readonly truncated: boolean;
  /** The command could not be found on PATH — a setup problem, not a tool failure. */
  readonly notFound: boolean;
  /** Sentinel killed this child (timeout, abort, or killAll). */
  readonly killed: boolean;
  readonly durationMs: number;
}

/** The process operations Sentinel needs; implement it to script tool output in tests. */
export interface ProcessExecutor {
  /**
   * Runs a command to completion, capturing stdout/stderr under a timeout and a
   * size cap. It never rejects: a missing binary, a timeout or a crash all come
   * back as a result, so a phase decides what to do instead of unwinding.
   */
  run(
    command: string,
    args?: readonly string[],
    options?: ProcessRunOptions,
  ): Promise<ProcessResult>;
  /**
   * Kills every child still running and resolves once they are all reaped, so a
   * Ctrl-C in the CLI does not leave analyzers orphaned in the background.
   */
  killAll(signal?: KillSignal): Promise<void>;
}

/** POSIX signal numbers, for the 128 + N exit-code convention. */
const SIGNAL_NUMBERS: Readonly<Record<string, number>> = {
  SIGHUP: 1,
  SIGINT: 2,
  SIGQUIT: 3,
  SIGILL: 4,
  SIGABRT: 6,
  SIGFPE: 8,
  SIGKILL: 9,
  SIGSEGV: 11,
  SIGPIPE: 13,
  SIGALRM: 14,
  SIGTERM: 15,
};

/** Maps a terminating signal to its conventional exit code. */
function exitCodeForSignal(signal: string): number {
  return 128 + (SIGNAL_NUMBERS[signal] ?? 0);
}

/** Accumulates a stream up to a byte cap, then drains silently instead of growing. */
class CappedSink {
  readonly #chunks: Uint8Array[] = [];
  #bytes = 0;
  #truncated = false;

  constructor(private readonly limit: number) {}

  get truncated(): boolean {
    return this.#truncated;
  }

  /** Appends up to the remaining budget; everything past the cap is dropped. */
  push(chunk: Uint8Array): void {
    if (this.#truncated) return;
    const remaining = this.limit - this.#bytes;
    if (remaining <= 0) {
      this.#truncated = true;
      return;
    }
    if (chunk.byteLength <= remaining) {
      this.#chunks.push(chunk);
      this.#bytes += chunk.byteLength;
      return;
    }
    this.#chunks.push(chunk.subarray(0, remaining));
    this.#bytes = this.limit;
    this.#truncated = true;
  }

  /** Decodes the captured prefix as UTF-8. */
  text(): string {
    return Buffer.concat(this.#chunks).toString("utf8");
  }
}

/** Builds the child environment, honouring both overrides and explicit removals. */
function buildEnv(
  overrides: Readonly<Record<string, string | undefined>> | undefined,
  inherit: boolean,
): Record<string, string> {
  const env: Record<string, string> = {};
  if (inherit) {
    for (const [key, value] of Object.entries(process.env)) {
      if (value !== undefined) env[key] = value;
    }
  }
  for (const [key, value] of Object.entries(overrides ?? {})) {
    if (value === undefined) {
      delete env[key];
    } else {
      env[key] = value;
    }
  }
  return env;
}

/** A child currently being tracked, so killAll can reach it. */
interface LiveChild {
  kill(signal: KillSignal): void;
  readonly done: Promise<void>;
}

/** Creates the real process executor; every child is spawned in its own process group. */
export function createProcessExecutor(): ProcessExecutor {
  const live = new Set<LiveChild>();

  function run(
    command: string,
    args: readonly string[] = [],
    options: ProcessRunOptions = {},
  ): Promise<ProcessResult> {
    const startedAt = performance.now();
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const maxOutputBytes = options.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
    const killGraceMs = options.killGraceMs ?? DEFAULT_KILL_GRACE_MS;
    const stdout = new CappedSink(maxOutputBytes);
    const stderr = new CappedSink(maxOutputBytes);

    let timedOut = false;
    let killed = false;
    let notFound = false;
    let spawnErrorCode: number | null = null;

    let settled = false;
    let resolveResult: (result: ProcessResult) => void = () => undefined;
    const resultPromise = new Promise<ProcessResult>((resolvePromise) => {
      resolveResult = resolvePromise;
    });

    let markDone: () => void = () => undefined;
    const done = new Promise<void>((resolveDone) => {
      markDone = resolveDone;
    });

    let child: ChildProcess;
    try {
      child = spawn(command, [...args], {
        cwd: options.cwd ?? process.cwd(),
        env: buildEnv(options.env, options.inheritEnv ?? true),
        // Own process group: a tool that forks workers dies with all of them.
        detached: true,
        stdio: [options.stdin === undefined ? "ignore" : "pipe", "pipe", "pipe"],
        windowsHide: true,
      });
    } catch (error) {
      // Synchronous throw: bad arguments, never a real child.
      return Promise.resolve({
        command,
        args: [...args],
        exitCode: 1,
        signal: null,
        stdout: "",
        stderr: error instanceof Error ? error.message : String(error),
        timedOut: false,
        truncated: false,
        notFound: false,
        killed: false,
        durationMs: performance.now() - startedAt,
      });
    }

    let graceTimer: ReturnType<typeof setTimeout> | undefined;
    let timeoutTimer: ReturnType<typeof setTimeout> | undefined;
    let reapTimer: ReturnType<typeof setTimeout> | undefined;

    /** Signals the whole group; falls back to the single pid if the group is gone. */
    function killGroup(signal: KillSignal): void {
      killed = true;
      const { pid } = child;
      if (pid === undefined) return;
      try {
        process.kill(-pid, signal);
      } catch {
        try {
          child.kill(signal);
        } catch {
          // Already reaped.
        }
      }
    }

    /** SIGTERM now, SIGKILL after the grace period if it is still alive. */
    function terminate(signal: KillSignal): void {
      killGroup(signal);
      if (signal !== "SIGKILL" && graceTimer === undefined) {
        graceTimer = setTimeout(() => killGroup("SIGKILL"), killGraceMs);
        graceTimer.unref?.();
      }
    }

    const entry: LiveChild = { kill: terminate, done };
    live.add(entry);

    let exitCode: number | null = null;
    let exitSignal: string | null = null;

    function settle(): void {
      if (settled) return;
      settled = true;
      clearTimeout(timeoutTimer);
      clearTimeout(graceTimer);
      clearTimeout(reapTimer);
      options.signal?.removeEventListener("abort", onAbort);
      live.delete(entry);
      const resolvedExitCode =
        spawnErrorCode ??
        (exitCode !== null ? exitCode : exitSignal !== null ? exitCodeForSignal(exitSignal) : 1);
      resolveResult({
        command,
        args: [...args],
        exitCode: resolvedExitCode,
        signal: exitSignal,
        stdout: stdout.text(),
        stderr: stderr.text(),
        timedOut,
        truncated: stdout.truncated || stderr.truncated,
        notFound,
        killed,
        durationMs: performance.now() - startedAt,
      });
      markDone();
    }

    function onAbort(): void {
      terminate("SIGTERM");
    }

    child.stdout?.on("data", (chunk: Uint8Array) => stdout.push(chunk));
    child.stderr?.on("data", (chunk: Uint8Array) => stderr.push(chunk));

    child.on("error", (error: unknown) => {
      const code = (error as { code?: unknown }).code;
      if (code === "ENOENT") {
        notFound = true;
        spawnErrorCode = EXIT_NOT_FOUND;
        stderr.push(Buffer.from(`${command}: command not found\n`));
      } else if (code === "EACCES" || code === "EPERM") {
        spawnErrorCode = EXIT_NOT_EXECUTABLE;
        stderr.push(Buffer.from(`${command}: permission denied\n`));
      } else {
        spawnErrorCode = 1;
        stderr.push(Buffer.from(`${error instanceof Error ? error.message : String(error)}\n`));
      }
      settle();
    });

    child.on("exit", (code: number | null, signal: string | null) => {
      exitCode = code;
      exitSignal = signal;
      // "close" waits for the pipes; if they never close, do not hang forever.
      reapTimer = setTimeout(settle, 1_000);
      reapTimer.unref?.();
    });

    child.on("close", (code: number | null, signal: string | null) => {
      if (exitCode === null && exitSignal === null) {
        exitCode = code;
        exitSignal = signal;
      }
      settle();
    });

    if (options.stdin !== undefined && child.stdin !== null) {
      // A tool that exits before reading stdin makes the write fail; that is not our error.
      child.stdin.on("error", () => undefined);
      child.stdin.end(
        typeof options.stdin === "string" ? options.stdin : Buffer.from(options.stdin),
      );
    }

    if (timeoutMs > 0) {
      timeoutTimer = setTimeout(() => {
        timedOut = true;
        terminate("SIGTERM");
      }, timeoutMs);
      timeoutTimer.unref?.();
    }

    if (options.signal !== undefined) {
      if (options.signal.aborted) {
        onAbort();
      } else {
        options.signal.addEventListener("abort", onAbort, { once: true });
      }
    }

    return resultPromise;
  }

  return {
    run,
    async killAll(signal: KillSignal = "SIGTERM"): Promise<void> {
      const pending = [...live];
      for (const entry of pending) {
        entry.kill(signal);
      }
      await Promise.all(pending.map((entry) => entry.done));
    },
  };
}

/** What a stubbed run returns; anything omitted falls back to a clean success. */
export type StubProcessResult = Partial<Omit<ProcessResult, "command" | "args">>;

/** Decides what a stubbed command returns, given the call. */
export type StubProcessHandler = (
  command: string,
  args: readonly string[],
  options: ProcessRunOptions,
) => StubProcessResult | Promise<StubProcessResult>;

/**
 * A ProcessExecutor that never spawns anything, for unit tests of tool runners
 * and normalisers: the handler decides what each command "prints".
 */
export function createStubProcessExecutor(handler: StubProcessHandler): ProcessExecutor {
  return {
    async run(
      command: string,
      args: readonly string[] = [],
      options: ProcessRunOptions = {},
    ): Promise<ProcessResult> {
      const stub = await handler(command, [...args], options);
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
    async killAll(): Promise<void> {
      // Nothing was ever spawned.
    },
  };
}
