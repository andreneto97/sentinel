import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { type Clock, createSystemClock } from "../../ports/clock.ts";

/**
 * The run directory layout from PLAN.md: every run writes into
 * `<out>/<runId>/`, with `raw/` holding untouched tool output, and
 * `<out>/.latest` pointing at the most recent run so `resume`, `status` and
 * `report` can be given the output directory instead of a run id.
 */

/** Source of the random half of a run id. */
export interface RandomSource {
  /** Lowercase hex string of exactly `bytes * 2` characters. */
  hex(bytes: number): string;
}

/** Web-crypto-backed randomness (Bun exposes `crypto` as a global). */
export const cryptoRandom: RandomSource = {
  hex(bytes: number): string {
    const buffer = new Uint8Array(bytes);
    crypto.getRandomValues(buffer);
    return Array.from(buffer, (byte) => byte.toString(16).padStart(2, "0")).join("");
  },
};

/** Name of the pointer file written beside the run directories. */
export const LATEST_POINTER = ".latest";

/** Name of the per-run subdirectory holding untouched tool output. */
export const RAW_DIR = "raw";

/** `YYYYMMDDTHHmmss-<8 hex>`; the timestamp half is UTC. */
export const RUN_ID_PATTERN = /^\d{8}T\d{6}-[0-9a-f]{8}$/;

/** True when `value` is a syntactically valid run id. */
export function isRunId(value: string): boolean {
  return RUN_ID_PATTERN.test(value);
}

/** Format epoch milliseconds as the `YYYYMMDDTHHmmss` half of a run id, in UTC. */
export function formatRunTimestamp(epochMs: number): string {
  const date = new Date(epochMs);
  const pad = (value: number, width = 2): string => String(value).padStart(width, "0");
  return (
    `${pad(date.getUTCFullYear(), 4)}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}` +
    `T${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}`
  );
}

/**
 * Build a run id. UTC keeps ids sortable and comparable across machines and DST
 * boundaries; the random half keeps two runs started in the same second apart.
 */
export function createRunId(clock: Clock, random: RandomSource = cryptoRandom): string {
  return `${formatRunTimestamp(clock.now())}-${random.hex(4)}`;
}

/** Every path a phase needs inside one run. */
export interface RunDir {
  /** Directory holding all runs, i.e. `<target>/sentinel`. */
  readonly outDir: string;
  readonly runId: string;
  /** `<outDir>/<runId>`. */
  readonly dir: string;
  /** `<outDir>/<runId>/raw`. */
  readonly rawDir: string;
  /** `<outDir>/.latest`. */
  readonly latestPath: string;
  /** Absolute path of an artifact inside the run directory. */
  artifact(name: string): string;
  /** Absolute path of an untouched tool output inside `raw/`. */
  raw(name: string): string;
}

/** Compute the layout for a run without touching the filesystem. */
export function runDirLayout(outDir: string, runId: string): RunDir {
  const root = resolve(outDir);
  const dir = join(root, runId);
  const rawDir = join(dir, RAW_DIR);
  return {
    outDir: root,
    runId,
    dir,
    rawDir,
    latestPath: join(root, LATEST_POINTER),
    artifact: (name: string) => join(dir, name),
    raw: (name: string) => join(rawDir, name),
  };
}

/**
 * The slice of the filesystem port this module needs. Declared structurally so
 * the run directory never imports the port itself — any `FileSystem` satisfies
 * it, and a test can pass an in-memory double.
 */
export interface RunDirFileSystem {
  mkdirp(path: string): Promise<void>;
  /** Atomic in the real port: a reader sees the old pointer or the new one. */
  writeFile(path: string, data: string): Promise<void>;
  readFile(path: string): Promise<string>;
  exists(path: string): Promise<boolean>;
}

/** Options for creating a run directory. */
export interface CreateRunDirOptions {
  readonly outDir: string;
  /** Reuse an existing id (a resumed run) instead of minting a new one. */
  readonly runId?: string;
  readonly clock?: Clock;
  readonly random?: RandomSource;
  /** Skip writing `<out>/.latest`. */
  readonly updateLatest?: boolean;
}

/** Create `<out>/<runId>/raw` and point `<out>/.latest` at the new run. */
export async function createRunDir(
  fs: RunDirFileSystem,
  options: CreateRunDirOptions,
): Promise<RunDir> {
  const runId = options.runId ?? createRunId(options.clock ?? createSystemClock(), options.random);
  if (!isRunId(runId)) throw new Error(`invalid run id: ${runId}`);
  const layout = runDirLayout(options.outDir, runId);
  await fs.mkdirp(layout.rawDir);
  if (options.updateLatest !== false) await writeLatestPointer(fs, layout.outDir, runId);
  return layout;
}

/** Point `<out>/.latest` at `runId`. */
export async function writeLatestPointer(
  fs: RunDirFileSystem,
  outDir: string,
  runId: string,
): Promise<void> {
  if (!isRunId(runId)) throw new Error(`invalid run id: ${runId}`);
  await fs.mkdirp(resolve(outDir));
  await fs.writeFile(join(resolve(outDir), LATEST_POINTER), `${runId}\n`);
}

/**
 * Read `<out>/.latest`. Undefined when it is absent or does not hold a
 * well-formed run id — the pointer is a file on disk like any other, so it is
 * validated rather than trusted.
 */
export async function readLatestPointer(
  fs: RunDirFileSystem,
  outDir: string,
): Promise<string | undefined> {
  const target = join(resolve(outDir), LATEST_POINTER);
  if (!(await fs.exists(target))) return undefined;
  const raw = (await fs.readFile(target)).trim();
  return isRunId(raw) ? raw : undefined;
}

/** Either the resolved layout or why the argument named no run. */
export type RunDirResolution =
  | { readonly ok: true; readonly runDir: RunDir }
  | { readonly ok: false; readonly reason: "not-found" | "no-latest" | "not-a-run-dir" };

/**
 * Resolve the `<run-dir>` argument of `resume` / `status` / `report`: either a
 * run directory itself, or an output directory whose `.latest` names one.
 */
export async function resolveRunDir(
  fs: RunDirFileSystem,
  path: string,
  cwd: string,
): Promise<RunDirResolution> {
  const absolute = isAbsolute(path) ? path : resolve(cwd, path);
  if (!(await fs.exists(absolute))) return { ok: false, reason: "not-found" };

  const name = basename(absolute);
  if (isRunId(name)) return { ok: true, runDir: runDirLayout(dirname(absolute), name) };

  const latest = await readLatestPointer(fs, absolute);
  if (latest === undefined) {
    const hasPointer = await fs.exists(join(absolute, LATEST_POINTER));
    return { ok: false, reason: hasPointer ? "not-a-run-dir" : "no-latest" };
  }
  return { ok: true, runDir: runDirLayout(absolute, latest) };
}
