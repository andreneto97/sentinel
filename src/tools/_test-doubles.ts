import { dirname } from "node:path";
import type {
  FetchLike,
  ToolFileSystem,
  ToolProcessExecutor,
  ToolProcessResult,
} from "./installer.ts";
import type { ResolverFileSystem } from "./resolve.ts";

function ancestors(path: string): string[] {
  const out: string[] = [];
  let current = path;
  for (;;) {
    out.push(current);
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return out;
}

/**
 * An in-memory disk satisfying the slices the installer and resolver take, so
 * the tests exercise the real install logic without touching the developer's
 * cache — and can assert that a failed install left nothing behind.
 */
export class MemoryFileSystem implements ToolFileSystem, ResolverFileSystem {
  private readonly files = new Map<string, Uint8Array>();
  private readonly dirs = new Set<string>();
  private readonly modes = new Map<string, number>();

  async readFile(path: string): Promise<string> {
    return new TextDecoder().decode(await this.readFileBytes(path));
  }

  async readFileBytes(path: string): Promise<Uint8Array> {
    const data = this.files.get(path);
    if (data === undefined) throw new Error(`ENOENT: no such file, open '${path}'`);
    return data;
  }

  async writeFile(
    path: string,
    data: string | Uint8Array,
    options?: { mode?: number },
  ): Promise<void> {
    const bytes = typeof data === "string" ? new TextEncoder().encode(data) : new Uint8Array(data);
    for (const dir of ancestors(dirname(path))) this.dirs.add(dir);
    this.files.set(path, bytes);
    this.modes.set(path, options?.mode ?? 0o644);
  }

  async mkdirp(path: string): Promise<void> {
    for (const dir of ancestors(path)) this.dirs.add(dir);
  }

  async exists(path: string): Promise<boolean> {
    return this.files.has(path) || this.dirs.has(path);
  }

  async remove(path: string): Promise<void> {
    const prefix = `${path}/`;
    this.files.delete(path);
    this.modes.delete(path);
    this.dirs.delete(path);
    for (const existing of [...this.files.keys()]) {
      if (!existing.startsWith(prefix)) continue;
      this.files.delete(existing);
      this.modes.delete(existing);
    }
    for (const dir of [...this.dirs]) {
      if (dir.startsWith(prefix)) this.dirs.delete(dir);
    }
  }

  async chmod(path: string, mode: number): Promise<void> {
    if (!this.files.has(path)) throw new Error(`ENOENT: no such file, chmod '${path}'`);
    this.modes.set(path, mode);
  }

  async isExecutable(path: string): Promise<boolean> {
    const mode = this.modes.get(path);
    return mode !== undefined && (mode & 0o111) !== 0;
  }

  /** Every file path currently present, sorted — used to assert nothing leaked. */
  filePaths(): string[] {
    return [...this.files.keys()].sort();
  }

  /** The mode a path carries, or undefined when it does not exist. */
  modeOf(path: string): number | undefined {
    return this.modes.get(path);
  }
}

/** One recorded invocation of the process executor double. */
export interface RecordedCommand {
  command: string;
  args: string[];
  cwd: string | null;
}

/** A process executor that records calls and defers behaviour to a handler. */
export class RecordingProcessExecutor implements ToolProcessExecutor {
  readonly calls: RecordedCommand[] = [];
  private readonly handler: (
    call: RecordedCommand,
  ) => Promise<ToolProcessResult> | ToolProcessResult;

  constructor(
    handler: (call: RecordedCommand) => Promise<ToolProcessResult> | ToolProcessResult = () => ({
      exitCode: 0,
      stdout: "",
      stderr: "",
    }),
  ) {
    this.handler = handler;
  }

  async run(
    command: string,
    args: readonly string[] = [],
    options?: { cwd?: string },
  ): Promise<ToolProcessResult> {
    const call: RecordedCommand = { command, args: [...args], cwd: options?.cwd ?? null };
    this.calls.push(call);
    return this.handler(call);
  }
}

/** A fetch double serving fixed bytes, or a status code, per URL. */
export function stubFetch(routes: Record<string, Uint8Array | number>): {
  fetch: FetchLike;
  calls: string[];
} {
  const calls: string[] = [];
  const fetchImpl: FetchLike = async (url) => {
    calls.push(url);
    const route = routes[url];
    if (route === undefined) return new Response(null, { status: 404, statusText: "Not Found" });
    if (typeof route === "number") {
      return new Response(null, { status: route, statusText: "Error" });
    }
    return new Response(route, { status: 200 });
  };
  return { fetch: fetchImpl, calls };
}
