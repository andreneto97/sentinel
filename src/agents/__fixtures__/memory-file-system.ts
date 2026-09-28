import { dirname } from "node:path";
import type { RawLogFileSystem } from "../raw-log.ts";

/** An in-memory disk for the transcript sink: enough to assert what was written where. */
export class MemoryRawLogFileSystem implements RawLogFileSystem {
  readonly files = new Map<string, string>();
  readonly dirs = new Set<string>();

  async writeFile(path: string, data: string): Promise<void> {
    if (!this.dirs.has(dirname(path)))
      throw new Error(`ENOENT: missing directory ${dirname(path)}`);
    this.files.set(path, data);
  }

  async mkdirp(path: string): Promise<void> {
    this.dirs.add(path);
  }

  /** Paths written, sorted, so an assertion does not depend on write order. */
  paths(): string[] {
    return [...this.files.keys()].sort();
  }
}
