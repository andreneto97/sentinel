import type { VerifyFileSystem } from "./context.ts";

/** Contents of a fake repository: absolute paths to text or raw bytes. */
export interface MemoryFileSystemInit {
  /** Absolute path → file contents. */
  readonly files: Readonly<Record<string, string | Uint8Array>>;
  /** Absolute symlink path → absolute target, resolved by `realpath`. */
  readonly links?: Readonly<Record<string, string>>;
  /** Directories that exist even though they hold no listed file. */
  readonly dirs?: readonly string[];
}

const MAX_LINK_HOPS = 8;

/**
 * An in-memory `VerifyFileSystem` for tests: it models the two things the
 * verifier actually depends on — reading bytes and resolving symlinks — without
 * touching disk or the filesystem port.
 */
export class MemoryFileSystem implements VerifyFileSystem {
  private readonly files: Map<string, Uint8Array>;
  private readonly links: [string, string][];
  private readonly dirs: Set<string>;

  constructor(init: MemoryFileSystemInit) {
    const encoder = new TextEncoder();
    this.files = new Map(
      Object.entries(init.files).map(([path, body]) => [
        path,
        typeof body === "string" ? encoder.encode(body) : body,
      ]),
    );
    // Longest prefix first, so nested links resolve before their parents.
    this.links = Object.entries(init.links ?? {}).sort((a, b) => b[0].length - a[0].length);
    this.dirs = new Set(init.dirs ?? []);
  }

  /** Resolves symlink prefixes and rejects paths that do not exist. */
  async realpath(path: string): Promise<string> {
    let current = path;
    for (let hop = 0; hop < MAX_LINK_HOPS; hop += 1) {
      const link = this.links.find(([from]) => current === from || current.startsWith(`${from}/`));
      if (link === undefined) break;
      current = `${link[1]}${current.slice(link[0].length)}`;
    }
    if (!this.exists(current)) throw new Error(`ENOENT: ${path}`);
    return current;
  }

  /** Returns a file's bytes, rejecting missing paths and directories. */
  async readBytes(path: string): Promise<Uint8Array> {
    const real = await this.realpath(path);
    const bytes = this.files.get(real);
    if (bytes === undefined) throw new Error(`EISDIR: ${path}`);
    return bytes;
  }

  private exists(path: string): boolean {
    if (this.files.has(path) || this.dirs.has(path)) return true;
    const prefix = `${path}/`;
    for (const known of this.files.keys()) if (known.startsWith(prefix)) return true;
    return false;
  }
}
