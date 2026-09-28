import { describe, expect, test } from "bun:test";
import { FakeClock } from "../../ports/clock.ts";
import {
  RUN_ID_PATTERN,
  type RunDirFileSystem,
  createRunDir,
  createRunId,
  formatRunTimestamp,
  isRunId,
  readLatestPointer,
  resolveRunDir,
  runDirLayout,
  writeLatestPointer,
} from "./run-dir.ts";

/** In-memory stand-in for the filesystem port, so these tests touch no disk. */
class MemoryFileSystem implements RunDirFileSystem {
  readonly files = new Map<string, string>();
  readonly dirs = new Set<string>();

  async mkdirp(path: string): Promise<void> {
    const segments = path.split("/");
    for (let index = 1; index < segments.length; index += 1) {
      this.dirs.add(segments.slice(0, index + 1).join("/"));
    }
  }

  async writeFile(path: string, data: string): Promise<void> {
    this.files.set(path, data);
  }

  async readFile(path: string): Promise<string> {
    const content = this.files.get(path);
    if (content === undefined) throw new Error(`ENOENT: ${path}`);
    return content;
  }

  async exists(path: string): Promise<boolean> {
    return this.files.has(path) || this.dirs.has(path);
  }
}

const AT = Date.UTC(2026, 8, 22, 15, 4, 5);
const clock = new FakeClock(AT);
const random = { hex: (bytes: number) => "ab".repeat(bytes) };

describe("createRunId", () => {
  test("is YYYYMMDDTHHmmss-<8 hex>", () => {
    const runId = createRunId(clock, random);
    expect(runId).toBe("20260922T150405-abababab");
    expect(RUN_ID_PATTERN.test(runId)).toBe(true);
    expect(isRunId(runId)).toBe(true);
  });

  test("formats the timestamp in UTC, zero-padded", () => {
    expect(formatRunTimestamp(Date.UTC(2026, 0, 2, 3, 4, 5))).toBe("20260102T030405");
  });

  test("rejects ids that do not match the shape", () => {
    expect(isRunId("20260922T150405-ABABABAB")).toBe(false);
    expect(isRunId("20260922-abababab")).toBe(false);
    expect(isRunId("latest")).toBe(false);
  });

  test("uses real randomness by default, so two ids in the same second differ", () => {
    expect(createRunId(clock)).not.toBe(createRunId(clock));
  });
});

describe("runDirLayout", () => {
  test("puts raw output under the run directory", () => {
    const layout = runDirLayout("/repo/sentinel", "20260922T150405-abababab");
    expect(layout.dir).toBe("/repo/sentinel/20260922T150405-abababab");
    expect(layout.rawDir).toBe("/repo/sentinel/20260922T150405-abababab/raw");
    expect(layout.latestPath).toBe("/repo/sentinel/.latest");
    expect(layout.artifact("findings.json")).toBe(
      "/repo/sentinel/20260922T150405-abababab/findings.json",
    );
    expect(layout.raw("trivy.json")).toBe("/repo/sentinel/20260922T150405-abababab/raw/trivy.json");
  });
});

describe("createRunDir", () => {
  test("creates raw/ and points .latest at the new run", async () => {
    const fs = new MemoryFileSystem();
    const layout = await createRunDir(fs, { outDir: "/repo/sentinel", clock, random });

    expect(layout.runId).toBe("20260922T150405-abababab");
    expect(fs.dirs.has("/repo/sentinel/20260922T150405-abababab/raw")).toBe(true);
    expect(await readLatestPointer(fs, "/repo/sentinel")).toBe("20260922T150405-abababab");
    expect([...fs.files.keys()]).toEqual(["/repo/sentinel/.latest"]);
  });

  test("reuses a given run id, which is what resume needs", async () => {
    const fs = new MemoryFileSystem();
    const layout = await createRunDir(fs, {
      outDir: "/repo/sentinel",
      runId: "20260101T000000-deadbeef",
    });
    expect(layout.dir).toBe("/repo/sentinel/20260101T000000-deadbeef");
  });

  test("refuses a malformed run id", async () => {
    const fs = new MemoryFileSystem();
    await expect(createRunDir(fs, { outDir: "/repo/sentinel", runId: "nope" })).rejects.toThrow(
      "invalid run id",
    );
  });

  test("can skip the pointer update", async () => {
    const fs = new MemoryFileSystem();
    await createRunDir(fs, { outDir: "/repo/sentinel", clock, random, updateLatest: false });
    expect(await readLatestPointer(fs, "/repo/sentinel")).toBeUndefined();
  });
});

describe("readLatestPointer", () => {
  test("ignores a pointer that does not hold a run id", async () => {
    const fs = new MemoryFileSystem();
    await writeLatestPointer(fs, "/repo/sentinel", "20260922T150405-abababab");
    await fs.writeFile("/repo/sentinel/.latest", "../../etc/passwd\n");
    expect(await readLatestPointer(fs, "/repo/sentinel")).toBeUndefined();
  });

  test("is undefined when there is no pointer at all", async () => {
    expect(await readLatestPointer(new MemoryFileSystem(), "/repo/sentinel")).toBeUndefined();
  });
});

describe("resolveRunDir", () => {
  test("accepts a run directory directly", async () => {
    const fs = new MemoryFileSystem();
    await createRunDir(fs, { outDir: "/repo/sentinel", clock, random });
    const resolved = await resolveRunDir(fs, "/repo/sentinel/20260922T150405-abababab", "/repo");
    expect(resolved.ok).toBe(true);
    if (!resolved.ok) return;
    expect(resolved.runDir.runId).toBe("20260922T150405-abababab");
    expect(resolved.runDir.outDir).toBe("/repo/sentinel");
  });

  test("follows .latest when given the output directory", async () => {
    const fs = new MemoryFileSystem();
    await createRunDir(fs, { outDir: "/repo/sentinel", clock, random });
    const resolved = await resolveRunDir(fs, "/repo/sentinel", "/repo");
    expect(resolved.ok).toBe(true);
    if (!resolved.ok) return;
    expect(resolved.runDir.dir).toBe("/repo/sentinel/20260922T150405-abababab");
  });

  test("resolves a relative path against the given cwd", async () => {
    const fs = new MemoryFileSystem();
    await createRunDir(fs, { outDir: "/repo/sentinel", clock, random });
    expect((await resolveRunDir(fs, "sentinel", "/repo")).ok).toBe(true);
  });

  test("reports a missing path", async () => {
    const resolved = await resolveRunDir(new MemoryFileSystem(), "/repo/sentinel", "/repo");
    expect(resolved).toEqual({ ok: false, reason: "not-found" });
  });

  test("reports a directory that holds no runs", async () => {
    const fs = new MemoryFileSystem();
    await fs.mkdirp("/repo/sentinel");
    expect(await resolveRunDir(fs, "/repo/sentinel", "/repo")).toEqual({
      ok: false,
      reason: "no-latest",
    });
  });

  test("reports a pointer that exists but is unusable", async () => {
    const fs = new MemoryFileSystem();
    await fs.mkdirp("/repo/sentinel");
    await fs.writeFile("/repo/sentinel/.latest", "garbage\n");
    expect(await resolveRunDir(fs, "/repo/sentinel", "/repo")).toEqual({
      ok: false,
      reason: "not-a-run-dir",
    });
  });
});
