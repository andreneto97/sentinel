import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createFileSystem } from "./file-system.ts";
import { createProcessExecutor } from "./process-executor.ts";

const fs = createFileSystem();
let root = "";

/** Unique scratch path under the OS temp dir, so tests never collide. */
function scratch(name: string): string {
  return join(root, `${name}-${Math.random().toString(36).slice(2, 8)}`);
}

beforeAll(async () => {
  root = join(tmpdir(), `sentinel-fs-${Date.now().toString(36)}-${process.pid.toString(36)}`);
  await fs.mkdirp(root);
});

afterAll(async () => {
  await fs.remove(root);
});

describe("readFile / writeFile", () => {
  test("round-trips text and creates missing parent directories", async () => {
    const path = join(scratch("nested"), "deep", "report.md");
    await fs.writeFile(path, "# dossier\n");
    expect(await fs.readFile(path)).toBe("# dossier\n");
  });

  test("round-trips bytes", async () => {
    const path = scratch("bytes.bin");
    await fs.writeFile(path, new Uint8Array([0, 1, 2, 255]));
    expect([...(await fs.readFileBytes(path))]).toEqual([0, 1, 2, 255]);
  });

  test("leaves no temp file behind on success", async () => {
    const dir = scratch("clean");
    await fs.mkdirp(dir);
    await fs.writeFile(join(dir, "findings.json"), "{}");
    await fs.writeFile(join(dir, "findings.json"), '{"v":2}');
    const names = (await fs.readDir(dir)).map((entry) => entry.name);
    expect(names).toEqual(["findings.json"]);
    expect(await fs.readFile(join(dir, "findings.json"))).toBe('{"v":2}');
  });

  test("stages through a temp file, so the destination is never partial", async () => {
    const dir = scratch("atomic");
    await fs.mkdirp(dir);
    const destination = join(dir, "findings.json");
    const oldSize = 4 * 1024 * 1024;
    const newSize = 32 * 1024 * 1024;
    await fs.writeFile(destination, "O".repeat(oldSize));

    // Payload big enough that the staged write is in flight for milliseconds
    // while this process watches the directory.
    const writerPath = join(dir, "big-writer.ts");
    await fs.writeFile(
      writerPath,
      [
        `import { createFileSystem } from ${JSON.stringify(join(import.meta.dir, "file-system.ts"))};`,
        "const fs = createFileSystem();",
        `const payload = "N".repeat(${newSize});`,
        "for (let round = 0; round < 2; round += 1) {",
        "  await fs.writeFile(process.argv[2], payload);",
        "}",
      ].join("\n"),
    );

    const executor = createProcessExecutor();
    const pending = executor.run(process.execPath, [writerPath, destination], {
      timeoutMs: 60_000,
    });
    let finished = false;
    const stop = () => {
      finished = true;
    };
    void pending.then(stop, stop);

    let sawTempFile = false;
    const observedSizes = new Set<number>();
    while (!finished) {
      for (const entry of await fs.readDir(dir)) {
        if (entry.name.endsWith(".sentinel-tmp")) sawTempFile = true;
      }
      const stats = await fs.stat(destination);
      if (stats !== null) observedSizes.add(stats.size);
    }

    const result = await pending;
    expect(result.exitCode).toBe(0);
    // The staged file is what makes the replacement atomic; an in-place write
    // would never produce one.
    expect(sawTempFile).toBe(true);
    // Seeing both sizes proves the watch really spanned the write.
    expect(observedSizes.has(oldSize)).toBe(true);
    expect(observedSizes.has(newSize)).toBe(true);
    expect([...observedSizes].filter((size) => size !== oldSize && size !== newSize)).toEqual([]);
    expect((await fs.readDir(dir)).some((entry) => entry.name.endsWith(".sentinel-tmp"))).toBe(
      false,
    );
  }, 60_000);

  test("a crash between temp file and rename leaves the destination intact", async () => {
    const dir = scratch("crash");
    await fs.mkdirp(dir);
    const destination = join(dir, "findings.json");
    await fs.writeFile(destination, "OLD");

    // The child starts an atomic write and is SIGKILLed in the same synchronous
    // turn, so the rename cannot possibly have run.
    const script = [
      `import { createFileSystem } from ${JSON.stringify(join(import.meta.dir, "file-system.ts"))};`,
      "const fs = createFileSystem();",
      'void fs.writeFile(process.argv[2], "NEW".repeat(200000));',
      'process.kill(process.pid, "SIGKILL");',
    ].join("\n");
    const scriptPath = join(dir, "crash-writer.ts");
    await fs.writeFile(scriptPath, script);

    const executor = createProcessExecutor();
    const result = await executor.run(process.execPath, [scriptPath, destination], {
      timeoutMs: 20_000,
    });

    expect(result.signal).toBe("SIGKILL");
    expect(await fs.readFile(destination)).toBe("OLD");

    // Anything the crash left behind is a hidden temp file, never the destination.
    const leftovers = (await fs.readDir(dir))
      .map((entry) => entry.name)
      .filter((name) => name !== "findings.json" && name !== "crash-writer.ts");
    for (const name of leftovers) {
      expect(name.startsWith(".")).toBe(true);
    }
  });
});

describe("directories and metadata", () => {
  test("mkdirp is idempotent and exists follows it", async () => {
    const dir = join(scratch("mk"), "a", "b");
    await fs.mkdirp(dir);
    await fs.mkdirp(dir);
    expect(await fs.exists(dir)).toBe(true);
    expect(await fs.exists(join(dir, "nope"))).toBe(false);
  });

  test("stat reports size, mtime and kind, and null for a missing path", async () => {
    const path = scratch("stat.txt");
    await fs.writeFile(path, "12345");
    const stats = await fs.stat(path);
    expect(stats?.size).toBe(5);
    expect(stats?.isFile).toBe(true);
    expect(stats?.isDirectory).toBe(false);
    expect(stats?.mtimeMs).toBeGreaterThan(0);

    const dirStats = await fs.stat(root);
    expect(dirStats?.isDirectory).toBe(true);
    expect(await fs.stat(join(root, "definitely-missing"))).toBeNull();
  });

  test("readDir returns entries sorted by name", async () => {
    const dir = scratch("listing");
    await fs.mkdirp(join(dir, "zeta"));
    await fs.writeFile(join(dir, "beta.ts"), "");
    await fs.writeFile(join(dir, "alpha.ts"), "");
    const entries = await fs.readDir(dir);
    expect(entries.map((entry) => entry.name)).toEqual(["alpha.ts", "beta.ts", "zeta"]);
    expect(entries[2]?.isDirectory).toBe(true);
    expect(entries[0]?.isFile).toBe(true);
  });

  test("glob matches across patterns, de-duplicated and sorted", async () => {
    const dir = scratch("glob");
    await fs.writeFile(join(dir, "src", "a.ts"), "");
    await fs.writeFile(join(dir, "src", "b.js"), "");
    await fs.writeFile(join(dir, "src", "nested", "c.ts"), "");
    await fs.writeFile(join(dir, ".hidden", "d.ts"), "");

    expect(await fs.glob("**/*.ts", { cwd: dir })).toEqual(["src/a.ts", "src/nested/c.ts"]);
    expect(await fs.glob(["**/*.ts", "**/*.js", "**/*.ts"], { cwd: dir })).toEqual([
      "src/a.ts",
      "src/b.js",
      "src/nested/c.ts",
    ]);
    expect(await fs.glob("**/*.ts", { cwd: dir, dot: true })).toContain(".hidden/d.ts");
    const absolute = await fs.glob("src/a.ts", { cwd: dir, absolute: true });
    expect(absolute[0]?.endsWith(join("src", "a.ts"))).toBe(true);
  });

  test("remove deletes recursively and ignores a missing path", async () => {
    const dir = scratch("rm");
    await fs.writeFile(join(dir, "a", "b.txt"), "x");
    await fs.remove(dir);
    expect(await fs.exists(dir)).toBe(false);
    await fs.remove(dir);
  });

  test("realpath resolves . and .. segments", async () => {
    const dir = scratch("real");
    await fs.mkdirp(join(dir, "sub"));
    expect(await fs.realpath(join(dir, "sub", "..", "sub"))).toBe(
      await fs.realpath(join(dir, "sub")),
    );
  });

  test("isExecutable follows chmod", async () => {
    const path = scratch("tool.sh");
    await fs.writeFile(path, "#!/bin/sh\nexit 0\n");
    await fs.chmod(path, 0o644);
    expect(await fs.isExecutable(path)).toBe(false);
    await fs.chmod(path, 0o755);
    expect(await fs.isExecutable(path)).toBe(true);
    expect(await fs.isExecutable(join(root, "missing-binary"))).toBe(false);
  });
});

describe("readLines", () => {
  test("returns a 1-indexed inclusive slice", async () => {
    const path = scratch("lines.ts");
    await fs.writeFile(path, "one\ntwo\nthree\nfour\nfive\n");
    expect(await fs.readLines(path, 1, 1)).toEqual(["one"]);
    expect(await fs.readLines(path, 2, 4)).toEqual(["two", "three", "four"]);
    expect(await fs.readLines(path, 5, 5)).toEqual(["five"]);
  });

  test("keeps the last line when the file has no trailing newline", async () => {
    const path = scratch("no-newline.ts");
    await fs.writeFile(path, "alpha\nomega");
    expect(await fs.readLines(path, 2, 2)).toEqual(["omega"]);
    expect(await fs.readLines(path, 1, Number.POSITIVE_INFINITY)).toEqual(["alpha", "omega"]);
  });

  test("strips CRLF carriage returns", async () => {
    const path = scratch("crlf.ts");
    await fs.writeFile(path, "const a = 1;\r\nconst b = 2;\r\n");
    expect(await fs.readLines(path, 1, 2)).toEqual(["const a = 1;", "const b = 2;"]);
  });

  test("clamps instead of throwing when the range runs past EOF", async () => {
    const path = scratch("short.ts");
    await fs.writeFile(path, "only\n");
    expect(await fs.readLines(path, 1, 99)).toEqual(["only"]);
    expect(await fs.readLines(path, 50, 60)).toEqual([]);
  });

  test("handles an empty file", async () => {
    const path = scratch("empty.ts");
    await fs.writeFile(path, "");
    expect(await fs.readLines(path, 1, 10)).toEqual([]);
  });

  test("reads a slice out of the middle of a large file", async () => {
    const path = scratch("large.ts");
    const total = 100_000;
    const content = `${Array.from({ length: total }, (_, index) => `line ${index + 1}`).join("\n")}\n`;
    await fs.writeFile(path, content);

    expect(await fs.readLines(path, 50_000, 50_002)).toEqual([
      "line 50000",
      "line 50001",
      "line 50002",
    ]);
    expect(await fs.readLines(path, total, total)).toEqual([`line ${total}`]);
    expect(await fs.readLines(path, 1, 2)).toEqual(["line 1", "line 2"]);
  });

  test("rejects a non 1-indexed or inverted range", async () => {
    const path = scratch("range.ts");
    await fs.writeFile(path, "a\nb\n");
    await expect(fs.readLines(path, 0, 2)).rejects.toThrow(RangeError);
    await expect(fs.readLines(path, 3, 2)).rejects.toThrow(RangeError);
    await expect(fs.readLines(path, 1.5, 2)).rejects.toThrow(RangeError);
  });
});
