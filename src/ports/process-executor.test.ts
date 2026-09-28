import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createFileSystem } from "./file-system.ts";
import {
  EXIT_NOT_FOUND,
  createProcessExecutor,
  createStubProcessExecutor,
} from "./process-executor.ts";

const fs = createFileSystem();
const executor = createProcessExecutor();
const bun = process.execPath;
let root = "";

beforeAll(async () => {
  root = join(tmpdir(), `sentinel-proc-${Date.now().toString(36)}-${process.pid.toString(36)}`);
  await fs.mkdirp(root);
});

afterAll(async () => {
  await executor.killAll("SIGKILL");
  await fs.remove(root);
});

describe("run", () => {
  test("captures stdout of a successful command", async () => {
    const result = await executor.run(bun, ["-e", 'console.log("hi")'], { timeoutMs: 20_000 });
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe("hi");
    expect(result.stderr).toBe("");
    expect(result.timedOut).toBe(false);
    expect(result.truncated).toBe(false);
    expect(result.notFound).toBe(false);
    expect(result.killed).toBe(false);
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });

  test("reports a non-zero exit with its stderr", async () => {
    const result = await executor.run("/bin/sh", ["-c", "echo oops 1>&2; exit 3"], {
      timeoutMs: 20_000,
    });
    expect(result.exitCode).toBe(3);
    expect(result.stderr.trim()).toBe("oops");
    expect(result.notFound).toBe(false);
  });

  test("distinguishes a missing binary from a failing one", async () => {
    const result = await executor.run("sentinel-no-such-tool-9f3a", ["--version"], {
      timeoutMs: 20_000,
    });
    expect(result.notFound).toBe(true);
    expect(result.exitCode).toBe(EXIT_NOT_FOUND);
    expect(result.stderr).toContain("command not found");
  });

  test("honours cwd and environment overrides, including removals", async () => {
    const dir = join(root, "cwd-check");
    await fs.mkdirp(dir);
    process.env.SENTINEL_INHERITED = "from-parent";
    try {
      const result = await executor.run(
        bun,
        [
          "-e",
          "console.log(JSON.stringify([process.cwd(), process.env.SENTINEL_TOKEN ?? null, process.env.SENTINEL_INHERITED ?? null]))",
        ],
        {
          cwd: dir,
          env: { SENTINEL_TOKEN: "abc", SENTINEL_INHERITED: undefined },
          timeoutMs: 20_000,
        },
      );
      const [cwd, token, inherited] = JSON.parse(result.stdout) as [
        string,
        string | null,
        string | null,
      ];
      expect(await fs.realpath(cwd)).toBe(await fs.realpath(dir));
      expect(token).toBe("abc");
      expect(inherited).toBeNull();
    } finally {
      Reflect.deleteProperty(process.env, "SENTINEL_INHERITED");
    }
  });

  test("writes stdin to the child", async () => {
    const result = await executor.run("/bin/cat", [], { stdin: "piped input", timeoutMs: 20_000 });
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe("piped input");
  });
});

describe("timeout", () => {
  test("kills a child that outlives its budget", async () => {
    const started = performance.now();
    const result = await executor.run(bun, ["-e", "setTimeout(() => {}, 120000)"], {
      timeoutMs: 300,
    });
    const elapsed = performance.now() - started;

    expect(result.timedOut).toBe(true);
    expect(result.killed).toBe(true);
    expect(result.exitCode).not.toBe(0);
    expect(["SIGTERM", "SIGKILL"]).toContain(result.signal ?? "");
    expect(elapsed).toBeLessThan(15_000);
  }, 30_000);

  test("kills the whole process group, not just the direct child", async () => {
    // The shell backgrounds a grandchild that would outlive a naive kill(pid).
    const result = await executor.run("/bin/sh", ["-c", "sleep 30 & echo $!; sleep 30"], {
      timeoutMs: 500,
    });
    expect(result.timedOut).toBe(true);

    const grandchildPid = Number.parseInt(result.stdout.trim(), 10);
    expect(Number.isInteger(grandchildPid)).toBe(true);

    // Give the kernel a moment to reap the group before asking about it.
    let alive = true;
    for (let attempt = 0; attempt < 20 && alive; attempt += 1) {
      await Bun.sleep(100);
      const probe = await executor.run("/bin/ps", ["-p", String(grandchildPid)], {
        timeoutMs: 10_000,
      });
      alive = probe.exitCode === 0;
    }
    expect(alive).toBe(false);
  }, 30_000);
});

describe("output cap", () => {
  test("truncates instead of buffering everything the child prints", async () => {
    const result = await executor.run(
      "/bin/sh",
      [
        "-c",
        'i=0; while [ $i -lt 5000 ]; do echo "0123456789012345678901234567890123456789"; i=$((i+1)); done',
      ],
      { maxOutputBytes: 1_000, timeoutMs: 20_000 },
    );
    expect(result.exitCode).toBe(0);
    expect(result.truncated).toBe(true);
    expect(result.stdout.length).toBe(1_000);
    expect(result.stdout.startsWith("0123456789")).toBe(true);
  }, 30_000);

  test("does not flag truncation when the output fits", async () => {
    const result = await executor.run("/bin/sh", ["-c", "echo small"], {
      maxOutputBytes: 1_000,
      timeoutMs: 20_000,
    });
    expect(result.truncated).toBe(false);
    expect(result.stdout.trim()).toBe("small");
  });
});

describe("killAll", () => {
  test("reaps children that are still running", async () => {
    const scoped = createProcessExecutor();
    const marker = join(root, "ready.marker");
    await fs.remove(marker);

    const pending = scoped.run(bun, [
      "-e",
      `Bun.write(${JSON.stringify(marker)}, "ready"); setTimeout(() => {}, 120000)`,
    ]);

    let ready = false;
    for (let attempt = 0; attempt < 100 && !ready; attempt += 1) {
      await Bun.sleep(50);
      ready = await fs.exists(marker);
    }
    expect(ready).toBe(true);

    await scoped.killAll("SIGKILL");
    const result = await pending;
    expect(result.killed).toBe(true);
    expect(result.timedOut).toBe(false);
    expect(result.exitCode).toBe(137);
  }, 30_000);

  test("is a no-op when nothing is running", async () => {
    const scoped = createProcessExecutor();
    await scoped.killAll();
  });
});

describe("createStubProcessExecutor", () => {
  test("returns scripted output without spawning anything", async () => {
    const calls: string[] = [];
    const stub = createStubProcessExecutor((command, args) => {
      calls.push([command, ...args].join(" "));
      return command === "trivy" ? { stdout: '{"Results":[]}' } : { exitCode: 1, stderr: "nope" };
    });

    const good = await stub.run("trivy", ["fs", "."]);
    expect(good.exitCode).toBe(0);
    expect(good.stdout).toBe('{"Results":[]}');

    const bad = await stub.run("gitleaks", ["detect"]);
    expect(bad.exitCode).toBe(1);
    expect(bad.stderr).toBe("nope");
    expect(calls).toEqual(["trivy fs .", "gitleaks detect"]);
  });
});
