import { describe, expect, test } from "bun:test";
import { FakeClock } from "./clock.ts";
import { createJsonLogger, createMemoryLogger, parseLogThreshold, silentLogger } from "./logger.ts";

/** Collects the lines a logger writes, so the wire format can be asserted. */
function capture() {
  const lines: string[] = [];
  return { lines, write: (line: string) => void lines.push(line) };
}

describe("createJsonLogger", () => {
  test("writes one JSON object per line with level, message and fields", () => {
    const { lines, write } = capture();
    const clock = new FakeClock(Date.UTC(2026, 0, 2, 3, 4, 5));
    const logger = createJsonLogger({ level: "debug", write, clock });

    logger.info("scan finished", { tool: "trivy", findings: 12 });

    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0] ?? "")).toEqual({
      ts: "2026-01-02T03:04:05.000Z",
      level: "info",
      msg: "scan finished",
      tool: "trivy",
      findings: 12,
    });
  });

  test("drops lines below the threshold", () => {
    const { lines, write } = capture();
    const logger = createJsonLogger({ level: "warn", write });

    logger.debug("noise");
    logger.info("noise");
    logger.warn("careful");
    logger.error("broken");

    expect(lines.map((line) => JSON.parse(line).level)).toEqual(["warn", "error"]);
    expect(logger.enabled("info")).toBe(false);
    expect(logger.enabled("warn")).toBe(true);
  });

  test("child loggers merge their bound fields and keep the threshold", () => {
    const { lines, write } = capture();
    const logger = createJsonLogger({ level: "info", write, base: { runId: "r1" } });
    const phase = logger.child({ phase: "scan" });
    const tool = phase.child({ tool: "knip" });

    tool.info("started", { batch: 3 });
    phase.info("done");

    expect(JSON.parse(lines[0] ?? "")).toMatchObject({
      runId: "r1",
      phase: "scan",
      tool: "knip",
      batch: 3,
      msg: "started",
    });
    expect(JSON.parse(lines[1] ?? "")).toMatchObject({ runId: "r1", phase: "scan", msg: "done" });
    expect(JSON.parse(lines[1] ?? "").tool).toBeUndefined();
  });

  test("serialises errors instead of dropping them to an empty object", () => {
    const { lines, write } = capture();
    const logger = createJsonLogger({ level: "error", write });

    logger.error("tool crashed", { error: new TypeError("bad json") });

    const parsed = JSON.parse(lines[0] ?? "");
    expect(parsed.error.name).toBe("TypeError");
    expect(parsed.error.message).toBe("bad json");
    expect(typeof parsed.error.stack).toBe("string");
  });

  test("survives circular structures and bigint fields", () => {
    const { lines, write } = capture();
    const logger = createJsonLogger({ level: "info", write });
    const cyclic: Record<string, unknown> = { name: "loop" };
    cyclic.self = cyclic;

    logger.info("weird payload", { cyclic, size: 9_007_199_254_740_993n });

    const parsed = JSON.parse(lines[0] ?? "");
    expect(parsed.cyclic.name).toBe("loop");
    expect(parsed.cyclic.self).toBe("[circular]");
    expect(parsed.size).toBe("9007199254740993");
  });
});

describe("silentLogger", () => {
  test("emits nothing at any level", () => {
    silentLogger.debug("a");
    silentLogger.info("b");
    silentLogger.warn("c");
    silentLogger.error("d");
    silentLogger.child({ phase: "x" }).error("e");
    expect(silentLogger.enabled("error")).toBe(false);
  });
});

describe("createMemoryLogger", () => {
  test("records structured lines for assertions", () => {
    const { logger, records } = createMemoryLogger({ clock: new FakeClock(0) });
    logger.child({ phase: "audit" }).warn("batch retried", { attempt: 2 });

    expect(records).toHaveLength(1);
    expect(records[0]?.level).toBe("warn");
    expect(records[0]?.message).toBe("batch retried");
    expect(records[0]?.fields).toEqual({ phase: "audit", attempt: 2 });
    expect(records[0]?.ts).toBe("1970-01-01T00:00:00.000Z");
  });
});

describe("parseLogThreshold", () => {
  test("accepts known levels, case-insensitively, and falls back otherwise", () => {
    expect(parseLogThreshold("debug", "info")).toBe("debug");
    expect(parseLogThreshold("WARN", "info")).toBe("warn");
    expect(parseLogThreshold("silent", "info")).toBe("silent");
    expect(parseLogThreshold(undefined, "info")).toBe("info");
    expect(parseLogThreshold("verbose", "info")).toBe("info");
  });
});
