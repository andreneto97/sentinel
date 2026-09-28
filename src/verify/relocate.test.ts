import { describe, expect, test } from "bun:test";
import { buildNeedles, fuzzyRelocate, lineMatchesAnyNeedle } from "./relocate.ts";

const LINES = [
  "import { db } from './db';",
  "",
  "export async function listOrders(req, res) {",
  "  const rows = await db.order.findMany();",
  "  res.json(rows);",
  "}",
];

describe("buildNeedles", () => {
  test("takes anchors from a snippet, longest first", () => {
    const needles = buildNeedles({ snippet: "  res.json(rows);\n  const rows = await db;" }, 2);
    expect(needles[0]).toBe("const rows = await db;");
    expect(needles).toContain("res.json(rows);");
  });

  test("strips a Sentinel gutter from a snippet fed back in", () => {
    expect(buildNeedles({ snippet: "> 12 |   res.json(rows);" }, 2)).toEqual(["res.json(rows);"]);
  });

  test("accepts a symbol but refuses noise", () => {
    expect(buildNeedles({ symbol: "listOrders" }, 2)).toEqual(["listOrders"]);
    expect(buildNeedles({ symbol: "db" }, 2)).toEqual([]);
    expect(buildNeedles({ symbol: "not a symbol" }, 2)).toEqual([]);
    expect(buildNeedles({ snippet: "}\n});\n  " }, 2)).toEqual([]);
  });
});

describe("lineMatchesAnyNeedle", () => {
  test("matches through tab indentation", () => {
    expect(lineMatchesAnyNeedle("\tres.json(rows);", ["res.json(rows);"], 2)).toBe(true);
    expect(lineMatchesAnyNeedle("res.send();", ["res.json(rows);"], 2)).toBe(false);
  });
});

describe("fuzzyRelocate", () => {
  test("corrects a line that drifted", () => {
    const moved = fuzzyRelocate({
      lines: LINES,
      line: 2,
      needles: ["const rows = await db.order.findMany();"],
      window: 50,
      tabWidth: 2,
    });
    expect(moved).toEqual({ line: 4, needle: "const rows = await db.order.findMany();" });
  });

  test("refuses an ambiguous anchor", () => {
    const duplicated = ["a();", "  res.json(rows);", "b();", "  res.json(rows);"];
    expect(
      fuzzyRelocate({
        lines: duplicated,
        line: 1,
        needles: ["res.json(rows);"],
        window: 50,
        tabWidth: 2,
      }),
    ).toBe(null);
  });

  test("refuses when two anchors disagree", () => {
    expect(
      fuzzyRelocate({
        lines: LINES,
        line: 1,
        needles: ["res.json(rows);", "listOrders"],
        window: 50,
        tabWidth: 2,
      }),
    ).toBe(null);
  });

  test("ignores anything outside the window", () => {
    const long = [...Array.from({ length: 200 }, () => "filler();"), "const target = compute();"];
    expect(
      fuzzyRelocate({
        lines: long,
        line: 1,
        needles: ["const target = compute();"],
        window: 50,
        tabWidth: 2,
      }),
    ).toBe(null);
  });

  test("centres the window on the last line when the citation is past EOF", () => {
    const moved = fuzzyRelocate({
      lines: LINES,
      line: 900,
      needles: ["listOrders"],
      window: 50,
      tabWidth: 2,
    });
    expect(moved?.line).toBe(3);
  });

  test("returns null without anchors", () => {
    expect(fuzzyRelocate({ lines: LINES, line: 1, needles: [], window: 50, tabWidth: 2 })).toBe(
      null,
    );
  });
});
