import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { createFileSystem } from "../ports/file-system.ts";
import {
  type SliceContext,
  budgetOf,
  createSourceCache,
  elisionMarker,
  loadSource,
  planSegments,
  renderSlice,
  resolveBlock,
  scanSource,
  sliceCode,
} from "./slice.ts";

const TARGET = join(import.meta.dir, "__fixtures__", "slice-target");

/** A context over the real fixture directory, read through the real port. */
function contextWith(budget?: SliceContext["budget"]): SliceContext {
  return {
    fs: createFileSystem(),
    targetDir: TARGET,
    ...(budget === undefined ? {} : { budget }),
    cache: createSourceCache(),
  };
}

/** The 1-based line numbers a rendered slice actually shows. */
function shownLines(text: string): number[] {
  const numbers: number[] = [];
  for (const line of text.split("\n")) {
    const match = /^\s*(\d+) \|/.exec(line);
    if (match?.[1] !== undefined) numbers.push(Number(match[1]));
  }
  return numbers;
}

describe("scanSource", () => {
  test("braces inside strings, templates, regexes and comments open no block", () => {
    const lines = [
      'const sql = "select { from } t";',
      'const tpl = `a ${x ? "{" : "}"} b`;',
      "const re = /^\\{[^}]*\\}$/u;",
      "// a trailing { in a comment",
      "/* another { one */",
      "function real() {",
      "  return 1;",
      "}",
    ];
    const structure = scanSource(lines);
    expect(structure.blocks).toEqual([{ startLine: 6, endLine: 8, depth: 0 }]);
  });

  test("a template interpolation is code again, so its braces nest correctly", () => {
    const lines = ["const t = `${ { a: 1 }.a }`;", "function after() {", "}"];
    const structure = scanSource(lines);
    // The object literal inside `${ … }` is a block; the interpolation itself is not.
    expect(structure.blocks).toEqual([
      { startLine: 1, endLine: 1, depth: 1 },
      { startLine: 2, endLine: 3, depth: 0 },
    ]);
    expect(structure.braceDepth[1]).toBe(0);
  });

  test("a division is not mistaken for a regular expression", () => {
    const lines = ["const ratio = total / count; // }", "function after() {", "}"];
    const structure = scanSource(lines);
    expect(structure.blocks).toEqual([{ startLine: 2, endLine: 3, depth: 0 }]);
  });

  test("an unclosed block still ends somewhere, so the file stays sliceable", () => {
    const structure = scanSource(["function broken() {", "  return 1;"]);
    expect(structure.blocks).toEqual([{ startLine: 1, endLine: 2, depth: 0 }]);
  });
});

describe("resolveBlock", () => {
  const lines = [
    "const before = 1;",
    "export async function wide(",
    "  first: string,",
    "): Promise<string> {",
    "  const joined = first;",
    "  return joined;",
    "}",
    'router.get("/x", (req, res) => {',
    "  res.json(1);",
    "});",
    "const after = 2;",
  ];
  const structure = scanSource(lines);

  test("a bare line resolves to its innermost enclosing block", () => {
    expect(resolveBlock(lines, structure, 5)).toEqual({ startLine: 2, endLine: 7 });
  });

  test("a multi-line signature is climbed, so the slice starts at the declaration", () => {
    expect(resolveBlock(lines, structure, 4)).toEqual({ startLine: 2, endLine: 7 });
  });

  test("an explicit range is taken as given", () => {
    expect(resolveBlock(lines, structure, 8, 10)).toEqual({ startLine: 8, endLine: 10 });
  });

  test("a top-level line with no enclosing block resolves to its own statement", () => {
    expect(resolveBlock(lines, structure, 11)).toEqual({ startLine: 11, endLine: 11 });
  });

  test("decorators directly above a block belong to it", () => {
    const decorated = [
      '@Get(":id")',
      "@UseGuards(AuthGuard)",
      "async findOne() {",
      "  return 1;",
      "}",
    ];
    const scanned = scanSource(decorated);
    expect(resolveBlock(decorated, scanned, 4)).toEqual({ startLine: 1, endLine: 5 });
  });
});

describe("planSegments", () => {
  const block = { startLine: 10, endLine: 109 };

  test("a block that fits is kept whole", () => {
    expect(planSegments(block, { startLine: 10, endLine: 10 }, 100)).toEqual([block]);
  });

  test("the citation always survives the cut", () => {
    const plan = planSegments(block, { startLine: 80, endLine: 82 }, 20);
    const covered = plan.some((range) => range.startLine <= 80 && range.endLine >= 82);
    expect(covered).toBe(true);
    const kept = plan.reduce((sum, range) => sum + range.endLine - range.startLine + 1, 0);
    expect(kept).toBe(20);
  });

  test("head and tail of the block are preferred over the lines around the citation", () => {
    const plan = planSegments(block, { startLine: 10, endLine: 10 }, 20);
    expect(plan[0]?.startLine).toBe(10);
    expect(plan[plan.length - 1]?.endLine).toBe(109);
  });

  test("budgets are never exceeded, however small", () => {
    for (const budget of [1, 2, 3, 7, 19, 99]) {
      const plan = planSegments(block, { startLine: 55, endLine: 60 }, budget);
      const kept = plan.reduce((sum, range) => sum + range.endLine - range.startLine + 1, 0);
      expect(kept).toBeLessThanOrEqual(budget);
    }
  });
});

describe("renderSlice", () => {
  const lines = Array.from({ length: 60 }, (_, index) => `  line ${index + 1};`);

  test("keeps real line numbers and names the file in a header", () => {
    const slice = renderSlice(
      "src/a.ts",
      lines,
      { startLine: 1, endLine: 60 },
      { startLine: 1, endLine: 1 },
      budgetOf({ maxLines: 200 }),
    );
    expect(slice.text.split("\n")[0]).toBe("// src/a.ts:1-60");
    expect(shownLines(slice.text)).toEqual(Array.from({ length: 60 }, (_, i) => i + 1));
    expect(slice.truncated).toBe(false);
    expect(slice.elidedLines).toBe(0);
  });

  test("marks every cut with the number of lines it removed", () => {
    const budget = budgetOf({ maxLines: 12 });
    const slice = renderSlice(
      "src/a.ts",
      lines,
      { startLine: 1, endLine: 60 },
      { startLine: 30, endLine: 30 },
      budget,
    );
    expect(slice.text.split("\n").length).toBeLessThanOrEqual(budget.maxLines);
    expect(slice.truncated).toBe(true);
    expect(shownLines(slice.text)).toContain(30);
    const elided = slice.text
      .split("\n")
      .filter((line) => line.startsWith("// …"))
      .map((line) => Number(/(\d+) line/.exec(line)?.[1] ?? 0));
    expect(elided.length).toBeGreaterThan(0);
    expect(elided.reduce((a, b) => a + b, 0)).toBe(slice.elidedLines);
    expect(shownLines(slice.text).length + slice.elidedLines).toBe(60);
  });

  test("the byte budget holds even when the line budget would not", () => {
    const budget = budgetOf({ maxLines: 200, maxBytes: 120 });
    const slice = renderSlice(
      "src/a.ts",
      lines,
      { startLine: 1, endLine: 60 },
      { startLine: 5, endLine: 5 },
      budget,
    );
    expect(slice.bytes).toBeLessThanOrEqual(120);
    expect(slice.bytes).toBe(Buffer.byteLength(slice.text, "utf8"));
    expect(slice.truncated).toBe(true);
  });

  test("an over-wide line is truncated instead of blowing the budget", () => {
    const wide = ["const x = 1;", `const y = "${"z".repeat(400)}";`, "const z = 2;"];
    const slice = renderSlice(
      "src/a.ts",
      wide,
      { startLine: 1, endLine: 3 },
      { startLine: 2, endLine: 2 },
      budgetOf({ maxLineWidth: 40 }),
    );
    for (const line of slice.text.split("\n")) expect(line.length).toBeLessThanOrEqual(60);
  });

  test("elisionMarker states the count in the exact shape the prompts rely on", () => {
    expect(elisionMarker(240)).toBe("// … 240 lines elided …");
    expect(elisionMarker(1)).toBe("// … 1 line elided …");
  });
});

describe("sliceCode", () => {
  test("extracts the enclosing function of a bare citation from disk", async () => {
    const result = await sliceCode({ file: "handlers.ts", line: 11 }, contextWith());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.slice.file).toBe("handlers.ts");
    expect(result.slice.startLine).toBe(10);
    expect(result.slice.endLine).toBe(13);
    expect(result.slice.text).toContain("export function shortHandler");
    expect(result.slice.truncated).toBe(false);
  });

  test("climbs over a signature spread across lines", async () => {
    const result = await sliceCode({ file: "handlers.ts", line: 21 }, contextWith());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.slice.startLine).toBe(17);
    expect(result.slice.text).toContain("export async function wideSignature(");
  });

  test("a long handler is elided in the middle, never cut silently at the end", async () => {
    const result = await sliceCode(
      { file: "handlers.ts", line: 27 },
      contextWith({ maxLines: 30 }),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const { slice } = result;
    expect(slice.startLine).toBe(26);
    expect(slice.endLine).toBe(189);
    expect(slice.text.split("\n").length).toBeLessThanOrEqual(30);
    expect(slice.text).toContain("lines elided");
    // The closing line of the function is still visible, so "no check here" is provable.
    expect(shownLines(slice.text)).toContain(189);
    expect(shownLines(slice.text)).toContain(27);
  });

  test("a top-level registration slices as one statement", async () => {
    const result = await sliceCode({ file: "handlers.ts", line: 192 }, contextWith());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.slice.startLine).toBe(192);
    expect(result.slice.endLine).toBe(195);
  });

  test("a citation outside the repository is refused", async () => {
    const result = await sliceCode({ file: "../outside.ts", line: 1 }, contextWith());
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("path-escape");
  });

  test("a missing file and an impossible line are refused with their reasons", async () => {
    const missing = await sliceCode({ file: "nope.ts", line: 1 }, contextWith());
    expect(missing.ok).toBe(false);
    if (!missing.ok) expect(missing.reason).toBe("file-not-found");

    const far = await sliceCode({ file: "handlers.ts", line: 9_000 }, contextWith());
    expect(far.ok).toBe(false);
    if (!far.ok) expect(far.reason).toBe("line-out-of-range");
  });

  test("a file is read once per cache, however many units cite it", async () => {
    const real = createFileSystem();
    let reads = 0;
    const ctx: SliceContext = {
      fs: {
        readFileBytes: async (path: string) => {
          reads += 1;
          return await real.readFileBytes(path);
        },
        realpath: (path: string) => real.realpath(path),
      },
      targetDir: TARGET,
      cache: createSourceCache(),
    };
    await sliceCode({ file: "handlers.ts", line: 11 }, ctx);
    await sliceCode({ file: "handlers.ts", line: 27 }, ctx);
    await loadSource("handlers.ts", ctx);
    expect(reads).toBe(1);
  });
});
