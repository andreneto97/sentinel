import { describe, expect, test } from "bun:test";
import { extractSnippet } from "./snippet.ts";

const SOURCE = [
  "export async function handler(req, res) {",
  "  const id = req.params.id;",
  "  const row = await db.user.findUnique({ where: { id } });",
  "  res.json(row);",
  "}",
];

const base = {
  contextLines: 1,
  maxLineWidth: 200,
  maxSnippetLines: 24,
  tabWidth: 2,
};

describe("extractSnippet", () => {
  test("marks the cited line and numbers the context", () => {
    const snippet = extractSnippet({ ...base, lines: SOURCE, line: 3 });
    expect(snippet).toBe(
      [
        "  2 | const id = req.params.id;",
        "> 3 | const row = await db.user.findUnique({ where: { id } });",
        "  4 | res.json(row);",
      ].join("\n"),
    );
  });

  test("marks every line of a cited range", () => {
    const snippet = extractSnippet({
      ...base,
      lines: SOURCE,
      line: 2,
      endLine: 3,
      contextLines: 0,
    });
    expect(snippet.split("\n").filter((line) => line.startsWith(">"))).toHaveLength(2);
  });

  test("clamps the window to the file", () => {
    const snippet = extractSnippet({ ...base, lines: SOURCE, line: 1, contextLines: 10 });
    expect(snippet.split("\n")).toHaveLength(5);
    expect(snippet.startsWith("> 1 |")).toBe(true);
  });

  test("strips common indentation and normalises tabs", () => {
    const nested = ["\t\tif (ok) {", "\t\t\tdoThing();", "\t\t}"];
    const snippet = extractSnippet({ ...base, lines: nested, line: 2, tabWidth: 4 });
    expect(snippet).toBe(["  1 | if (ok) {", "> 2 |     doThing();", "  3 | }"].join("\n"));
  });

  test("truncates an over-wide line", () => {
    const snippet = extractSnippet({
      ...base,
      lines: [`const sql = "${"x".repeat(400)}";`],
      line: 1,
      maxLineWidth: 20,
    });
    expect(snippet).toBe('> 1 | const sql = "xxxxxx…');
    expect(snippet.slice("> 1 | ".length)).toHaveLength(20);
  });

  test("never grows past the snippet cap", () => {
    const long = Array.from({ length: 200 }, (_, index) => `line ${index + 1}`);
    const snippet = extractSnippet({
      ...base,
      lines: long,
      line: 10,
      endLine: 180,
      maxSnippetLines: 6,
    });
    expect(snippet.split("\n")).toHaveLength(6);
  });

  test("pads the gutter so numbers line up", () => {
    const long = Array.from({ length: 120 }, (_, index) => `line ${index + 1}`);
    const snippet = extractSnippet({ ...base, lines: long, line: 100 });
    expect(snippet.split("\n")[0]).toBe("   99 | line 99");
  });

  test("returns nothing for an empty file", () => {
    expect(extractSnippet({ ...base, lines: [], line: 1 })).toBe("");
  });
});
