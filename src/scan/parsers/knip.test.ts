import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { type KnipCandidate, knipCandidates, parseKnipReport } from "./knip.ts";

/** Real `knip 6.37.0 --reporter json` output, captured from a demo repository. */
const REPORT = await Bun.file(join(import.meta.dir, "__fixtures__/knip-report.json")).text();

/** Real output carrying the one category the demo repository cannot produce. */
const UNRESOLVED = await Bun.file(
  join(import.meta.dir, "__fixtures__/knip-unresolved.json"),
).text();

/** Parses a fixture, failing the test rather than the suite when it does not. */
function candidatesOf(raw: string): KnipCandidate[] {
  const report = parseKnipReport(raw);
  if (!report.ok) throw new Error(report.error);
  return knipCandidates(report.value);
}

describe("parseKnipReport", () => {
  test("accepts real knip output", () => {
    const report = parseKnipReport(REPORT);
    expect(report.ok).toBe(true);
    if (report.ok) expect(report.value.issues).toHaveLength(4);
  });

  test("refuses output that is not JSON instead of throwing", () => {
    const report = parseKnipReport("knip: command failed\n");
    expect(report.ok).toBe(false);
    if (!report.ok) expect(report.error).toContain("knip did not produce valid JSON");
  });

  test("refuses JSON of the wrong shape", () => {
    const report = parseKnipReport('{"issues": "none"}');
    expect(report.ok).toBe(false);
    if (!report.ok) expect(report.error).toContain("unexpected shape");
  });

  test("skips the banner a framework plugin prints ahead of the report", () => {
    // Real knip 6.37.0 stdout from a Next.js repository: the env loader speaks
    // first, and its own braces must not be mistaken for the document.
    const banner =
      "\u25c7 injected env (7) from .env.local // tip: enable debugging { debug: true }";
    const report = parseKnipReport(`${banner}\n{"issues":[{"file":"src/a.ts"}]}\n`);
    expect(report.ok).toBe(true);
    if (report.ok) expect(report.value.issues).toHaveLength(1);
  });

  test("a pretty-printed report behind a banner is still found whole", () => {
    const body = JSON.stringify({ issues: [{ file: "src/a.ts" }] }, null, 2);
    const report = parseKnipReport(`loading config { a: 1 }\n${body}\n`);
    expect(report.ok).toBe(true);
    if (report.ok) expect(report.value.issues).toHaveLength(1);
  });

  test("a genuinely malformed report still fails, banner or not", () => {
    const report = parseKnipReport('loading config { a: 1 }\n{"issues": [\n');
    expect(report.ok).toBe(false);
    if (!report.ok) expect(report.error).toContain("knip did not produce valid JSON");
  });

  test("a knip version that omits a category degrades to nothing found", () => {
    const report = parseKnipReport('{"issues":[{"file":"src/a.ts"}]}');
    expect(report.ok).toBe(true);
    if (report.ok) expect(knipCandidates(report.value)).toEqual([]);
  });
});

describe("knipCandidates", () => {
  test("flattens every category the demo repository produced", () => {
    expect(candidatesOf(REPORT)).toEqual([
      {
        kind: "unused-dependency",
        file: "package.json",
        line: 7,
        name: "left-pad",
      },
      {
        kind: "unused-dev-dependency",
        file: "package.json",
        line: 10,
        name: "rimraf",
      },
      {
        kind: "unused-export",
        file: "src/b.ts",
        line: 7,
        name: "neverUsed",
      },
      {
        kind: "unused-type-export",
        file: "src/b.ts",
        line: 9,
        name: "UnusedShape",
      },
      {
        kind: "unlisted-dependency",
        file: "src/index.ts",
        line: 1,
        name: "not-a-listed-package",
      },
      {
        kind: "unused-file",
        file: "src/orphan.ts",
        line: 1,
        name: "src/orphan.ts",
      },
    ]);
  });

  test("an unused file cites the file itself, not the group it was reported under", () => {
    const file = candidatesOf(REPORT).find((candidate) => candidate.kind === "unused-file");
    expect(file?.file).toBe("src/orphan.ts");
    expect(file?.line).toBe(1);
  });

  test("an entry with no position falls back to line 1", () => {
    expect(candidatesOf(UNRESOLVED)).toEqual([
      {
        kind: "unresolved-import",
        file: "tsconfig.json",
        line: 1,
        name: "bun-types",
      },
    ]);
  });
});
