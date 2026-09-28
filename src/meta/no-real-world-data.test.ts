import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { createFileSystem } from "../ports/file-system.ts";
import {
  EXEMPT_FILES,
  LEAK_SHAPES,
  PLACEHOLDER_OWNERS,
  PUBLISHED_PLACEHOLDERS,
  collectFiles,
  findLeaks,
  formatLeak,
  scanText,
} from "./_leak-shapes.ts";

/**
 * The guard that stops another repository's data from being published inside
 * this one.
 *
 * Three pre-publication reviews rejected this tree — once for identifiers, once
 * for knowledge baked into fixtures, once for case histories in prose — and each
 * round found a category the last one had not thought of. This test is the first
 * thing in the repository that *enforces* the rule instead of restating it:
 * every file is read, every shape in `_leak-shapes.ts` is applied, and each hit
 * is reported with its file, its line, the matched text and the reason that
 * shape is a leak.
 *
 * Three groups below, and they earn their keep in different ways:
 *
 * 1. **The shapes work.** Each one is asserted against a witness it must flag
 *    and the legitimate neighbour it must not. A pattern that silently stops
 *    matching is the way a guard like this dies, and this is what catches it.
 * 2. **The walk is exhaustive.** A guard that quietly stopped reading fixtures
 *    would pass forever. The walk is asserted to reach every kind of file the
 *    earlier leaks arrived in, and to stay out of `node_modules` and `.git`.
 * 3. **The tree is clean.** One assertion over the whole repository.
 *
 * And a fourth: the allowlists are asserted to be small, so that widening one is
 * a visible act in a diff rather than a quiet one.
 */

const disk = createFileSystem();

/** This file sits at `src/meta/`, so the repository root is two levels up. */
const REPO_ROOT = join(import.meta.dir, "..", "..");

describe("every shape flags what it is for and nothing beside it", () => {
  for (const shape of LEAK_SHAPES) {
    test(`${shape.id} flags its witness`, () => {
      // A `.md` name so the prose-scoped shapes apply to their own witness.
      const hits = scanText("witness.md", shape.witness, [shape]);
      expect(hits.length).toBeGreaterThanOrEqual(1);
    });

    test(`${shape.id} leaves its near miss alone`, () => {
      expect(scanText("near-miss.md", shape.nearMiss, [shape])).toEqual([]);
    });
  }

  test("every shape is complete enough to act on", () => {
    const ids = LEAK_SHAPES.map((shape) => shape.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const shape of LEAK_SHAPES) {
      expect(shape.pattern.flags).toContain("g");
      // The reason is what turns a failure into a fix rather than a suppression,
      // so a one-word `why` is a broken shape.
      expect(shape.why.length).toBeGreaterThan(60);
      expect(shape.witness.length).toBeGreaterThan(0);
      expect(shape.nearMiss.length).toBeGreaterThan(0);
    }
  });
});

/** The walk, taken once: every assertion below reads the same list. */
const files = await collectFiles(disk, REPO_ROOT);

describe("the walk covers the whole repository", () => {
  test("it reaches every kind of file the earlier leaks arrived in", () => {
    // Each of these is a category an earlier round leaked through: prose, a
    // tracked config, a vendor report replayed as a fixture, infrastructure
    // declarations, SQL, and a dot-directory nobody globs for.
    const required = [
      "README.md",
      "PLAN.md",
      "package.json",
      ".gitignore",
      ".claude/commands/sentinel.md",
      "assets/rules/opengrep/xss.yaml",
      "src/scan/parsers/__fixtures__/gitleaks-report.sarif",
      "src/inventory/__fixtures__/async-target/serverless.yml",
      "src/inventory/__fixtures__/async-target/supabase/config.toml",
      "src/inventory/__fixtures__/data-layer-target/prisma/schema.prisma",
      "src/scan/__fixtures__/target/Dockerfile",
      "src/inventory/__fixtures__/data-layer-target/supabase/migrations/20240301000000_drop_legacy.sql",
    ];
    expect(required.filter((file) => !files.includes(file))).toEqual([]);
  });

  test("it is a whole-tree walk, not a sample", () => {
    expect(files.length).toBeGreaterThan(500);
    // Not only source. Two of the three rejected rounds arrived in something
    // that is not a `.ts` file, so a walk that had narrowed to code would be
    // blind to them, and this is the assertion that notices.
    const extensions = new Set(files.map((file) => file.replace(/^.*\./, "")));
    expect(extensions.size).toBeGreaterThan(8);
  });

  test("it stays out of dependencies, history and build output", () => {
    const forbidden = files.filter((file) =>
      /(?:^|\/)(?:node_modules|\.git|dist|sentinel-out)\//.test(file),
    );
    expect(forbidden).toEqual([]);
  });

  test("the only skipped file is the one that defines the shapes", () => {
    expect(EXEMPT_FILES.map(([file]) => file)).toEqual(["src/meta/_leak-shapes.ts"]);
    expect(files).not.toContain("src/meta/_leak-shapes.ts");
    // The test that applies the shapes is *not* exempt: it is walked like
    // anything else, so a value pasted into it fails the build too.
    expect(files).toContain("src/meta/no-real-world-data.test.ts");
  });
});

describe("the allowlists stay small enough to audit at a glance", () => {
  test("every entry carries a reason", () => {
    for (const [literal, reason] of [
      ...PUBLISHED_PLACEHOLDERS,
      ...PLACEHOLDER_OWNERS,
      ...EXEMPT_FILES,
    ]) {
      expect(literal.length).toBeGreaterThan(0);
      expect(reason.length).toBeGreaterThan(20);
    }
  });

  test("the lists are bounded, so widening one has to be argued for here", () => {
    // These bounds are the audit. Raising one is a line in a diff that a
    // reviewer will ask about, which is the only mechanism that has worked.
    expect(PUBLISHED_PLACEHOLDERS.length).toBeLessThanOrEqual(6);
    expect(PLACEHOLDER_OWNERS.length).toBeLessThanOrEqual(24);
    expect(EXEMPT_FILES.length).toBe(1);
  });
});

describe("the repository carries no real-world data", () => {
  test("no file holds a marker of somebody else's codebase", async () => {
    const leaks = await findLeaks(disk, REPO_ROOT);
    const report =
      leaks.length === 0
        ? ""
        : [
            `${leaks.length} marker(s) of a real-world codebase:`,
            ...leaks.map(formatLeak),
            "",
            "Fix the file, do not widen the allowlist: every one of these shapes",
            "exists because a review found it in this tree already.",
          ].join("\n");
    expect(report).toBe("");
  });
});
