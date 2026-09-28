import { describe, expect, test } from "bun:test";
import {
  citation,
  formatCount,
  formatDate,
  formatDuration,
  formatTimestamp,
  humanise,
  monoColumns,
  parseSnippet,
  plural,
  repositoryName,
  shortenPath,
  toWinAnsi,
  truncateEnd,
  truncateStart,
  wrapMonospace,
} from "./text.ts";

/**
 * A snippet in the shape the verifier hands to the renderer: a numbered gutter,
 * a `>` on the cited line, and a blank line in the middle. Those three things
 * are what the parser has to survive, so the fixture carries all of them rather
 * than a tidy block of code.
 */
const SNIPPET =
  '  23 | if (!parsed.success) return validationFailed(parsed.error, values);\n  24 |\n  25 | const identity = await createIdentityClient();\n> 26 | const ok = await identity.verifyPassword(parsed.data.email, password);\n  27 | if (!ok) return { message: "Invalid credentials." };';

describe("toWinAnsi", () => {
  test("keeps the Latin-1 accents, which WinAnsi does encode", () => {
    expect(toWinAnsi('return { message: "Référence inconnue." };')).toBe(
      'return { message: "Référence inconnue." };',
    );
  });

  test("keeps the typographic characters WinAnsi does encode", () => {
    expect(toWinAnsi("a — b … “c” • €")).toBe("a — b … “c” • €");
  });

  test("replaces what the base-14 fonts cannot print, instead of dropping it", () => {
    expect(toWinAnsi("check ✓ 中文 🚀")).toBe("check ? ?? ?");
  });

  test("expands tabs and strips control characters, but keeps newlines", () => {
    expect(toWinAnsi("a\tb\u0000c\nd")).toBe("a  bc\nd");
  });
});

describe("parseSnippet", () => {
  test("splits the verifier's gutter away from the code and marks the cited line", () => {
    const rows = parseSnippet(SNIPPET, { maxChars: 80 });
    expect(rows.map((row) => row.gutter)).toEqual(["23", "24", "25", "26", "27"]);
    expect(rows.map((row) => row.cited)).toEqual([false, false, false, true, false]);
    expect(rows[3]?.code).toBe(
      "const ok = await identity.verifyPassword(parsed.data.email, password);",
    );
    expect(rows[1]?.code).toBe("");
  });

  test("wraps an over-wide line instead of truncating the evidence", () => {
    const long = `  10 | ALTER TABLE "order_items" ADD CONSTRAINT "${"x".repeat(120)}"`;
    const rows = parseSnippet(long, { maxChars: 60 });
    expect(rows.length).toBeGreaterThan(1);
    expect(rows[0]?.gutter).toBe("10");
    expect(rows[1]?.gutter).toBe("");
    expect(rows[1]?.wrapped).toBe(true);
    expect(rows.map((row) => row.code).join("")).toContain("x".repeat(60));
    expect(rows.every((row) => row.code.length <= 60)).toBe(true);
  });

  test("a wrapped continuation inherits the cited flag of the line it continues", () => {
    const rows = parseSnippet(`> 7 | ${"a".repeat(100)}`, { maxChars: 40 });
    expect(rows).toHaveLength(3);
    expect(rows.every((row) => row.cited)).toBe(true);
  });

  test("numbers a snippet that carries no gutter from the cited line", () => {
    const rows = parseSnippet("const key = [REDACTED];\nconst other = 1;", {
      maxChars: 80,
      firstLine: 4,
    });
    expect(rows.map((row) => row.gutter)).toEqual(["4", "5"]);
    expect(rows[0]?.code).toBe("const key = [REDACTED];");
  });

  test("caps the block and says how much it did not show", () => {
    const many = Array.from({ length: 20 }, (_, index) => `  ${index + 1} | line`).join("\n");
    const rows = parseSnippet(many, { maxChars: 80, maxLines: 6 });
    expect(rows).toHaveLength(7);
    expect(rows.at(-1)?.code).toBe("... 14 more line(s) in the file");
  });

  test("an empty snippet renders nothing at all", () => {
    expect(parseSnippet("", { maxChars: 80 })).toEqual([]);
    expect(parseSnippet("\n\n", { maxChars: 80 })).toEqual([]);
  });
});

describe("wrapMonospace", () => {
  test("keeps a line that fits", () => {
    expect(wrapMonospace("short", 10)).toEqual(["short"]);
  });

  test("breaks on a late space rather than mid-token", () => {
    expect(wrapMonospace("aaaaaaaa bbbbbb", 10)).toEqual(["aaaaaaaa", "bbbbbb"]);
  });

  test("breaks hard when no space falls near the budget", () => {
    expect(wrapMonospace("a".repeat(25), 10)).toEqual([
      "a".repeat(10),
      "a".repeat(10),
      "a".repeat(5),
    ]);
  });

  test("an early space is not a break: code has no words, only tokens", () => {
    expect(wrapMonospace("aa bbbbbbbbbbbb", 10)).toEqual(["aa bbbbbbb", "bbbbb"]);
  });
});

describe("measurement", () => {
  test("monoColumns matches Courier's fixed advance", () => {
    expect(monoColumns(450, 7.5)).toBe(100);
  });
});

describe("shortening", () => {
  test("a path loses its head, a title loses its tail", () => {
    expect(truncateStart("src/api/sessions.ts", 15)).toBe(".../sessions.ts");
    expect(truncateEnd("Sign-in handler has no attempt limiter", 12)).toBe("Sign-in han…");
    expect(truncateStart("short.ts", 20)).toBe("short.ts");
  });

  test("a long target path keeps its first and last segments", () => {
    expect(shortenPath("/workspace/example-api/packages/api/src", 20)).toBe(
      "/workspace/.../packages/api/src",
    );
  });
});

describe("formatting", () => {
  test("citation renders a range only when there is one", () => {
    expect(citation("src/a.ts", 26)).toBe("src/a.ts:26");
    expect(citation("src/a.ts", 26, 26)).toBe("src/a.ts:26");
    expect(citation("src/a.ts", 26, 31)).toBe("src/a.ts:26-31");
  });

  test("the repository name is the last segment of the analysed path", () => {
    expect(repositoryName("/workspace/example-api")).toBe("example-api");
    expect(repositoryName("/workspace/example-api/")).toBe("example-api");
  });

  test("dates and durations read the way a reader expects", () => {
    const at = new Date("2026-03-04T09:30:00.000Z");
    expect(formatDate(at)).toBe("4 March 2026");
    expect(formatTimestamp(at)).toBe("2026-03-04 09:30 UTC");
    expect(formatDuration(645000)).toBe("10m 45s");
    expect(formatDuration(3000)).toBe("3s");
    expect(formatDuration(Number.NaN)).toBe("unknown");
  });

  test("counts, plurals and identifiers", () => {
    expect(formatCount(1234567)).toBe("1,234,567");
    expect(plural(1, "finding")).toBe("finding");
    expect(plural(0, "finding")).toBe("findings");
    // A noun ending in a sibilant takes `-es`; the bare `-s` default says "batchs".
    expect(plural(2, "batch")).toBe("batches");
    expect(plural(1, "batch")).toBe("batch");
    expect(plural(2, "box")).toBe("boxes");
    // An irregular plural is still the caller's to supply.
    expect(plural(2, "retry", "retries")).toBe("retries");
    expect(humanise("not-assessed")).toBe("Not assessed");
  });
});
