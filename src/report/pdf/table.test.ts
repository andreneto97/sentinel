import { describe, expect, test } from "bun:test";
import { decodePdfText, occurrences, testCanvas } from "./_test-support.ts";
import { CHIP_HEIGHT } from "./components.ts";
import { type TableCell, chipOffset, renderTable } from "./table.ts";
import { CONTENT, SEVERITY_COLOR } from "./theme.ts";

/** The findings table's own columns, as section 5 declares them. */
const FINDINGS_COLUMNS = [
  { header: "Severity", width: 58 },
  { header: "File:line", width: 174 },
  { header: "Finding", width: 250 },
];

/** One findings row, in the three cell kinds the report uses. */
function row(file: string, title: string): TableCell[] {
  return [
    { kind: "chip", label: "medium", color: SEVERITY_COLOR.medium },
    { kind: "mono", text: file },
    { kind: "text", text: title },
  ];
}

describe("renderTable", () => {
  test("keeps a short table on one page", () => {
    const canvas = testCanvas();
    canvas.beginSection("Findings");
    const result = renderTable(canvas, {
      columns: FINDINGS_COLUMNS,
      rows: [row("src/api/sessions.ts:26", "Sign-in handler has no limiter")],
    });
    expect(result).toEqual({ rows: 1, pageBreaks: 0 });
    expect(canvas.pageCount).toBe(1);
  });

  test("breaks a long table and repeats the header on every page it reaches", async () => {
    const canvas = testCanvas();
    canvas.beginSection("Findings");
    const rows = Array.from({ length: 60 }, (_, index) =>
      row(`src/app/api/route-${index}/handler.ts:${index + 1}`, `Finding number ${index + 1}`),
    );
    const result = renderTable(canvas, { columns: FINDINGS_COLUMNS, rows });

    expect(result.rows).toBe(60);
    expect(result.pageBreaks).toBeGreaterThan(0);
    expect(canvas.pageCount).toBe(result.pageBreaks + 1);

    const text = decodePdfText(await canvas.finish());
    // One header band per page the table occupies: a severity column that
    // scrolled off the top of a page is a table the reader has to guess at.
    expect(occurrences(text, "File:line")).toBe(result.pageBreaks + 1);
    // Every row still made it.
    expect(occurrences(text, "Finding number 60")).toBe(1);
  });

  test("never leaves a row hanging below the content box", () => {
    const canvas = testCanvas();
    canvas.beginSection("Findings");
    canvas.y = CONTENT.bottom - 30;
    renderTable(canvas, {
      columns: FINDINGS_COLUMNS,
      rows: [row("src/a.ts:1", "first"), row("src/b.ts:2", "second"), row("src/c.ts:3", "third")],
    });
    expect(canvas.y).toBeLessThanOrEqual(CONTENT.bottom);
  });

  test("a tall first row takes the header with it instead of orphaning it", async () => {
    // The room reserved before the header used to be a guess at two lines, so a
    // first row taller than that left a header band alone at the foot of the
    // page with every row on the next one — a labelled empty table, which reads
    // as "this domain had nothing in it".
    const canvas = testCanvas();
    canvas.beginSection("Coverage and exclusions");
    canvas.y = CONTENT.bottom - 90;
    const tall = Array.from({ length: 24 }, (_unused, index) => `reason ${index + 1}`).join("\n");
    const result = renderTable(canvas, {
      columns: FINDINGS_COLUMNS,
      rows: [
        [
          { kind: "text", text: "Units" },
          { kind: "text", text: "265 of 316" },
          { kind: "text", text: tall },
        ],
      ],
    });

    // The table moved to a fresh page whole: one header, no break.
    expect(result).toEqual({ rows: 1, pageBreaks: 0 });
    const text = decodePdfText(await canvas.finish());
    expect(occurrences(text, "File:line")).toBe(1);
    expect(occurrences(text, "265 of 316")).toBe(1);
    expect(text).toContain("reason 24");
  });

  test("a row taller than a whole page is still drawn rather than looped over", async () => {
    // `ensure` refuses to break for something that cannot fit a page at all, so
    // the header is drawn where it stands and the row follows it.
    const canvas = testCanvas();
    canvas.beginSection("Coverage and exclusions");
    const enormous = Array.from({ length: 400 }, (_unused, index) => `reason ${index}`).join("\n");
    const result = renderTable(canvas, {
      columns: FINDINGS_COLUMNS,
      rows: [
        [
          { kind: "text", text: "units" },
          { kind: "text", text: "1 of 2" },
          { kind: "text", text: enormous },
        ],
      ],
    });
    expect(result.rows).toBe(1);
    const text = decodePdfText(await canvas.finish());
    expect(text).toContain("reason 399");
  });

  test("a chip on a tall row sits with the first line, not in the middle of it", () => {
    // A twenty-line reason cell used to leave the severity chip stranded
    // halfway down, level with nothing, while every other cell started at the
    // top of the row.
    const tall = chipOffset(300, 7.5);
    expect(tall).toBe(3);
  });

  test("a chip on a short row stays centred against the line beside it", () => {
    const short = chipOffset(CHIP_HEIGHT + 6, 7.5);
    expect(short).toBeCloseTo(3, 5);
    // A row barely taller than the chip still centres rather than jumping.
    expect(chipOffset(CHIP_HEIGHT + 12, 7.5)).toBeGreaterThan(3);
  });

  test("wraps a monospace cell by character, so a long path stays in its column", async () => {
    const canvas = testCanvas();
    canvas.beginSection("Findings");
    const long =
      "sentinel/20260922T203437-0ffe4b36/raw/dependency-cruiser/dependency-cruiser.config.mjs:1";
    renderTable(canvas, { columns: FINDINGS_COLUMNS, rows: [row(long, "Unused file candidate")] });
    const text = decodePdfText(await canvas.finish());
    // The path is broken across lines rather than printed past the border, so
    // the whole string is no longer present as one run.
    expect(text).not.toContain(long);
    expect(text).toContain("sentinel/20260922T203437");
    expect(text).toContain("config.mjs:1");
  });

  test("an empty table says so instead of drawing a bare header", async () => {
    const canvas = testCanvas();
    canvas.beginSection("Prioritised plan");
    const result = renderTable(canvas, {
      columns: FINDINGS_COLUMNS,
      rows: [],
      emptyMessage: "Nothing in this tier.",
    });
    expect(result).toEqual({ rows: 0, pageBreaks: 0 });
    const text = decodePdfText(await canvas.finish());
    expect(text).toContain("Nothing in this tier.");
    expect(text).toContain("Severity");
  });

  test("columns are scaled to the content width, whatever the declared widths sum to", async () => {
    const canvas = testCanvas();
    canvas.beginSection("Findings");
    renderTable(canvas, {
      columns: [
        { header: "A", width: 1 },
        { header: "B", width: 1 },
      ],
      rows: [
        [
          { kind: "text", text: "left" },
          { kind: "text", text: "right" },
        ],
      ],
    });
    const raw = new TextDecoder("latin1").decode(await canvas.finish());
    // The middle border of two equal columns lands on the centre of the box.
    const middle = (CONTENT.left + CONTENT.right) / 2;
    expect(raw).toContain(`${middle} `);
  });

  test("a header that wraps in its column grows the band instead of spilling out of it", () => {
    // `lineBreak: false` does not stop pdfkit wrapping a `text` call that
    // carries a width, so a label too wide for its column becomes two lines. A
    // band sized for one drew the second below the grey, through the hairline
    // and into the first row — the header has to be measured like a body row.
    const narrow = [
      { header: "X", width: 54 },
      { header: "Finding", width: 428 },
    ];
    const wrapping = [
      { header: "Reported as", width: 54 },
      { header: "Finding", width: 428 },
    ];
    const body: TableCell[] = [
      { kind: "chip", label: "medium", color: SEVERITY_COLOR.medium },
      { kind: "text", text: "one line" },
    ];

    const heightWith = (columns: typeof narrow): number => {
      const canvas = testCanvas();
      canvas.beginSection("Human verification");
      const before = canvas.y;
      renderTable(canvas, { columns, rows: [body] });
      return canvas.y - before;
    };

    expect(heightWith(wrapping)).toBeGreaterThan(heightWith(narrow));
  });

  test("a row with a taller cell grows, and the chip stays with its row", () => {
    const canvas = testCanvas();
    canvas.beginSection("Findings");
    const before = canvas.y;
    renderTable(canvas, {
      columns: FINDINGS_COLUMNS,
      rows: [row("src/a.ts:1", "one line")],
    });
    const shortHeight = canvas.y - before;

    const canvas2 = testCanvas();
    canvas2.beginSection("Findings");
    const before2 = canvas2.y;
    renderTable(canvas2, {
      columns: FINDINGS_COLUMNS,
      rows: [
        row(
          "src/a.ts:1",
          "a much longer finding title that has to wrap across several lines of its column before the row is done",
        ),
      ],
    });
    expect(canvas2.y - before2).toBeGreaterThan(shortHeight);
  });
});
