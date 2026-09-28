import { describe, expect, test } from "bun:test";
import { occurrences, testCanvas, decodePdfText as textOf } from "./_test-support.ts";
import { CHROME, CONTENT, PAGE, SIZE } from "./theme.ts";

/** A canvas with compression off, so a test can read what was drawn. */
function canvasFor(runId = "20260304T093000-9f2c41ab") {
  return testCanvas({ runId });
}

describe("the content box", () => {
  test("is A4 with ~2cm margins, and the chrome lives outside it", () => {
    expect(PAGE.width).toBeCloseTo(595.28, 2);
    expect(PAGE.height).toBeCloseTo(841.89, 2);
    // 2cm is 56.69pt; the header and footer sit in the margin band, which is
    // what lets pdfkit's own page break land exactly at the content top.
    expect(PAGE.margin).toBeCloseTo(56.7, 2);
    expect(CHROME.headerRule).toBeLessThan(CONTENT.top);
    expect(CHROME.headerBaseline).toBeLessThan(CHROME.headerRule);
    expect(CHROME.footerRule).toBeGreaterThan(CONTENT.bottom);
    expect(CHROME.footerBaseline).toBeGreaterThan(CHROME.footerRule);
  });
});

describe("ensure", () => {
  test("does not break when the block fits", () => {
    const canvas = canvasFor();
    canvas.beginSection("Findings");
    canvas.y = CONTENT.top;
    expect(canvas.ensure(100)).toBe(false);
    expect(canvas.pageCount).toBe(1);
  });

  test("breaks to a new page when it does not, and the cursor lands at the top", () => {
    const canvas = canvasFor();
    canvas.beginSection("Findings");
    canvas.y = CONTENT.bottom - 20;
    expect(canvas.ensure(100)).toBe(true);
    expect(canvas.pageCount).toBe(2);
    expect(canvas.y).toBe(CONTENT.top);
  });

  test("a block taller than a page is drawn where it stands instead of looping", () => {
    const canvas = canvasFor();
    canvas.beginSection("Findings");
    canvas.y = CONTENT.top + 40;
    expect(canvas.ensure(CONTENT.bottom - CONTENT.top + 1)).toBe(false);
    expect(canvas.pageCount).toBe(1);
    expect(canvas.y).toBe(CONTENT.top + 40);
  });
});

describe("chrome", () => {
  test("every page after the cover carries the running header", async () => {
    const canvas = canvasFor();
    canvas.beginCover();
    canvas.beginSection("Findings");
    canvas.addPage();
    const bytes = await canvas.finish();
    const text = textOf(bytes);
    // Three pages: cover, section start, one more. The header names the section
    // on the two content pages and never on the cover. (The report's own name
    // also appears once in the document metadata, so the section is what is
    // counted here.)
    expect(occurrences(text, "Findings")).toBe(2);
    expect(text).toContain("Backend Dossier - example-api");
  });

  test("the footer knows the real total, which needs the second pass", async () => {
    const canvas = canvasFor();
    canvas.beginCover();
    canvas.beginSection("Findings");
    canvas.addPage();
    canvas.addPage();
    const bytes = await canvas.finish();
    const text = textOf(bytes);
    // Four buffered pages, three of them numbered: the cover is not page 1.
    expect(text).toContain("page 1 of 3");
    expect(text).toContain("page 2 of 3");
    expect(text).toContain("page 3 of 3");
    expect(text).not.toContain("page 4 of");
    expect(text).toContain("20260304T093000-9f2c41ab");
  });

  test("restores the text state it borrowed, so a broken paragraph keeps its font", () => {
    const canvas = canvasFor();
    canvas.beginSection("Findings");
    canvas.use("Helvetica-Bold", SIZE.h1, "#B91C1C");
    const widthBefore = canvas.widthOf("measured in the heading font");
    canvas.addPage(); // fires the pageAdded listener, which draws the header
    expect(canvas.widthOf("measured in the heading font")).toBe(widthBefore);
  });

  test("the cursor survives a header draw untouched", () => {
    const canvas = canvasFor();
    canvas.beginSection("Findings");
    canvas.y = 300;
    canvas.addPage();
    // addPage resets the cursor to the content top on purpose; the header must
    // not have moved it anywhere else.
    expect(canvas.y).toBe(CONTENT.top);
  });
});

describe("finish", () => {
  test("returns a real PDF", async () => {
    const canvas = canvasFor();
    canvas.beginCover();
    canvas.beginSection("Appendix");
    const bytes = await canvas.finish();
    expect(new TextDecoder().decode(bytes.slice(0, 8))).toBe("%PDF-1.3");
    expect(textOf(bytes).endsWith("%%EOF\n")).toBe(true);
    expect(bytes.length).toBeGreaterThan(1000);
  });

  test("a single-page document says page 1 of 1 once the cover is excluded", async () => {
    const canvas = canvasFor();
    canvas.beginCover();
    canvas.beginSection("Only");
    const bytes = await canvas.finish();
    expect(textOf(bytes)).toContain("page 1 of 1");
  });
});
