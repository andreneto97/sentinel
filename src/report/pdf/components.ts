/**
 * The vocabulary every section is written in.
 *
 * Each helper measures before it draws and asks the canvas for the room it
 * needs, so "nothing overflows a page silently" is a property of these
 * primitives rather than a rule each section has to remember. Anything that
 * *can* flow across a page — a paragraph, a list — is allowed to; anything that
 * would be unreadable split in two — a chip, a heading with its first line, a
 * row of a code box — is kept whole.
 */

import type { Severity } from "../../contracts/findings.ts";
import type { ReportCanvas } from "./layout.ts";
import { monoColumns, parseSnippet, toWinAnsi } from "./text.ts";
import { COLOR, FONT, SEVERITY_COLOR, SIZE, SPACE } from "./theme.ts";

/** Draws a filled rectangle; the canvas's text state survives it. */
export function fillRect(
  canvas: ReportCanvas,
  x: number,
  y: number,
  width: number,
  height: number,
  color: string,
): void {
  canvas.doc.rect(x, y, width, height).fill(color);
  canvas.restore();
}

/** Draws a rectangle outline. */
export function strokeRect(
  canvas: ReportCanvas,
  x: number,
  y: number,
  width: number,
  height: number,
  color: string = COLOR.hairline,
  lineWidth = 0.5,
): void {
  canvas.doc.lineWidth(lineWidth).rect(x, y, width, height).stroke(color);
  canvas.restore();
}

/** Draws a horizontal hairline across the content box. */
export function hairline(canvas: ReportCanvas, y: number, color: string = COLOR.hairline): void {
  canvas.doc.lineWidth(0.5).moveTo(canvas.left, y).lineTo(canvas.right, y).stroke(color);
  canvas.restore();
}

/** The page's first-level heading: the section title, with a rule under it. */
export function sectionTitle(canvas: ReportCanvas, title: string, caption?: string): void {
  canvas.use(FONT.bold, SIZE.h1, COLOR.ink);
  canvas.doc.text(toWinAnsi(title), canvas.left, canvas.y, { width: canvas.width });
  canvas.moveDown(2);
  hairline(canvas, canvas.y);
  canvas.moveDown(SPACE.paragraph);
  if (caption !== undefined && caption !== "") {
    paragraph(canvas, caption, { color: COLOR.muted, size: SIZE.small });
  }
}

/** A second-level heading, kept on the same page as the first line it introduces. */
export function heading(canvas: ReportCanvas, title: string, color: string = COLOR.ink): void {
  canvas.ensure(SIZE.h2 * 2.4 + SPACE.paragraph);
  canvas.moveDown(SPACE.paragraph);
  canvas.use(FONT.bold, SIZE.h2, color);
  canvas.doc.text(toWinAnsi(title), canvas.left, canvas.y, { width: canvas.width });
  canvas.moveDown(3);
}

/** A third-level heading: the label above a block of detail. */
export function subheading(canvas: ReportCanvas, title: string, color: string = COLOR.ink): void {
  canvas.ensure(SIZE.h3 * 2.6);
  canvas.use(FONT.bold, SIZE.h3, color);
  canvas.doc.text(toWinAnsi(title), canvas.left, canvas.y, { width: canvas.width });
  canvas.moveDown(2);
}

/** Options for a run of body copy. */
export interface ParagraphOptions {
  readonly size?: number | undefined;
  readonly color?: string | undefined;
  readonly font?: string | undefined;
  readonly indent?: number | undefined;
  readonly width?: number | undefined;
  readonly gapAfter?: number | undefined;
}

/**
 * Body copy.
 *
 * Long paragraphs are allowed to break across pages — pdfkit's own break lands
 * at the top margin, which is where the next page's content starts — but the
 * canvas is asked for two lines first, so a paragraph never leaves a single
 * orphan line at the foot of a page.
 */
export function paragraph(
  canvas: ReportCanvas,
  text: string,
  options: ParagraphOptions = {},
): void {
  const size = options.size ?? SIZE.body;
  const indent = options.indent ?? 0;
  const width = options.width ?? canvas.width - indent;
  canvas.use(options.font ?? FONT.regular, size, options.color ?? COLOR.body);
  canvas.ensure(size * 2.6);
  canvas.doc.text(toWinAnsi(text), canvas.left + indent, canvas.y, {
    width,
    lineGap: size * (SPACE.line - 1) * 0.5,
  });
  canvas.moveDown(options.gapAfter ?? SPACE.paragraph);
}

/** A `Label: value` line, with the label in bold and the value beside it. */
export function labelled(
  canvas: ReportCanvas,
  label: string,
  value: string,
  options: { readonly labelWidth?: number; readonly indent?: number; readonly color?: string } = {},
): void {
  const labelWidth = options.labelWidth ?? 120;
  const indent = options.indent ?? 0;
  const valueWidth = canvas.width - labelWidth - indent;
  canvas.use(FONT.regular, SIZE.body, options.color ?? COLOR.body);
  const height = canvas.measure(value, valueWidth);
  canvas.ensure(height);
  const top = canvas.y;

  canvas.use(FONT.bold, SIZE.body, COLOR.ink);
  canvas.doc.text(toWinAnsi(label), canvas.left + indent, top, {
    width: labelWidth,
    lineBreak: false,
  });
  canvas.use(FONT.regular, SIZE.body, options.color ?? COLOR.body);
  canvas.doc.text(toWinAnsi(value), canvas.left + indent + labelWidth, top, { width: valueWidth });
  canvas.y = Math.max(canvas.y, top + height);
  canvas.moveDown(2);
}

/** A bulleted line. The bullet colour is the one lever a list has for meaning. */
export function bullet(
  canvas: ReportCanvas,
  text: string,
  options: { readonly color?: string; readonly indent?: number; readonly size?: number } = {},
): void {
  const size = options.size ?? SIZE.body;
  const indent = options.indent ?? 0;
  const gutter = 10;
  const width = canvas.width - indent - gutter;
  canvas.use(FONT.regular, size, COLOR.body);
  const height = canvas.measure(text, width);
  canvas.ensure(Math.min(height, size * 2.6));
  const top = canvas.y;
  canvas.doc
    .circle(canvas.left + indent + 2.5, top + size * 0.45, 1.6)
    .fill(options.color ?? COLOR.muted);
  canvas.use(FONT.regular, size, COLOR.body);
  canvas.doc.text(toWinAnsi(text), canvas.left + indent + gutter, top, { width });
  canvas.moveDown(2);
}

/** Height of a severity chip; also the height of a table row that carries one. */
export const CHIP_HEIGHT = 11;

/** Width a chip needs for a given word, at the chip's own type size. */
export function chipWidth(canvas: ReportCanvas, label: string): number {
  canvas.doc.font(FONT.bold).fontSize(SIZE.tiny);
  const width = canvas.doc.widthOfString(toWinAnsi(label.toUpperCase())) + 10;
  canvas.restore();
  return width;
}

/**
 * A filled chip with the word inside it.
 *
 * The word stays next to the colour on purpose: a chip that relies on colour
 * alone disappears on a greyscale printer, and this document is printed.
 */
export function chip(
  canvas: ReportCanvas,
  x: number,
  y: number,
  label: string,
  color: string,
): number {
  const text = toWinAnsi(label.toUpperCase());
  canvas.doc.font(FONT.bold).fontSize(SIZE.tiny);
  const width = canvas.doc.widthOfString(text) + 10;
  canvas.doc.roundedRect(x, y, width, CHIP_HEIGHT, 2).fill(color);
  canvas.doc.fillColor(COLOR.onColor).text(text, x + 5, y + 2.6, { lineBreak: false });
  canvas.restore();
  return width;
}

/** A severity chip, coloured from the fixed palette. */
export function severityChip(
  canvas: ReportCanvas,
  x: number,
  y: number,
  severity: Severity,
): number {
  return chip(canvas, x, y, severity, SEVERITY_COLOR[severity]);
}

/** A key with a coloured swatch, used by both chart legends. */
export function legendEntry(
  canvas: ReportCanvas,
  x: number,
  y: number,
  color: string,
  label: string,
  value: string,
): void {
  canvas.doc.rect(x, y + 1.5, 6, 6).fill(color);
  canvas.use(FONT.regular, SIZE.small, COLOR.body);
  canvas.doc.text(toWinAnsi(label), x + 11, y, { lineBreak: false });
  canvas.use(FONT.bold, SIZE.small, COLOR.ink);
  const width = canvas.widthOf(value);
  canvas.doc.text(toWinAnsi(value), x + 150 - width, y, { lineBreak: false });
  canvas.restore();
}

/**
 * A left-barred callout: a quiet way to mark a block as different without a
 * second colour scheme.
 */
export function callout(
  canvas: ReportCanvas,
  text: string,
  color: string,
  options: { readonly title?: string } = {},
): void {
  const padding = 7;
  const innerWidth = canvas.width - padding * 2 - 3;
  canvas.use(FONT.regular, SIZE.small, COLOR.body);
  let height = canvas.measure(text, innerWidth) + padding * 2;
  if (options.title !== undefined) height += SIZE.h3 + 3;
  canvas.ensure(height);

  const top = canvas.y;
  fillRect(canvas, canvas.left, top, canvas.width, height, COLOR.panel);
  fillRect(canvas, canvas.left, top, 3, height, color);

  let cursor = top + padding;
  if (options.title !== undefined) {
    canvas.use(FONT.bold, SIZE.h3, color);
    canvas.doc.text(toWinAnsi(options.title), canvas.left + 3 + padding, cursor, {
      width: innerWidth,
    });
    cursor += SIZE.h3 + 3;
  }
  canvas.use(FONT.regular, SIZE.small, COLOR.body);
  canvas.doc.text(toWinAnsi(text), canvas.left + 3 + padding, cursor, { width: innerWidth });
  canvas.y = top + height;
  canvas.moveDown(SPACE.paragraph);
}

/** How a code box turned out — used by tests and by the caller's spacing. */
export interface CodeBoxResult {
  /** Rows actually drawn, wraps included. */
  readonly rows: number;
  readonly height: number;
}

/**
 * The verified snippet, in a monospace box with its real line numbers.
 *
 * The numbers come from the snippet itself (`src/verify/snippet.ts` writes
 * them), so they are the file's line numbers, not a count of the rows in the
 * box, and the cited line keeps the marker the verifier put on it. A box that
 * does not fit on the remaining page moves whole to the next one: half a
 * snippet proves nothing.
 */
export function codeBox(
  canvas: ReportCanvas,
  snippet: string,
  options: {
    readonly firstLine?: number;
    readonly maxLines?: number;
    readonly indent?: number;
  } = {},
): CodeBoxResult {
  const indent = options.indent ?? 0;
  const padding = 6;
  const boxWidth = canvas.width - indent;
  const gutterWidth = 24;
  const codeWidth = boxWidth - padding * 2 - gutterWidth - 4;
  const columns = monoColumns(codeWidth, SIZE.code);
  const rows = parseSnippet(snippet, {
    maxChars: columns,
    ...(options.firstLine === undefined ? {} : { firstLine: options.firstLine }),
    maxLines: options.maxLines ?? 18,
  });
  if (rows.length === 0) return { rows: 0, height: 0 };

  const lineHeight = SIZE.code * 1.45;
  const height = rows.length * lineHeight + padding * 2;
  canvas.ensure(height);

  const top = canvas.y;
  const left = canvas.left + indent;
  fillRect(canvas, left, top, boxWidth, height, COLOR.code);
  strokeRect(canvas, left, top, boxWidth, height);
  // The gutter is separated by a rule rather than by whitespace, so a wrapped
  // continuation is visibly a continuation and not a new line of code.
  canvas.doc
    .lineWidth(0.5)
    .moveTo(left + padding + gutterWidth, top + 2)
    .lineTo(left + padding + gutterWidth, top + height - 2)
    .stroke(COLOR.hairline);

  rows.forEach((row, index) => {
    const y = top + padding + index * lineHeight;
    if (row.cited) {
      fillRect(canvas, left + 1, y - 1, boxWidth - 2, lineHeight, "#FEF3C7");
    }
    if (row.gutter !== "") {
      canvas.use(FONT.mono, SIZE.code, COLOR.muted);
      const width = canvas.widthOf(row.gutter);
      canvas.doc.text(row.gutter, left + padding + gutterWidth - 6 - width, y, {
        lineBreak: false,
      });
    }
    if (row.code !== "") {
      canvas.use(row.cited ? FONT.monoBold : FONT.mono, SIZE.code, COLOR.ink);
      canvas.doc.text(row.code, left + padding + gutterWidth + 6, y, { lineBreak: false });
    }
  });

  canvas.restore();
  canvas.y = top + height;
  canvas.moveDown(SPACE.paragraph);
  return { rows: rows.length, height };
}

/** A monospace line of citation, used where a snippet would be too much. */
export function monoLine(
  canvas: ReportCanvas,
  text: string,
  options: { readonly color?: string; readonly indent?: number } = {},
): void {
  const indent = options.indent ?? 0;
  canvas.use(FONT.mono, SIZE.code, options.color ?? COLOR.muted);
  canvas.ensure(SIZE.code * 1.6);
  canvas.doc.text(toWinAnsi(text), canvas.left + indent, canvas.y, {
    width: canvas.width - indent,
    lineGap: 1,
  });
  canvas.moveDown(1);
}
