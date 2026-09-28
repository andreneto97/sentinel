/**
 * A real table: bordered columns, measured rows, and a header that comes back
 * every time the table crosses onto a new page.
 *
 * The page break is the whole point. A row is measured before it is drawn, and
 * a row that does not fit moves to the next page *with* the header row above
 * it — a findings table whose severity column has scrolled off the top of the
 * page is a table the reader has to guess at.
 *
 * Cells are values, not callbacks, so a test can assert what a table contains
 * without rendering one.
 */

import { CHIP_HEIGHT, chip, fillRect } from "./components.ts";
import type { ReportCanvas } from "./layout.ts";
import { monoColumns, toWinAnsi, wrapMonospace } from "./text.ts";
import { COLOR, FONT, SIZE } from "./theme.ts";

/** What a cell can hold. */
export type TableCell =
  | {
      readonly kind: "text";
      readonly text: string;
      readonly bold?: boolean | undefined;
      readonly color?: string | undefined;
    }
  /** Monospace, pre-wrapped at the column's character budget: paths never bleed. */
  | { readonly kind: "mono"; readonly text: string; readonly color?: string | undefined }
  /** A coloured chip, vertically centred in its row. */
  | { readonly kind: "chip"; readonly label: string; readonly color: string }
  | { readonly kind: "empty" };

/** One column: its heading, its width in points, and how its text is aligned. */
export interface TableColumn {
  readonly header: string;
  readonly width: number;
  readonly align?: "left" | "right" | undefined;
}

/** Everything {@link renderTable} needs. */
export interface TableOptions {
  readonly columns: readonly TableColumn[];
  readonly rows: readonly (readonly TableCell[])[];
  /** Tints every other row; off by default, since most tables here are short. */
  readonly zebra?: boolean | undefined;
  /** Printed in place of the body when there is nothing to list. */
  readonly emptyMessage?: string | undefined;
  readonly fontSize?: number | undefined;
}

/** What a rendered table cost, for the caller's spacing and for tests. */
export interface TableResult {
  readonly rows: number;
  /** How many times the table broke onto a new page, repeating its header. */
  readonly pageBreaks: number;
}

const PADDING = 4;
const ROW_GAP = 3;

/** What an empty table says when the caller names nothing better. */
const EMPTY_MESSAGE = "Nothing to list.";

/**
 * How tall the header band has to be for the labels it carries.
 *
 * Not `fontSize + PADDING * 2`, which is what this used to assume. pdfkit wraps
 * whenever a `text` call is given a `width` — `lineBreak: false` only stops it
 * from *inventing* a width, it does not turn wrapping off — so a label that does
 * not fit its column ("Reported as" in a 54pt column) becomes two lines. A band
 * sized for one line then has the second line drawn below it, outside the grey,
 * across the hairline and into the first row: exactly the defect this measures
 * away.
 *
 * The header is measured the same way a body row is, so the band is whatever
 * the widest label needs, and never less than one line.
 */
function headerHeight(
  canvas: ReportCanvas,
  columns: readonly TableColumn[],
  widths: readonly number[],
  fontSize: number,
): number {
  canvas.use(FONT.bold, fontSize, COLOR.ink);
  const tallest = columns.reduce((height, column, index) => {
    const inner = (widths[index] ?? 0) - PADDING * 2;
    if (inner <= 0) return height;
    return Math.max(height, canvas.measure(column.header, inner));
  }, fontSize);
  canvas.restore();
  return tallest + PADDING * 2;
}

/**
 * How far down its row a chip is drawn.
 *
 * Centred against a short row, which is what makes a severity chip look level
 * with the one line of text beside it. Top-aligned on a tall one: a withheld
 * finding whose reason runs twenty lines used to strand its `CRITICAL` chip
 * halfway down the cell, level with nothing in particular, while every other
 * cell in the row started at the top. A reader pairs a chip with the first line
 * of the row, so on anything taller than a few lines it belongs at the top with
 * the rest.
 */
export function chipOffset(rowHeight: number, fontSize: number): number {
  const content = rowHeight - ROW_GAP * 2;
  return content > CHIP_HEIGHT + fontSize * 3 ? ROW_GAP : (rowHeight - CHIP_HEIGHT) / 2;
}

/** Text cells are wrapped by pdfkit; mono cells are wrapped here, by character. */
function monoText(text: string, width: number, size: number): string {
  const columns = monoColumns(width, size);
  return toWinAnsi(text)
    .split("\n")
    .flatMap((line) => wrapMonospace(line, columns))
    .join("\n");
}

/** Height one cell needs at a given column width. */
function cellHeight(
  canvas: ReportCanvas,
  cell: TableCell,
  width: number,
  fontSize: number,
): number {
  switch (cell.kind) {
    case "empty":
      return fontSize;
    case "chip":
      return CHIP_HEIGHT;
    case "mono": {
      canvas.use(FONT.mono, SIZE.code, COLOR.body);
      return canvas.measure(monoText(cell.text, width, SIZE.code), width, 1);
    }
    case "text": {
      canvas.use(cell.bold === true ? FONT.bold : FONT.regular, fontSize, COLOR.body);
      return canvas.measure(cell.text, width);
    }
  }
}

/** Draws one cell inside its column box. */
function drawCell(
  canvas: ReportCanvas,
  cell: TableCell,
  x: number,
  y: number,
  width: number,
  column: TableColumn,
  fontSize: number,
): void {
  switch (cell.kind) {
    case "empty":
      return;
    case "chip":
      chip(canvas, x, y, cell.label, cell.color);
      return;
    case "mono": {
      canvas.use(FONT.mono, SIZE.code, cell.color ?? COLOR.body);
      canvas.doc.text(monoText(cell.text, width, SIZE.code), x, y, { width, lineGap: 1 });
      return;
    }
    case "text": {
      canvas.use(cell.bold === true ? FONT.bold : FONT.regular, fontSize, cell.color ?? COLOR.body);
      canvas.doc.text(toWinAnsi(cell.text), x, y, {
        width,
        ...(column.align === undefined ? {} : { align: column.align }),
      });
      return;
    }
  }
}

/**
 * How tall this table would be if nothing broke it.
 *
 * Measuring costs the same wrapping arithmetic the draw does, so this is only
 * worth calling for a table a caller would rather move whole than split — a
 * scorecard, say, whose whole job is to be compared row against row. Everything
 * else should just flow and let {@link renderTable} repeat the header.
 */
export function measureTable(canvas: ReportCanvas, options: TableOptions): number {
  const fontSize = options.fontSize ?? SIZE.small;
  const columns = options.columns;
  const total = columns.reduce((sum, column) => sum + column.width, 0);
  const scale = total > 0 ? canvas.width / total : 1;
  const widths = columns.map((column) => column.width * scale);
  const header = headerHeight(canvas, columns, widths, fontSize);
  if (options.rows.length === 0) return header + emptyHeight(canvas, options, fontSize) + SIZE.body;
  const body = options.rows.reduce((sum, row) => {
    const heights = columns.map((_, index) =>
      cellHeight(
        canvas,
        row[index] ?? { kind: "empty" },
        (widths[index] ?? 0) - PADDING * 2,
        fontSize,
      ),
    );
    return sum + Math.max(...heights, fontSize) + ROW_GAP * 2;
  }, 0);
  return header + body + SIZE.body;
}

/** The empty-table box: two lines of room, or more when the message needs it. */
function emptyHeight(canvas: ReportCanvas, options: TableOptions, fontSize: number): number {
  canvas.use(FONT.italic, fontSize, COLOR.muted);
  const message = canvas.measure(options.emptyMessage ?? EMPTY_MESSAGE, canvas.width - PADDING * 2);
  canvas.restore();
  return Math.max(fontSize * 2.4, message + PADDING * 2);
}

/**
 * Renders a bordered table, breaking rows onto new pages with the header
 * repeated above them.
 */
export function renderTable(canvas: ReportCanvas, options: TableOptions): TableResult {
  const fontSize = options.fontSize ?? SIZE.small;
  const columns = options.columns;
  const total = columns.reduce((sum, column) => sum + column.width, 0);
  const scale = total > 0 ? canvas.width / total : 1;
  const widths = columns.map((column) => column.width * scale);
  const header = headerHeight(canvas, columns, widths, fontSize);

  /** Draws the header band and returns the y the first body row starts at. */
  const drawHeader = (): number => {
    const top = canvas.y;
    fillRect(canvas, canvas.left, top, canvas.width, header, COLOR.panel);
    let x = canvas.left;
    columns.forEach((column, index) => {
      const width = widths[index] ?? 0;
      canvas.use(FONT.bold, fontSize, COLOR.ink);
      // No `lineBreak: false` here: it would not stop the wrap (pdfkit wraps on
      // `width` alone), and pretending otherwise is what let a two-line label
      // escape a one-line band. The band is measured for the wrap instead.
      canvas.doc.text(toWinAnsi(column.header), x + PADDING, top + PADDING, {
        width: width - PADDING * 2,
        ...(column.align === undefined ? {} : { align: column.align }),
      });
      x += width;
    });
    canvas.doc.lineWidth(0.5).rect(canvas.left, top, canvas.width, header).stroke(COLOR.hairline);
    canvas.restore();
    return top + header;
  };

  if (options.rows.length === 0) {
    const height = emptyHeight(canvas, options, fontSize);
    canvas.ensure(header + height);
    canvas.y = drawHeader();
    const message = options.emptyMessage ?? EMPTY_MESSAGE;
    fillRect(canvas, canvas.left, canvas.y, canvas.width, height, COLOR.page);
    canvas.doc
      .lineWidth(0.5)
      .rect(canvas.left, canvas.y, canvas.width, height)
      .stroke(COLOR.hairline);
    canvas.use(FONT.italic, fontSize, COLOR.muted);
    canvas.doc.text(toWinAnsi(message), canvas.left + PADDING, canvas.y + PADDING, {
      width: canvas.width - PADDING * 2,
    });
    canvas.y += height;
    canvas.moveDown(SIZE.body);
    return { rows: 0, pageBreaks: 0 };
  }

  /** How tall one row will be once its cells are wrapped. */
  const rowHeight = (row: readonly TableCell[]): number => {
    const heights = columns.map((_unused, index) =>
      cellHeight(
        canvas,
        row[index] ?? { kind: "empty" },
        (widths[index] ?? 0) - PADDING * 2,
        fontSize,
      ),
    );
    return Math.max(...heights, fontSize) + ROW_GAP * 2;
  };

  // Room for the header *and the row that follows it*, measured rather than
  // guessed. `fontSize * 4` stood here, which is about two lines: a first row
  // taller than that — a coverage cell listing twenty skip reasons, say — left
  // the header drawn at the foot of one page and every row of the table on the
  // next, under a second copy of it. An orphaned header is not a small
  // blemish: it is a labelled empty table, and a reader who stops there has
  // been told the domain has nothing in it.
  canvas.ensure(header + rowHeight(options.rows[0] ?? []));
  canvas.y = drawHeader();

  let pageBreaks = 0;
  options.rows.forEach((row, rowIndex) => {
    const height = rowHeight(row);

    if (canvas.y + height > canvas.bottom) {
      canvas.addPage();
      canvas.y = drawHeader();
      pageBreaks += 1;
    }

    const top = canvas.y;
    if (options.zebra === true && rowIndex % 2 === 1) {
      fillRect(canvas, canvas.left, top, canvas.width, height, COLOR.code);
    }

    let x = canvas.left;
    columns.forEach((column, index) => {
      const width = widths[index] ?? 0;
      const cell = row[index] ?? { kind: "empty" };
      const inner = width - PADDING * 2;
      const cellY = cell.kind === "chip" ? top + chipOffset(height, fontSize) : top + ROW_GAP;
      drawCell(canvas, cell, x + PADDING, cellY, inner, column, fontSize);
      x += width;
    });

    // The grid: verticals between every pair of columns, a hairline under the row.
    let border = canvas.left;
    canvas.doc.lineWidth(0.5);
    for (const width of widths) {
      canvas.doc
        .moveTo(border, top)
        .lineTo(border, top + height)
        .stroke(COLOR.hairline);
      border += width;
    }
    canvas.doc
      .moveTo(border, top)
      .lineTo(border, top + height)
      .stroke(COLOR.hairline);
    canvas.doc
      .moveTo(canvas.left, top + height)
      .lineTo(canvas.right, top + height)
      .stroke(COLOR.hairline);
    canvas.restore();

    canvas.y = top + height;
  });

  canvas.moveDown(SIZE.body);
  return { rows: options.rows.length, pageBreaks };
}
