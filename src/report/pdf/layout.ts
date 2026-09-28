/**
 * The paged canvas: the one place that knows where the pen is.
 *
 * Three invariants live here, and every section depends on all three.
 *
 * 1. **The content box is sacred.** The running header and the `page N of M`
 *    footer are drawn inside the margin band, above and below the flowing box.
 *    That means pdfkit's own automatic page break — which drops the cursor at
 *    the top margin of the new page — lands in exactly the right place, so a
 *    paragraph that runs long can never slide under the header.
 * 2. **Chrome never leaks state.** The header is drawn from a `pageAdded`
 *    listener, which can fire in the middle of a paragraph. A stray
 *    `fillColor`/`font` left behind would repaint the rest of that paragraph in
 *    the header's grey, so the canvas tracks the text state it set and restores
 *    it after every chrome draw.
 * 3. **`page N of M` needs M.** Pages are buffered, the footers are stamped in
 *    a second pass once the total is known, and only then is the document
 *    ended. A report that guessed the total would be a report that lies about
 *    something checkable.
 */

import PDFDocument from "pdfkit";
import { toWinAnsi } from "./text.ts";
import { CHROME, COLOR, CONTENT, FONT, PAGE, SIZE } from "./theme.ts";

/** What the running chrome says on every page. */
export interface CanvasOptions {
  /** The report's name, printed top-left on every page but the cover. */
  readonly title: string;
  /** The repository the dossier is about. */
  readonly subject: string;
  /** Printed bottom-left, so a page torn out of the stack is still traceable. */
  readonly runId: string;
  /** Stamped as the document's creation date, which keeps two renders identical. */
  readonly createdAt: Date;
  /** Kept for the PDF's own metadata. */
  readonly author?: string | undefined;
  /**
   * Deflate the content streams. On by default; a test turns it off so it can
   * read the page text straight out of the bytes and check what was stamped.
   */
  readonly compress?: boolean | undefined;
}

/** The text state the canvas owns, so chrome can be undone exactly. */
interface TextState {
  font: string;
  size: number;
  color: string;
}

/**
 * A paged A4 canvas with a running header, a real `page N of M` footer, and a
 * cursor that refuses to write past the bottom margin without being told to.
 */
export class ReportCanvas {
  readonly doc: PDFKit.PDFDocument;
  readonly options: CanvasOptions;

  #chunks: Uint8Array[] = [];
  #ended: Promise<void>;
  #state: TextState = { font: FONT.regular, size: SIZE.body, color: COLOR.body };
  #section = "";
  #chrome = false;

  constructor(options: CanvasOptions) {
    this.options = options;
    this.doc = new PDFDocument({
      size: "A4",
      margins: {
        top: PAGE.margin,
        bottom: PAGE.margin,
        left: PAGE.margin,
        right: PAGE.margin,
      },
      bufferPages: true,
      autoFirstPage: false,
      compress: options.compress ?? true,
      info: {
        Title: `${options.title} - ${options.subject}`,
        Author: options.author ?? "Sentinel",
        Subject: `Backend dossier for ${options.subject}`,
        Creator: "Sentinel",
        CreationDate: options.createdAt,
      },
    });

    this.doc.on("data", (chunk: Uint8Array) => {
      this.#chunks.push(chunk);
    });
    this.#ended = new Promise<void>((resolve) => {
      this.doc.on("end", () => {
        resolve();
      });
    });
    this.doc.on("pageAdded", () => {
      this.#drawChrome();
    });
  }

  // -------------------------------------------------------------------------
  // The box
  // -------------------------------------------------------------------------

  /** Left edge of the flowing content box. */
  get left(): number {
    return CONTENT.left;
  }

  /** Right edge of the flowing content box. */
  get right(): number {
    return CONTENT.right;
  }

  /** Width of the flowing content box. */
  get width(): number {
    return CONTENT.width;
  }

  /** The last y a block may occupy before it has to break to the next page. */
  get bottom(): number {
    return CONTENT.bottom;
  }

  /** Top of the flowing content box. */
  get top(): number {
    return CONTENT.top;
  }

  /** The cursor, in absolute page coordinates. */
  get y(): number {
    return this.doc.y;
  }

  set y(value: number) {
    this.doc.y = value;
  }

  /** How much room is left on this page. */
  get remaining(): number {
    return this.bottom - this.y;
  }

  /** Pages produced so far, cover included. */
  get pageCount(): number {
    return this.doc.bufferedPageRange().count;
  }

  /** The section name the running header is printing. */
  get section(): string {
    return this.#section;
  }

  // -------------------------------------------------------------------------
  // Flow
  // -------------------------------------------------------------------------

  /** Moves the cursor down without drawing anything. */
  moveDown(points: number): void {
    this.y += points;
  }

  /** Starts a page. The header is drawn by the `pageAdded` listener. */
  addPage(): void {
    this.doc.addPage();
    this.y = this.top;
  }

  /**
   * Guarantees `height` points of room, breaking to a new page if needed.
   *
   * Returns true when it broke, which is what lets a table repeat its header
   * row. A block taller than a whole page is drawn where it stands — breaking
   * for it would loop forever — and such a block is expected to be able to
   * flow across pages on its own.
   */
  ensure(height: number): boolean {
    if (height >= this.bottom - this.top) return false;
    if (this.y + height <= this.bottom) return false;
    this.addPage();
    return true;
  }

  /** Starts a new section: a fresh page, a new running header, cursor at the top. */
  beginSection(name: string): void {
    this.#section = name;
    this.#chrome = true;
    this.addPage();
  }

  /** The cover page, which carries no running chrome. */
  beginCover(): void {
    this.#chrome = false;
    this.doc.addPage();
    this.y = this.top;
  }

  // -------------------------------------------------------------------------
  // Text state
  // -------------------------------------------------------------------------

  /**
   * Sets the font, size and colour the next draw will use, and remembers them.
   *
   * Everything that draws text goes through here, which is what makes the
   * chrome restore exact: the canvas can only put back a state it recorded.
   */
  use(font: string, size: number, color: string): void {
    this.#state = { font, size, color };
    this.doc.font(font).fontSize(size).fillColor(color);
  }

  /** Re-applies the recorded text state, after something else changed it. */
  restore(): void {
    this.doc.font(this.#state.font).fontSize(this.#state.size).fillColor(this.#state.color);
  }

  /** Height the current font needs for `text` laid out in `width` points. */
  measure(text: string, width: number, lineGap = 0): number {
    return this.doc.heightOfString(toWinAnsi(text), { width, lineGap });
  }

  /** Width of `text` in the current font. */
  widthOf(text: string): number {
    return this.doc.widthOfString(toWinAnsi(text));
  }

  // -------------------------------------------------------------------------
  // Chrome
  // -------------------------------------------------------------------------

  /**
   * Draws the running header for the page that was just added.
   *
   * Deliberately avoids pdfkit's wrapping path: a `text` call carrying a
   * `width` would take over the line wrapper that the interrupted paragraph is
   * still using. Strings are measured and placed by hand instead.
   */
  #drawChrome(): void {
    if (!this.#chrome) return;
    const { x, y } = this.doc;

    this.doc.font(FONT.regular).fontSize(SIZE.tiny).fillColor(COLOR.muted);
    const left = toWinAnsi(`${this.options.title} - ${this.options.subject}`);
    this.doc.text(left, CONTENT.left, CHROME.headerBaseline, { lineBreak: false });
    if (this.#section !== "") {
      const right = toWinAnsi(this.#section);
      const width = this.doc.widthOfString(right);
      this.doc.text(right, CONTENT.right - width, CHROME.headerBaseline, { lineBreak: false });
    }
    this.doc
      .moveTo(CONTENT.left, CHROME.headerRule)
      .lineTo(CONTENT.right, CHROME.headerRule)
      .lineWidth(0.5)
      .stroke(COLOR.hairline);

    this.doc.x = x;
    this.doc.y = y;
    this.restore();
  }

  /**
   * Stamps `page N of M` on every page but the cover, now that M is known, and
   * closes the document.
   */
  async finish(): Promise<Uint8Array> {
    const range = this.doc.bufferedPageRange();
    const total = range.count;
    // The cover is page 0 of the buffer and is not numbered; the reader counts
    // from the first content page, which is what "page 1 of N" has to mean.
    const numbered = Math.max(0, total - 1);

    for (let index = 1; index < total; index += 1) {
      this.doc.switchToPage(range.start + index);
      this.doc.font(FONT.regular).fontSize(SIZE.tiny).fillColor(COLOR.muted);
      this.doc
        .moveTo(CONTENT.left, CHROME.footerRule)
        .lineTo(CONTENT.right, CHROME.footerRule)
        .lineWidth(0.5)
        .stroke(COLOR.hairline);
      this.doc.font(FONT.regular).fontSize(SIZE.tiny).fillColor(COLOR.muted);
      this.doc.text(toWinAnsi(this.options.runId), CONTENT.left, CHROME.footerBaseline, {
        lineBreak: false,
      });
      const stamp = `page ${index} of ${numbered}`;
      const width = this.doc.widthOfString(stamp);
      this.doc.text(stamp, CONTENT.right - width, CHROME.footerBaseline, { lineBreak: false });
    }

    this.doc.flushPages();
    this.doc.end();
    await this.#ended;

    const size = this.#chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of this.#chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    this.#chunks = [];
    return bytes;
  }
}

/** Creates the canvas the report draws on. */
export function createCanvas(options: CanvasOptions): ReportCanvas {
  return new ReportCanvas(options);
}
