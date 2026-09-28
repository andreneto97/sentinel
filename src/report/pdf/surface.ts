/**
 * The drawing seam.
 *
 * pdfkit's `PDFDocument` is a large, stateful, stream-backed object; asserting
 * that a donut closes by parsing the PDF it produces would be a test of pdfkit,
 * not of Sentinel. So everything that draws takes one of these narrow
 * structural interfaces instead. `PDFDocument` satisfies them as they are
 * written (TypeScript's method parameters are bivariant, and a method returning
 * `this` is assignable to one returning `void`), and a test passes a recorder
 * that keeps the calls.
 *
 * This is the same seam discipline as `src/ports`, one level down: the port
 * modules keep the process off the disk, these interfaces keep the report
 * testable without one.
 */

/** Path construction and painting — everything the charts need and nothing else. */
export interface VectorSurface {
  moveTo(x: number, y: number): void;
  lineTo(x: number, y: number): void;
  bezierCurveTo(cp1x: number, cp1y: number, cp2x: number, cp2y: number, x: number, y: number): void;
  closePath(): void;
  rect(x: number, y: number, width: number, height: number): void;
  roundedRect(x: number, y: number, width: number, height: number, radius?: number): void;
  circle(x: number, y: number, radius: number): void;
  /** Fills the current path. The colour is passed per call; no fill state leaks. */
  fill(color?: string): void;
  /** Strokes the current path. */
  stroke(color?: string): void;
  lineWidth(width: number): void;
  save(): void;
  restore(): void;
}

/** Text placement and measurement. */
export interface TextSurface {
  font(name: string): void;
  fontSize(size: number): void;
  fillColor(color: string): void;
  text(text: string, x: number, y: number, options?: TextOptions): void;
  widthOfString(text: string): number;
  heightOfString(text: string, options?: TextOptions): number;
  currentLineHeight(includeGap?: boolean): number;
}

/** The subset of pdfkit's text options the report uses. */
export interface TextOptions {
  width?: number | undefined;
  align?: "left" | "center" | "right" | "justify" | undefined;
  lineBreak?: boolean | undefined;
  lineGap?: number | undefined;
  /** Pdfkit's own name for "do not move the cursor"; used for measured blocks. */
  continued?: boolean | undefined;
  characterSpacing?: number | undefined;
  link?: string | undefined;
  underline?: boolean | undefined;
  ellipsis?: boolean | string | undefined;
  height?: number | undefined;
}

/** Everything a chart draws with. */
export interface ChartSurface extends VectorSurface, TextSurface {}

/** One recorded call, as {@link RecordingSurface} keeps it. */
export interface DrawCall {
  readonly op: string;
  readonly args: readonly (number | string | boolean | undefined)[];
}

/**
 * A `ChartSurface` that records instead of drawing, for tests.
 *
 * `widthOfString` returns a deterministic monospace-like estimate rather than
 * real font metrics: a layout assertion that depended on Helvetica's kerning
 * would be asserting the font, not the layout.
 */
export class RecordingSurface implements ChartSurface {
  readonly calls: DrawCall[] = [];
  #size = 10;

  #push(op: string, ...args: (number | string | boolean | undefined)[]): void {
    this.calls.push({ op, args });
  }

  /** Every recorded call of one kind, in order. */
  of(op: string): DrawCall[] {
    return this.calls.filter((call) => call.op === op);
  }

  moveTo(x: number, y: number): void {
    this.#push("moveTo", x, y);
  }
  lineTo(x: number, y: number): void {
    this.#push("lineTo", x, y);
  }
  bezierCurveTo(
    cp1x: number,
    cp1y: number,
    cp2x: number,
    cp2y: number,
    x: number,
    y: number,
  ): void {
    this.#push("bezierCurveTo", cp1x, cp1y, cp2x, cp2y, x, y);
  }
  closePath(): void {
    this.#push("closePath");
  }
  rect(x: number, y: number, width: number, height: number): void {
    this.#push("rect", x, y, width, height);
  }
  roundedRect(x: number, y: number, width: number, height: number, radius?: number): void {
    this.#push("roundedRect", x, y, width, height, radius);
  }
  circle(x: number, y: number, radius: number): void {
    this.#push("circle", x, y, radius);
  }
  fill(color?: string): void {
    this.#push("fill", color);
  }
  stroke(color?: string): void {
    this.#push("stroke", color);
  }
  lineWidth(width: number): void {
    this.#push("lineWidth", width);
  }
  save(): void {
    this.#push("save");
  }
  restore(): void {
    this.#push("restore");
  }
  font(name: string): void {
    this.#push("font", name);
  }
  fontSize(size: number): void {
    this.#size = size;
    this.#push("fontSize", size);
  }
  fillColor(color: string): void {
    this.#push("fillColor", color);
  }
  text(text: string, x: number, y: number, options?: TextOptions): void {
    this.#push("text", text, x, y, options?.width);
  }
  widthOfString(text: string): number {
    return text.length * this.#size * 0.5;
  }
  heightOfString(text: string, options?: TextOptions): number {
    const width = options?.width ?? 1000;
    const perLine = Math.max(1, Math.ceil(this.widthOfString(text) / width));
    return perLine * this.#size * 1.2;
  }
  currentLineHeight(): number {
    return this.#size * 1.2;
  }
}
