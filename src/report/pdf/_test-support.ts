/**
 * Helpers the PDF tests share.
 *
 * Reading a rendered PDF back is the only way to assert on what was actually
 * stamped — a footer that says `page 3 of 48` cannot be checked from the call
 * that asked for it — so this module decodes pdfkit's text-showing operators
 * and offers a canvas with compression turned off for tests to render into.
 *
 * Not part of the module's public surface; `index.ts` does not export it.
 */

import { type CanvasOptions, type ReportCanvas, createCanvas } from "./layout.ts";

/** A canvas whose content streams are readable, for a test to assert against. */
export function testCanvas(options: Partial<CanvasOptions> = {}): ReportCanvas {
  return createCanvas({
    title: "Backend Dossier",
    subject: "example-api",
    runId: "20260304T093000-9f2c41ab",
    createdAt: new Date("2026-03-04T09:30:00Z"),
    compress: false,
    ...options,
  });
}

/** Decodes one hex-encoded string run from a PDF text operator. */
function decodeRun(hex: string): string {
  return hex.replace(/../g, (pair) => String.fromCharCode(Number.parseInt(pair, 16)));
}

/**
 * The PDF's bytes with every text-showing array replaced by the text it draws.
 *
 * pdfkit writes a line as `[<48656c6c> 20 <6f>] TJ`: hex runs separated by
 * kerning adjustments. Joining the runs of one array and dropping the numbers
 * gives back the string, which is enough to assert on content without
 * implementing a PDF reader. Requires a canvas built with `compress: false`.
 */
export function decodePdfText(bytes: Uint8Array): string {
  const raw = new TextDecoder("latin1").decode(bytes);
  return raw.replace(/\[((?:\s*<[0-9a-fA-F]*>|\s*-?[\d.]+)*)\s*\]\s*TJ/g, (_match, body: string) =>
    [...body.matchAll(/<([0-9a-fA-F]*)>/g)].map((run) => decodeRun(run[1] ?? "")).join(""),
  );
}

/** How many times `needle` occurs in `haystack`. */
export function occurrences(haystack: string, needle: string): number {
  return haystack.split(needle).length - 1;
}
