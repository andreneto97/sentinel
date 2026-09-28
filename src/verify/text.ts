/** Byte-level and line-level text handling shared by snippet extraction and relocation. */

const BINARY_SAMPLE_BYTES = 8000;
const CONTROL_BYTE_RATIO = 0.3;

/** Decodes UTF-8 bytes to a string, dropping a leading byte-order mark. */
export function decodeUtf8(bytes: Uint8Array): string {
  const text = new TextDecoder("utf-8").decode(bytes);
  return text.startsWith("﻿") ? text.slice(1) : text;
}

/**
 * True when the bytes look like a binary file. A NUL byte settles it (that also
 * catches UTF-16); otherwise a sample dominated by control bytes does.
 */
export function looksBinary(bytes: Uint8Array): boolean {
  const sample = Math.min(bytes.length, BINARY_SAMPLE_BYTES);
  if (sample === 0) return false;
  let control = 0;
  for (let i = 0; i < sample; i += 1) {
    const byte = bytes[i] ?? 0;
    if (byte === 0) return true;
    const printable = byte >= 0x20 || byte === 0x09 || byte === 0x0a || byte === 0x0d;
    if (!printable || byte === 0x7f) control += 1;
  }
  return control / sample > CONTROL_BYTE_RATIO;
}

/**
 * Splits text into lines on LF, CRLF or lone CR, without the terminators, so a
 * CRLF file has the same line numbers as the editor shows.
 */
export function splitLines(text: string): string[] {
  if (text === "") return [];
  const lines = text.split(/\r\n|\n|\r/);
  // A trailing terminator ends the last line; it does not open a new one.
  if (lines.length > 1 && lines[lines.length - 1] === "") lines.pop();
  return lines;
}

/** Expands tabs to the next tab stop so snippets line up wherever they are rendered. */
export function expandTabs(line: string, tabWidth: number): string {
  if (!line.includes("\t")) return line;
  const width = Math.max(1, tabWidth);
  let out = "";
  let column = 0;
  for (const char of line) {
    if (char === "\t") {
      const pad = width - (column % width);
      out += " ".repeat(pad);
      column += pad;
    } else {
      out += char;
      column += 1;
    }
  }
  return out;
}

/** Truncates an over-wide line, marking the cut with an ellipsis. */
export function truncate(line: string, maxWidth: number): string {
  if (maxWidth <= 1 || line.length <= maxWidth) return line;
  return `${line.slice(0, maxWidth - 1)}…`;
}

/** Number of leading spaces on a line, or `null` for a blank line. */
export function leadingSpaces(line: string): number | null {
  if (line.trim() === "") return null;
  return line.length - line.trimStart().length;
}
