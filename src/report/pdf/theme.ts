/**
 * Every constant the PDF looks like.
 *
 * Colour is load-bearing in this document — a severity chip is read before the
 * word next to it — so the palette is fixed here and nowhere else. The five
 * severity colours and the strength green are specified by the plan and must
 * not drift; the neutrals around them are chosen to stay legible when the
 * dossier is printed in greyscale, which is how a client usually reads it.
 *
 * Geometry is in PostScript points (72 per inch), the unit pdfkit takes.
 */

import type { Severity } from "../../contracts/findings.ts";

/** A4 in points, the only page size Sentinel renders. */
export const PAGE = {
  width: 595.28,
  height: 841.89,
  /** ~2cm on every side; the header and footer live outside it. */
  margin: 56.7,
} as const;

/** The flowing content box, in absolute page coordinates. */
export const CONTENT = {
  left: PAGE.margin,
  right: PAGE.width - PAGE.margin,
  top: PAGE.margin,
  bottom: PAGE.height - PAGE.margin,
  width: PAGE.width - 2 * PAGE.margin,
} as const;

/** Where the running header and the `page N of M` footer sit, inside the margin band. */
export const CHROME = {
  headerBaseline: PAGE.margin - 26,
  headerRule: PAGE.margin - 14,
  footerBaseline: PAGE.height - PAGE.margin + 22,
  footerRule: PAGE.height - PAGE.margin + 14,
} as const;

/**
 * The severity palette, exactly as the plan specifies it.
 *
 * `info` is grey on purpose: an informational finding that shouts in colour
 * teaches the reader to distrust the colours that matter.
 */
export const SEVERITY_COLOR: Readonly<Record<Severity, string>> = {
  critical: "#B91C1C",
  high: "#EA580C",
  medium: "#D97706",
  low: "#2563EB",
  info: "#6B7280",
} as const;

/** The counterpart of the severity palette: what is protected, not what is broken. */
export const STRENGTH_COLOR = "#059669";

/** Neutrals. Every one of them keeps its contrast in greyscale. */
export const COLOR = {
  /** Headings and chip text on light fills. */
  ink: "#111827",
  /** Body copy. */
  body: "#374151",
  /** Captions, units, "not assessed" — present but subordinate. */
  muted: "#6B7280",
  /** Table and box borders. */
  hairline: "#D1D5DB",
  /** Panel fills (table header rows, callouts). */
  panel: "#F3F4F6",
  /** Code box fill. */
  code: "#F8FAFC",
  /** Text on a saturated fill. */
  onColor: "#FFFFFF",
  /** The page itself, used to knock holes in vector art. */
  page: "#FFFFFF",
  strength: STRENGTH_COLOR,
} as const;

/** The base-14 fonts, which embed nothing and render identically everywhere. */
export const FONT = {
  regular: "Helvetica",
  bold: "Helvetica-Bold",
  italic: "Helvetica-Oblique",
  mono: "Courier",
  monoBold: "Courier-Bold",
} as const;

/** Type scale. `code` drives the snippet box, whose width budget depends on it. */
export const SIZE = {
  title: 30,
  subtitle: 13,
  h1: 16,
  h2: 11.5,
  h3: 9.5,
  body: 9.5,
  small: 8,
  tiny: 7,
  code: 7.5,
} as const;

/** Vertical rhythm. */
export const SPACE = {
  line: 1.35,
  paragraph: 6,
  block: 12,
  section: 18,
} as const;

/** Courier is metrically fixed at 0.6em, which is what makes the code box measurable. */
export const MONO_ADVANCE = 0.6;

/** Bands the scorecard may report, worst last, with the colour each one earns. */
export const BAND_COLOR: Readonly<Record<string, string>> = {
  A: STRENGTH_COLOR,
  B: STRENGTH_COLOR,
  C: SEVERITY_COLOR.medium,
  D: SEVERITY_COLOR.high,
  E: SEVERITY_COLOR.high,
  F: SEVERITY_COLOR.critical,
} as const;

/** The colour for a band letter, defaulting to grey for anything unrecognised. */
export function bandColor(band: string | undefined): string {
  if (band === undefined) return COLOR.muted;
  return BAND_COLOR[band.trim().charAt(0).toUpperCase()] ?? COLOR.muted;
}
