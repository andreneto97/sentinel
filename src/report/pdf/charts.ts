/**
 * The two charts, drawn with nothing but PDF path primitives.
 *
 * `geometry.ts` decides where every point goes; this module replays those points
 * onto a surface and adds the labels. The split is what makes the arcs
 * testable, and it keeps the only pdfkit-specific knowledge here down to "fill
 * takes a colour".
 *
 * Both charts say their numbers in text as well as in colour. A dossier is
 * printed, photocopied and read by people who cannot tell `#EA580C` from
 * `#D97706`, so the chart is the summary and the number is the evidence.
 */

import { type BarLayout, type ChartDatum, barLayout, donutLayout } from "./geometry.ts";
import type { ChartSurface } from "./surface.ts";
import { toWinAnsi } from "./text.ts";
import { COLOR, FONT, SIZE } from "./theme.ts";

/** Where and how big the donut is, and what it divides. */
export interface DonutSpec {
  readonly cx: number;
  readonly cy: number;
  readonly outerRadius: number;
  readonly innerRadius: number;
  readonly data: readonly ChartDatum[];
  /** Printed large in the hole; the total, unless the caller wants another number. */
  readonly centerValue?: string | undefined;
  /** Printed small under it. */
  readonly centerLabel?: string | undefined;
}

/** What was drawn, so a caller can lay out a legend against the same numbers. */
export interface DonutResult {
  readonly total: number;
  readonly drawn: number;
}

/**
 * Draws a donut by severity.
 *
 * With nothing to divide, the ring is still drawn — as an outline — and the hole
 * says zero. An absent chart would read as a rendering failure; an empty ring
 * reads as the finding it is.
 */
export function drawDonut(surface: ChartSurface, spec: DonutSpec): DonutResult {
  const layout = donutLayout(spec.data, {
    cx: spec.cx,
    cy: spec.cy,
    outerRadius: spec.outerRadius,
    innerRadius: spec.innerRadius,
  });

  if (layout.total === 0) {
    surface.lineWidth(0.75);
    surface.circle(spec.cx, spec.cy, spec.outerRadius);
    surface.stroke(COLOR.hairline);
    surface.circle(spec.cx, spec.cy, spec.innerRadius);
    surface.stroke(COLOR.hairline);
  }

  for (const slice of layout.slices) {
    for (const op of slice.path) {
      switch (op.op) {
        case "moveTo":
          surface.moveTo(op.to.x, op.to.y);
          break;
        case "lineTo":
          surface.lineTo(op.to.x, op.to.y);
          break;
        case "bezierCurveTo":
          surface.bezierCurveTo(op.c1.x, op.c1.y, op.c2.x, op.c2.y, op.to.x, op.to.y);
          break;
        case "closePath":
          surface.closePath();
          break;
      }
    }
    surface.fill(slice.color);
  }

  const value = spec.centerValue ?? String(layout.total);
  surface.font(FONT.bold);
  surface.fontSize(SIZE.h1);
  surface.fillColor(COLOR.ink);
  const valueWidth = surface.widthOfString(value);
  surface.text(value, spec.cx - valueWidth / 2, spec.cy - SIZE.h1 * 0.72, { lineBreak: false });

  if (spec.centerLabel !== undefined) {
    const label = toWinAnsi(spec.centerLabel);
    surface.font(FONT.regular);
    surface.fontSize(SIZE.tiny);
    surface.fillColor(COLOR.muted);
    const labelWidth = surface.widthOfString(label);
    surface.text(label, spec.cx - labelWidth / 2, spec.cy + 2, { lineBreak: false });
  }

  return { total: layout.total, drawn: layout.slices.length };
}

/** One row of the bar chart: a domain, and the severities inside it. */
export interface BarGroup {
  readonly key: string;
  readonly label: string;
  readonly data: readonly ChartDatum[];
  /** Printed instead of the total, for a domain that was not assessed. */
  readonly note?: string | undefined;
}

/** Where and how big the bar chart is. */
export interface BarsSpec {
  readonly x: number;
  readonly y: number;
  /** Gutter for the row labels, right-aligned against the bars. */
  readonly labelWidth: number;
  /** The plotting area the longest bar fills. */
  readonly barWidth: number;
  /** Gutter after the bars for the row total. */
  readonly valueWidth: number;
  readonly rowHeight: number;
  readonly rowGap: number;
  readonly groups: readonly BarGroup[];
}

/**
 * Draws horizontal stacked bars, one row per domain.
 *
 * Every row is drawn on a track of the full width, so a domain with no findings
 * shows an empty track — visibly zero — instead of vanishing. A domain that was
 * never assessed says so in the value column, where a `0` would be a lie.
 */
export function drawBars(surface: ChartSurface, spec: BarsSpec): BarLayout {
  const barsLeft = spec.x + spec.labelWidth + 6;
  const layout = barLayout(
    spec.groups.map((group) => ({ key: group.key, label: group.label, data: group.data })),
    {
      x: barsLeft,
      y: spec.y,
      width: spec.barWidth,
      rowHeight: spec.rowHeight,
      rowGap: spec.rowGap,
    },
  );

  layout.rows.forEach((row, index) => {
    const group = spec.groups[index];
    surface.font(FONT.regular);
    surface.fontSize(SIZE.tiny);
    surface.fillColor(COLOR.body);
    const label = toWinAnsi(row.label);
    const labelWidth = surface.widthOfString(label);
    surface.text(
      label,
      spec.x + Math.max(0, spec.labelWidth - labelWidth),
      row.y + spec.rowHeight / 2 - SIZE.tiny * 0.62,
      { lineBreak: false },
    );

    surface.rect(barsLeft, row.y, spec.barWidth, spec.rowHeight);
    surface.fill(COLOR.panel);
    for (const segment of row.segments) {
      surface.rect(segment.x, segment.y, segment.width, segment.height);
      surface.fill(segment.color);
    }

    const note = group?.note;
    surface.font(note === undefined ? FONT.bold : FONT.italic);
    surface.fontSize(SIZE.tiny);
    surface.fillColor(note === undefined ? COLOR.ink : COLOR.muted);
    const value = toWinAnsi(note ?? String(row.total));
    surface.text(
      value,
      barsLeft + spec.barWidth + 6,
      row.y + spec.rowHeight / 2 - SIZE.tiny * 0.62,
      {
        lineBreak: false,
      },
    );
  });

  return layout;
}
