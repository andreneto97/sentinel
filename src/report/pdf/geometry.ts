/**
 * Chart geometry, as data.
 *
 * There is no chart library in this project and none is being added, so the
 * donut and the bars are built from the primitives a PDF understands: lines and
 * cubic beziers. That makes the arithmetic Sentinel's own, which makes it
 * testable — every function here returns a description of a shape instead of
 * drawing one, and `charts.ts` is the only thing that replays those
 * descriptions onto a surface.
 *
 * Coordinates are PDF user space: x grows right, y grows **down** the page
 * (pdfkit flips the PDF's native axis), so an angle of 0 points right and
 * angles increase clockwise on the printed page. Every angle is in radians.
 */

/** A point in PDF user space. */
export interface Point {
  readonly x: number;
  readonly y: number;
}

/** One cubic bezier hop, continuing from wherever the pen already is. */
export interface BezierSegment {
  readonly c1: Point;
  readonly c2: Point;
  readonly to: Point;
}

/** An arc approximated by beziers: where the pen starts, and the hops from there. */
export interface Arc {
  readonly from: Point;
  readonly segments: readonly BezierSegment[];
}

/** A path operation, in the vocabulary of {@link import("./surface.ts").VectorSurface}. */
export type PathOp =
  | { readonly op: "moveTo"; readonly to: Point }
  | { readonly op: "lineTo"; readonly to: Point }
  | { readonly op: "bezierCurveTo"; readonly c1: Point; readonly c2: Point; readonly to: Point }
  | { readonly op: "closePath" };

/** A quarter turn is the largest arc a single cubic bezier approximates well. */
const MAX_SEGMENT_ANGLE = Math.PI / 2;

/** Angles closer than this are the same angle; below it an arc is not a shape. */
export const ANGLE_EPSILON = 1e-9;

/** The point at `angle` on the circle of radius `r` centred on `(cx, cy)`. */
export function pointOnCircle(cx: number, cy: number, r: number, angle: number): Point {
  return { x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle) };
}

/**
 * Approximates the arc from `startAngle` to `endAngle` with cubic beziers.
 *
 * The arc is split so no segment spans more than a quarter turn — past that the
 * bezier approximation visibly deflates — and each segment uses the standard
 * control-point distance `k = 4/3 · tan(Δ/4)`, which puts the curve's midpoint
 * exactly on the circle. Sweeping backwards (`endAngle < startAngle`) is
 * supported and is what draws a ring's inner edge in reverse.
 */
export function arc(cx: number, cy: number, r: number, startAngle: number, endAngle: number): Arc {
  const from = pointOnCircle(cx, cy, r, startAngle);
  const sweep = endAngle - startAngle;
  if (Math.abs(sweep) < ANGLE_EPSILON) return { from, segments: [] };

  const count = Math.max(1, Math.ceil(Math.abs(sweep) / MAX_SEGMENT_ANGLE));
  const step = sweep / count;
  const k = (4 / 3) * Math.tan(step / 4);

  const segments: BezierSegment[] = [];
  for (let index = 0; index < count; index += 1) {
    const a0 = startAngle + step * index;
    const a1 = a0 + step;
    const p0 = pointOnCircle(cx, cy, r, a0);
    const p1 = pointOnCircle(cx, cy, r, a1);
    segments.push({
      c1: { x: p0.x - k * r * Math.sin(a0), y: p0.y + k * r * Math.cos(a0) },
      c2: { x: p1.x + k * r * Math.sin(a1), y: p1.y - k * r * Math.cos(a1) },
      to: p1,
    });
  }
  return { from, segments };
}

/** Turns an arc into path ops, starting a new subpath unless `continuing`. */
export function arcOps(shape: Arc, continuing = false): PathOp[] {
  const ops: PathOp[] = continuing ? [] : [{ op: "moveTo", to: shape.from }];
  for (const segment of shape.segments) {
    ops.push({ op: "bezierCurveTo", c1: segment.c1, c2: segment.c2, to: segment.to });
  }
  return ops;
}

/**
 * The closed path of one donut slice: out along the outer edge, in, back along
 * the inner edge, closed.
 *
 * The inner edge is swept in the opposite direction, so a slice that spans the
 * whole circle still leaves a hole under the nonzero winding rule instead of
 * painting a filled disc.
 */
export function donutSlicePath(
  cx: number,
  cy: number,
  outerRadius: number,
  innerRadius: number,
  startAngle: number,
  endAngle: number,
): PathOp[] {
  if (Math.abs(endAngle - startAngle) < ANGLE_EPSILON) return [];
  const outer = arc(cx, cy, outerRadius, startAngle, endAngle);
  const inner = arc(cx, cy, innerRadius, endAngle, startAngle);
  return [
    ...arcOps(outer),
    { op: "lineTo", to: inner.from },
    ...arcOps(inner, true),
    { op: "closePath" },
  ];
}

/** One input value of a chart: what it counts, how much, and in which colour. */
export interface ChartDatum {
  readonly key: string;
  readonly label: string;
  readonly value: number;
  readonly color: string;
}

/** One slice of a laid-out donut. */
export interface DonutSlice extends ChartDatum {
  readonly fraction: number;
  readonly startAngle: number;
  readonly endAngle: number;
  readonly path: readonly PathOp[];
}

/** A laid-out donut: its slices, and the total they divide. */
export interface DonutLayout {
  readonly total: number;
  readonly slices: readonly DonutSlice[];
}

/** Where a donut starts sweeping: the top of the circle, going clockwise. */
const DONUT_START = -Math.PI / 2;

/**
 * Lays out a donut.
 *
 * A datum whose value is zero or negative is dropped rather than drawn: a
 * zero-width slice still paints a one-point sliver of colour, and a reader who
 * sees red on a chart with no critical findings will not believe the next
 * chart either. The legend states the zero instead.
 */
export function donutLayout(
  data: readonly ChartDatum[],
  options: {
    readonly cx: number;
    readonly cy: number;
    readonly outerRadius: number;
    readonly innerRadius: number;
    readonly startAngle?: number;
  },
): DonutLayout {
  const positive = data.filter((datum) => datum.value > 0);
  const total = positive.reduce((sum, datum) => sum + datum.value, 0);
  if (total <= 0) return { total: 0, slices: [] };

  const slices: DonutSlice[] = [];
  let angle = options.startAngle ?? DONUT_START;
  positive.forEach((datum, index) => {
    const fraction = datum.value / total;
    // The last slice closes on the exact start angle rather than on the sum of
    // rounded fractions, so a full ring never leaves a hairline gap.
    const end =
      index === positive.length - 1
        ? (options.startAngle ?? DONUT_START) + 2 * Math.PI
        : angle + fraction * 2 * Math.PI;
    slices.push({
      ...datum,
      fraction,
      startAngle: angle,
      endAngle: end,
      path: donutSlicePath(
        options.cx,
        options.cy,
        options.outerRadius,
        options.innerRadius,
        angle,
        end,
      ),
    });
    angle = end;
  });
  return { total, slices };
}

/** One drawn rectangle of a bar row. */
export interface BarSegment extends ChartDatum {
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height: number;
}

/** One row of the bar chart: a label, its segments, and the total they sum to. */
export interface BarRow {
  readonly key: string;
  readonly label: string;
  readonly total: number;
  readonly y: number;
  readonly height: number;
  readonly segments: readonly BarSegment[];
}

/** A laid-out bar chart. */
export interface BarLayout {
  readonly rows: readonly BarRow[];
  readonly max: number;
  readonly height: number;
}

/**
 * Lays out horizontal stacked bars, one row per group.
 *
 * `minSegmentWidth` is the honest counterpart of the donut's dropped zero: a
 * row with a single low finding must show *something*, so a positive value is
 * never thinner than that, while a zero value produces no rectangle at all. The
 * distortion is bounded by a point and a half and the count is printed beside
 * the bar anyway.
 */
export function barLayout(
  groups: readonly {
    readonly key: string;
    readonly label: string;
    readonly data: readonly ChartDatum[];
  }[],
  options: {
    readonly x: number;
    readonly y: number;
    readonly width: number;
    readonly rowHeight: number;
    readonly rowGap: number;
    readonly minSegmentWidth?: number;
    readonly max?: number;
  },
): BarLayout {
  const totals = groups.map((group) =>
    group.data.reduce((sum, datum) => sum + Math.max(0, datum.value), 0),
  );
  const max = Math.max(options.max ?? 0, ...totals, 1);
  const minWidth = options.minSegmentWidth ?? 1.5;
  const rows: BarRow[] = [];

  groups.forEach((group, index) => {
    const y = options.y + index * (options.rowHeight + options.rowGap);
    const segments: BarSegment[] = [];
    let x = options.x;
    for (const datum of group.data) {
      if (datum.value <= 0) continue;
      const width = Math.max(minWidth, (datum.value / max) * options.width);
      segments.push({ ...datum, x, y, width, height: options.rowHeight });
      x += width;
    }
    rows.push({
      key: group.key,
      label: group.label,
      total: totals[index] ?? 0,
      y,
      height: options.rowHeight,
      segments,
    });
  });

  const height =
    groups.length === 0
      ? 0
      : groups.length * options.rowHeight + (groups.length - 1) * options.rowGap;
  return { rows, max, height };
}
