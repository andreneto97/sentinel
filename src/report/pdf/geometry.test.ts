import { describe, expect, test } from "bun:test";
import {
  ANGLE_EPSILON,
  type ChartDatum,
  type Point,
  arc,
  arcOps,
  barLayout,
  donutLayout,
  donutSlicePath,
  pointOnCircle,
} from "./geometry.ts";

/** How far a bezier approximation may sit from the true circle, in points. */
const TOLERANCE = 0.02;

/** Distance between two points; the only assertion geometry ever needs. */
function distance(a: Point, b: Point): number {
  return Math.hypot(a.x - b.x, a.y - b.y);
}

/** Cubic bezier evaluated at `t`, to check the curve is really on the circle. */
function bezierAt(p0: Point, c1: Point, c2: Point, p3: Point, t: number): Point {
  const u = 1 - t;
  const w0 = u * u * u;
  const w1 = 3 * u * u * t;
  const w2 = 3 * u * t * t;
  const w3 = t * t * t;
  return {
    x: w0 * p0.x + w1 * c1.x + w2 * c2.x + w3 * p3.x,
    y: w0 * p0.y + w1 * c1.y + w2 * c2.y + w3 * p3.y,
  };
}

describe("arc", () => {
  test("splits anything wider than a quarter turn, which is where beziers deflate", () => {
    expect(arc(0, 0, 10, 0, Math.PI / 2).segments).toHaveLength(1);
    expect(arc(0, 0, 10, 0, Math.PI / 2 + 0.01).segments).toHaveLength(2);
    expect(arc(0, 0, 10, 0, Math.PI).segments).toHaveLength(2);
    expect(arc(0, 0, 10, 0, 2 * Math.PI).segments).toHaveLength(4);
  });

  test("every control point puts the curve back on the circle", () => {
    const radius = 42;
    const shape = arc(100, 200, radius, -Math.PI / 2, Math.PI);
    let cursor = shape.from;
    for (const segment of shape.segments) {
      for (const t of [0, 0.25, 0.5, 0.75, 1]) {
        const on = bezierAt(cursor, segment.c1, segment.c2, segment.to, t);
        expect(Math.abs(distance(on, { x: 100, y: 200 }) - radius)).toBeLessThan(TOLERANCE);
      }
      cursor = segment.to;
    }
  });

  test("a full turn ends where it began, so the ring has no hairline seam", () => {
    const shape = arc(50, 50, 20, -Math.PI / 2, -Math.PI / 2 + 2 * Math.PI);
    const last = shape.segments.at(-1);
    expect(last).toBeDefined();
    expect(distance(last?.to ?? shape.from, shape.from)).toBeLessThan(1e-9);
  });

  test("sweeping backwards retraces the same points in reverse", () => {
    const forward = arc(0, 0, 10, 0, Math.PI / 2);
    const backward = arc(0, 0, 10, Math.PI / 2, 0);
    expect(distance(backward.from, forward.segments[0]?.to ?? forward.from)).toBeLessThan(1e-9);
    expect(distance(backward.segments[0]?.to ?? backward.from, forward.from)).toBeLessThan(1e-9);
  });

  test("an arc of no width has no segments at all", () => {
    expect(arc(0, 0, 10, 1, 1 + ANGLE_EPSILON / 2).segments).toHaveLength(0);
  });
});

describe("donutSlicePath", () => {
  test("closes: the inner sweep returns to the point the outer sweep left from", () => {
    const ops = donutSlicePath(100, 100, 40, 24, -Math.PI / 2, 0.4);
    expect(ops[0]?.op).toBe("moveTo");
    expect(ops.at(-1)?.op).toBe("closePath");

    const start = ops[0]?.op === "moveTo" ? ops[0].to : undefined;
    expect(start).toBeDefined();
    // The last curve of the inner sweep must land on the inner radius at the
    // slice's start angle, which is a straight line back to `start`.
    const curves = ops.filter((op) => op.op === "bezierCurveTo");
    const lastPoint = curves.at(-1)?.op === "bezierCurveTo" ? curves.at(-1) : undefined;
    const end = lastPoint?.op === "bezierCurveTo" ? lastPoint.to : undefined;
    expect(end).toBeDefined();
    expect(Math.abs(distance(end ?? { x: 0, y: 0 }, { x: 100, y: 100 }) - 24)).toBeLessThan(
      TOLERANCE,
    );
    const angleOfEnd = Math.atan2((end?.y ?? 0) - 100, (end?.x ?? 0) - 100);
    expect(Math.abs(angleOfEnd - -Math.PI / 2)).toBeLessThan(1e-6);
  });

  test("a full ring keeps its hole: outer and inner sweeps run in opposite directions", () => {
    const ops = donutSlicePath(0, 0, 30, 18, 0, 2 * Math.PI);
    const curves = ops.filter((op) => op.op === "bezierCurveTo");
    // Four quarters out, four quarters back.
    expect(curves).toHaveLength(8);
    const outerEnd = curves[3];
    const first = ops[0];
    expect(first?.op).toBe("moveTo");
    if (first?.op === "moveTo" && outerEnd?.op === "bezierCurveTo") {
      expect(distance(outerEnd.to, first.to)).toBeLessThan(1e-9);
    }
    const bridge = ops.find((op) => op.op === "lineTo");
    expect(bridge?.op).toBe("lineTo");
    if (bridge?.op === "lineTo") {
      expect(Math.abs(distance(bridge.to, { x: 0, y: 0 }) - 18)).toBeLessThan(1e-9);
    }
  });

  test("a slice of no width emits no path, so a zero never paints a sliver", () => {
    expect(donutSlicePath(0, 0, 30, 18, 1.2, 1.2)).toHaveLength(0);
  });
});

describe("arcOps", () => {
  test("continuing an arc does not lift the pen", () => {
    const shape = arc(0, 0, 5, 0, 1);
    expect(arcOps(shape)[0]?.op).toBe("moveTo");
    expect(arcOps(shape, true)[0]?.op).toBe("bezierCurveTo");
  });
});

/** The severity data the executive summary feeds the donut. */
function severities(counts: Partial<Record<string, number>>): ChartDatum[] {
  return [
    { key: "critical", label: "Critical", value: counts.critical ?? 0, color: "#B91C1C" },
    { key: "high", label: "High", value: counts.high ?? 0, color: "#EA580C" },
    { key: "medium", label: "Medium", value: counts.medium ?? 0, color: "#D97706" },
    { key: "low", label: "Low", value: counts.low ?? 0, color: "#2563EB" },
    { key: "info", label: "Info", value: counts.info ?? 0, color: "#6B7280" },
  ];
}

describe("donutLayout", () => {
  test("drops zero-valued severities instead of drawing them", () => {
    const layout = donutLayout(severities({ medium: 10, low: 28, info: 38 }), {
      cx: 100,
      cy: 100,
      outerRadius: 40,
      innerRadius: 25,
    });
    expect(layout.total).toBe(76);
    expect(layout.slices.map((slice) => slice.key)).toEqual(["medium", "low", "info"]);
    expect(layout.slices.every((slice) => slice.path.length > 0)).toBe(true);
  });

  test("the slices tile the circle exactly once", () => {
    const layout = donutLayout(
      severities({ critical: 1, high: 2, medium: 10, low: 28, info: 38 }),
      {
        cx: 0,
        cy: 0,
        outerRadius: 40,
        innerRadius: 25,
      },
    );
    const swept = layout.slices.reduce(
      (sum, slice) => sum + (slice.endAngle - slice.startAngle),
      0,
    );
    expect(Math.abs(swept - 2 * Math.PI)).toBeLessThan(1e-9);
    for (let index = 1; index < layout.slices.length; index += 1) {
      expect(layout.slices[index]?.startAngle).toBe(layout.slices[index - 1]?.endAngle);
    }
    expect(layout.slices.reduce((sum, slice) => sum + slice.fraction, 0)).toBeCloseTo(1, 12);
  });

  test("one non-zero severity produces a closed full ring, not a disc", () => {
    const layout = donutLayout(severities({ low: 4 }), {
      cx: 0,
      cy: 0,
      outerRadius: 30,
      innerRadius: 18,
    });
    expect(layout.slices).toHaveLength(1);
    const slice = layout.slices[0];
    expect(slice?.fraction).toBe(1);
    expect((slice?.endAngle ?? 0) - (slice?.startAngle ?? 0)).toBeCloseTo(2 * Math.PI, 12);
    expect(slice?.path.filter((op) => op.op === "bezierCurveTo")).toHaveLength(8);
  });

  test("no findings at all lays out nothing, so the caller can say so in words", () => {
    const layout = donutLayout(severities({}), {
      cx: 0,
      cy: 0,
      outerRadius: 30,
      innerRadius: 18,
    });
    expect(layout).toEqual({ total: 0, slices: [] });
  });

  test("the last slice closes on the start angle rather than on rounded fractions", () => {
    const thirds = [
      { key: "a", label: "a", value: 1, color: "#000" },
      { key: "b", label: "b", value: 1, color: "#111" },
      { key: "c", label: "c", value: 1, color: "#222" },
    ];
    const layout = donutLayout(thirds, { cx: 0, cy: 0, outerRadius: 10, innerRadius: 6 });
    const last = layout.slices.at(-1);
    expect(last?.endAngle).toBe(-Math.PI / 2 + 2 * Math.PI);
  });
});

describe("barLayout", () => {
  const groups = [
    {
      key: "appsec",
      label: "Application security",
      data: severities({ medium: 4, low: 6, info: 5 }),
    },
    { key: "data", label: "Data layer", data: severities({ medium: 6, low: 3 }) },
    { key: "delivery", label: "Delivery", data: severities({}) },
  ];

  test("scales every row against the widest total", () => {
    const layout = barLayout(groups, { x: 100, y: 200, width: 300, rowHeight: 10, rowGap: 4 });
    expect(layout.max).toBe(15);
    const first = layout.rows[0];
    expect(first?.total).toBe(15);
    expect(first?.segments.reduce((sum, segment) => sum + segment.width, 0)).toBeCloseTo(300, 9);
    expect(layout.rows[1]?.segments.reduce((sum, segment) => sum + segment.width, 0)).toBeCloseTo(
      (9 / 15) * 300,
      9,
    );
  });

  test("segments are laid end to end from the left edge", () => {
    const layout = barLayout(groups, { x: 100, y: 200, width: 300, rowHeight: 10, rowGap: 4 });
    const segments = layout.rows[0]?.segments ?? [];
    expect(segments[0]?.x).toBe(100);
    for (let index = 1; index < segments.length; index += 1) {
      expect(segments[index]?.x).toBeCloseTo(
        (segments[index - 1]?.x ?? 0) + (segments[index - 1]?.width ?? 0),
        9,
      );
    }
  });

  test("an empty row has no segments and still occupies its line", () => {
    const layout = barLayout(groups, { x: 100, y: 200, width: 300, rowHeight: 10, rowGap: 4 });
    const empty = layout.rows[2];
    expect(empty?.segments).toHaveLength(0);
    expect(empty?.total).toBe(0);
    expect(empty?.y).toBe(200 + 2 * 14);
    expect(layout.height).toBe(3 * 10 + 2 * 4);
  });

  test("a single finding is never thinner than the minimum, a zero never wider than nothing", () => {
    const layout = barLayout(
      [
        { key: "a", label: "a", data: severities({ critical: 1 }) },
        { key: "b", label: "b", data: severities({ low: 400 }) },
      ],
      { x: 0, y: 0, width: 200, rowHeight: 8, rowGap: 2, minSegmentWidth: 1.5 },
    );
    expect(layout.rows[0]?.segments).toHaveLength(1);
    expect(layout.rows[0]?.segments[0]?.width).toBe(1.5);
    expect(layout.rows[0]?.segments[0]?.key).toBe("critical");
  });

  test("an explicit max lets two charts share a scale", () => {
    const layout = barLayout([{ key: "a", label: "a", data: severities({ low: 5 }) }], {
      x: 0,
      y: 0,
      width: 100,
      rowHeight: 8,
      rowGap: 2,
      max: 20,
    });
    expect(layout.max).toBe(20);
    expect(layout.rows[0]?.segments[0]?.width).toBe(25);
  });

  test("no groups is a chart of no height", () => {
    expect(barLayout([], { x: 0, y: 0, width: 100, rowHeight: 8, rowGap: 2 })).toEqual({
      rows: [],
      max: 1,
      height: 0,
    });
  });
});

describe("pointOnCircle", () => {
  test("angle zero points right and a quarter turn points down the page", () => {
    expect(pointOnCircle(10, 10, 5, 0)).toEqual({ x: 15, y: 10 });
    const down = pointOnCircle(10, 10, 5, Math.PI / 2);
    expect(down.x).toBeCloseTo(10, 9);
    expect(down.y).toBeCloseTo(15, 9);
  });
});
