import { describe, expect, test } from "bun:test";
import { drawBars, drawDonut } from "./charts.ts";
import type { ChartDatum } from "./geometry.ts";
import { RecordingSurface } from "./surface.ts";
import { SEVERITY_COLOR } from "./theme.ts";

/**
 * A distribution with two empty tiers at the top, which is the shape that tempts
 * a donut into drawing a red sliver that is not there: the zeros still occupy
 * rows in the legend, so a chart that scales by index rather than by value
 * paints them.
 */
const SEVERITIES: ChartDatum[] = [
  { key: "critical", label: "Critical", value: 0, color: SEVERITY_COLOR.critical },
  { key: "high", label: "High", value: 0, color: SEVERITY_COLOR.high },
  { key: "medium", label: "Medium", value: 10, color: SEVERITY_COLOR.medium },
  { key: "low", label: "Low", value: 20, color: SEVERITY_COLOR.low },
  { key: "info", label: "Info", value: 30, color: SEVERITY_COLOR.info },
];

describe("drawDonut", () => {
  test("fills one closed path per non-zero severity and nothing for the zeros", () => {
    const surface = new RecordingSurface();
    const result = drawDonut(surface, {
      cx: 150,
      cy: 300,
      outerRadius: 46,
      innerRadius: 28,
      data: SEVERITIES,
      centerLabel: "findings",
    });

    expect(result).toEqual({ total: 60, drawn: 3 });
    const fills = surface.of("fill").map((call) => call.args[0]);
    expect(fills).toEqual([SEVERITY_COLOR.medium, SEVERITY_COLOR.low, SEVERITY_COLOR.info]);
    expect(fills).not.toContain(SEVERITY_COLOR.critical);
    expect(surface.of("closePath")).toHaveLength(3);
    expect(surface.of("moveTo")).toHaveLength(3);
    // One bridge line from the outer edge to the inner edge per slice.
    expect(surface.of("lineTo")).toHaveLength(3);
  });

  test("prints the total in the hole so the chart survives a photocopier", () => {
    const surface = new RecordingSurface();
    drawDonut(surface, {
      cx: 150,
      cy: 300,
      outerRadius: 46,
      innerRadius: 28,
      data: SEVERITIES,
      centerLabel: "findings",
    });
    const texts = surface.of("text").map((call) => call.args[0]);
    expect(texts).toEqual(["60", "findings"]);
  });

  test("an empty donut is an outlined ring, not a missing chart", () => {
    const surface = new RecordingSurface();
    const result = drawDonut(surface, {
      cx: 100,
      cy: 100,
      outerRadius: 40,
      innerRadius: 24,
      data: SEVERITIES.map((datum) => ({ ...datum, value: 0 })),
      centerLabel: "findings",
    });
    expect(result).toEqual({ total: 0, drawn: 0 });
    expect(surface.of("circle")).toHaveLength(2);
    expect(surface.of("stroke")).toHaveLength(2);
    expect(surface.of("fill")).toHaveLength(0);
    expect(surface.of("text").map((call) => call.args[0])).toEqual(["0", "findings"]);
  });

  test("every path point stays inside the ring's bounding box", () => {
    const surface = new RecordingSurface();
    drawDonut(surface, {
      cx: 200,
      cy: 400,
      outerRadius: 50,
      innerRadius: 30,
      data: SEVERITIES,
    });
    const points = surface.calls
      .filter((call) => call.op === "moveTo" || call.op === "lineTo")
      .map((call) => ({ x: Number(call.args[0]), y: Number(call.args[1]) }));
    for (const point of points) {
      expect(Math.hypot(point.x - 200, point.y - 400)).toBeLessThanOrEqual(50.001);
      expect(Math.hypot(point.x - 200, point.y - 400)).toBeGreaterThanOrEqual(29.999);
    }
  });
});

describe("drawBars", () => {
  const groups = [
    {
      key: "appsec",
      label: "Application security",
      data: [
        { key: "medium", label: "Medium", value: 4, color: SEVERITY_COLOR.medium },
        { key: "low", label: "Low", value: 6, color: SEVERITY_COLOR.low },
        { key: "info", label: "Info", value: 5, color: SEVERITY_COLOR.info },
      ],
    },
    {
      key: "reliability",
      label: "Reliability",
      data: [],
      note: "not assessed",
    },
  ];

  test("draws a track for every row, so a zero row is visibly zero", () => {
    const surface = new RecordingSurface();
    const layout = drawBars(surface, {
      x: 60,
      y: 100,
      labelWidth: 90,
      barWidth: 200,
      valueWidth: 40,
      rowHeight: 10,
      rowGap: 4,
      groups,
    });

    expect(layout.rows).toHaveLength(2);
    const rects = surface.of("rect");
    // Two tracks plus the three severity segments of the first row.
    expect(rects).toHaveLength(5);
    expect(rects[0]?.args).toEqual([156, 100, 200, 10]);
    expect(layout.rows[1]?.segments).toHaveLength(0);
  });

  test("a domain that was not assessed says so instead of showing a zero", () => {
    const surface = new RecordingSurface();
    drawBars(surface, {
      x: 60,
      y: 100,
      labelWidth: 90,
      barWidth: 200,
      valueWidth: 40,
      rowHeight: 10,
      rowGap: 4,
      groups,
    });
    const texts = surface.of("text").map((call) => call.args[0]);
    expect(texts).toEqual(["Application security", "15", "Reliability", "not assessed"]);
  });

  test("segments are painted in the palette order they were given", () => {
    const surface = new RecordingSurface();
    drawBars(surface, {
      x: 0,
      y: 0,
      labelWidth: 50,
      barWidth: 100,
      valueWidth: 20,
      rowHeight: 8,
      rowGap: 2,
      groups,
    });
    const fills = surface.of("fill").map((call) => call.args[0]);
    expect(fills.slice(1, 4)).toEqual([
      SEVERITY_COLOR.medium,
      SEVERITY_COLOR.low,
      SEVERITY_COLOR.info,
    ]);
  });
});
