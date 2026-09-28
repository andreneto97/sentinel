import { describe, expect, test } from "bun:test";
import {
  type BatchCompletion,
  type BatchProgress,
  MIN_PROJECTION_SAMPLES,
  PROGRESS_EVENT,
  createProgressTracker,
  createProgressWriter,
  formatProgressJson,
  formatProgressLine,
  formatSpan,
} from "./progress.ts";

/** A finished batch, shaped the way `BatchReport` hands one over. */
function completion(overrides: Partial<BatchCompletion> = {}): BatchCompletion {
  return {
    batchId: "appsec-route-0001",
    domain: "appsec",
    kinds: ["route"],
    units: 14,
    status: "audited",
    verdicts: 14,
    findings: 0,
    durationMs: 60_000,
    ...overrides,
  };
}

/** What a run of `n` batches at a fan-out looks like; the clock advances per wave. */
function driveBatches(input: {
  readonly batches: readonly BatchCompletion[];
  readonly batchesTotal?: number | undefined;
  readonly unitsTotal?: number | undefined;
  readonly concurrency?: number | undefined;
  readonly minSamples?: number | undefined;
}): BatchProgress[] {
  const events: BatchProgress[] = [];
  const concurrency = input.concurrency ?? 2;
  let clock = 0;
  const tracker = createProgressTracker({
    report: (progress) => void events.push(progress),
    batchesTotal: input.batchesTotal ?? input.batches.length,
    unitsTotal: input.unitsTotal ?? input.batches.reduce((sum, batch) => sum + batch.units, 0),
    concurrency,
    startedAt: 0,
    now: () => clock,
    ...(input.minSamples === undefined ? {} : { minSamples: input.minSamples }),
  });
  for (const batch of input.batches) {
    // `concurrency` batches run at once, so each completion costs a fraction of
    // its own duration in wall clock. That is what makes the projection's
    // fan-out arithmetic observable in `elapsedMs`.
    clock += batch.durationMs / concurrency;
    tracker.completed(batch);
  }
  return events;
}

/** The event at `index`, or a failure naming the gap rather than a cast. */
function at(events: readonly BatchProgress[], index: number): BatchProgress {
  const event = events[index];
  if (event === undefined) throw new Error(`no progress event at index ${index}`);
  return event;
}

/** Eight identical batches, the shape the CLI demo prints. */
function eightBatches(): readonly BatchCompletion[] {
  return Array.from({ length: 8 }, (_unused, index) =>
    completion({
      batchId: `appsec-route-${String(index + 1).padStart(4, "0")}`,
      findings: index % 3 === 0 ? 1 : 0,
    }),
  );
}

describe("formatSpan", () => {
  test("reads as seconds, then minutes, then hours", () => {
    expect(formatSpan(0)).toBe("0s");
    expect(formatSpan(42_000)).toBe("42s");
    expect(formatSpan(59_400)).toBe("59s");
    expect(formatSpan(60_000)).toBe("1m");
    expect(formatSpan(12 * 60_000 + 55_000)).toBe("12m");
    expect(formatSpan(64 * 60_000)).toBe("1h 04m");
  });

  test("never reports a negative span", () => {
    expect(formatSpan(-5_000)).toBe("0s");
  });
});

describe("the tracker", () => {
  test("reports one event per finished batch, with the run's totals so far", () => {
    const events = driveBatches({ batches: eightBatches() });
    expect(events).toHaveLength(8);
    expect(events.map((event) => event.batchesDone)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(events.every((event) => event.batchesTotal === 8)).toBe(true);
    // Cumulative, not per batch: this is the counter a watcher follows.
    expect(events.map((event) => event.unitsAudited)).toEqual([14, 28, 42, 56, 70, 84, 98, 112]);
    expect(at(events, 7).unitsTotal).toBe(112);
    expect(at(events, 7).findings).toBe(3);
    expect(at(events, 7).elapsedMs).toBe(4 * 60_000);
  });

  test("says `estimating` until enough batches have finished for a mean to mean something", () => {
    const events = driveBatches({ batches: eightBatches() });
    const estimating = events.filter((event) => event.remainingMs === null).length;
    expect(estimating).toBe(MIN_PROJECTION_SAMPLES - 1);
    expect(at(events, MIN_PROJECTION_SAMPLES - 2).remainingMs).toBeNull();
    expect(at(events, MIN_PROJECTION_SAMPLES - 1).remainingMs).not.toBeNull();
  });

  test("waits a full wave when the fan-out is wider than the sample floor", () => {
    const events = driveBatches({ batches: eightBatches(), concurrency: 6 });
    // Six in flight: five completions are one incomplete wave, not a rate.
    expect(events.slice(0, 5).every((event) => event.remainingMs === null)).toBe(true);
    expect(at(events, 5).remainingMs).not.toBeNull();
  });

  test("projects the mean of the completed durations over the waves still to come", () => {
    // Twelve batches of a minute each at a fan-out of two: after four, eight
    // remain, which is four waves of one minute.
    const events = driveBatches({
      batches: Array.from({ length: 12 }, () => completion()),
      concurrency: 2,
    });
    expect(at(events, 3).remainingMs).toBe(4 * 60_000);
    expect(at(events, 9).remainingMs).toBe(60_000);
  });

  test("the mean is the batches' own durations, so a slow batch moves the projection", () => {
    const batches = [
      completion({ durationMs: 60_000 }),
      completion({ durationMs: 60_000 }),
      completion({ durationMs: 60_000 }),
      completion({ durationMs: 180_000 }),
    ];
    const events = driveBatches({ batches, batchesTotal: 8, concurrency: 2 });
    // Mean of 60, 60, 60, 180 is 90 seconds; four batches left is two waves.
    expect(at(events, 3).remainingMs).toBe(2 * 90_000);
  });

  test("counts failed and partial batches apart, and keeps counting them", () => {
    const events = driveBatches({
      batches: [
        completion(),
        completion({ status: "failed", failure: "timeout", verdicts: 0, reason: "no reply" }),
        completion({ status: "partial", verdicts: 9, reason: "5 of 14 units have no verdict" }),
        completion(),
      ],
    });
    expect(events.map((event) => event.batchesFailed)).toEqual([0, 1, 1, 1]);
    expect(events.map((event) => event.batchesPartial)).toEqual([0, 0, 1, 1]);
    // A failed batch still spent its units; it just has no verdicts to show.
    expect(at(events, 1).unitsDispatched).toBe(28);
    expect(at(events, 1).unitsAudited).toBe(14);
    expect(at(events, 1).failure).toBe("timeout");
  });
});

describe("the line a person watches", () => {
  test("carries batches, units, findings, elapsed and a projection", () => {
    const events = driveBatches({
      batches: Array.from({ length: 95 }, (_unused, index) =>
        completion({ findings: index % 3 === 0 ? 1 : 0 }),
      ),
      unitsTotal: 1_049,
    });
    const line = formatProgressLine(at(events, 22));
    expect(line).toBe("[23/95] route × 14 · 322/1049 units · 8 findings · 11m elapsed · ~36m left");
  });

  test("says `~estimating` rather than inventing a rate from three batches", () => {
    const events = driveBatches({ batches: eightBatches() });
    expect(formatProgressLine(at(events, 2))).toContain("~estimating");
    expect(formatProgressLine(at(events, 2))).not.toContain("left");
    expect(formatProgressLine(at(events, 3))).toContain("left");
  });

  test("drops the projection on the last batch instead of ending in `~0s left`", () => {
    const events = driveBatches({ batches: eightBatches() });
    const last = formatProgressLine(at(events, 7));
    expect(last).toStartWith("[8/8] ");
    expect(last).not.toContain("left");
    expect(last).not.toContain("estimating");
  });

  test("classifies a failed batch on its own line, with its reason under it", () => {
    const events = driveBatches({
      batches: [
        completion(),
        completion({
          batchId: "appsec-route-0002",
          status: "failed",
          failure: "timeout",
          verdicts: 0,
          reason: "no reply within 240000ms",
        }),
        completion(),
        completion(),
      ],
    });
    const line = formatProgressLine(at(events, 1));
    expect(line).toContain("route × 14 failed (timeout)");
    expect(line).toContain("1 failed");
    expect(line).toEndWith("\n    no reply within 240000ms");
    // And it stays visible on the lines after it, for a reader who scrolled past.
    expect(formatProgressLine(at(events, 3))).toContain("1 failed");
  });

  test("a partial batch says how many verdicts it did get", () => {
    const events = driveBatches({
      batches: [
        completion({
          status: "partial",
          verdicts: 9,
          reason: "5 of 14 units have no verdict: 5 it returned no verdict for",
        }),
        completion(),
      ],
    });
    const line = formatProgressLine(at(events, 0));
    expect(line).toContain("route × 14 partial (9/14 verdicts)");
    expect(line).toContain("1 partial");
    expect(line).toContain("\n    5 of 14 units have no verdict");
  });

  test("a clean batch never prints a reason, even when the report carries one", () => {
    const events = driveBatches({ batches: [completion({ reason: "ignored" }), completion()] });
    expect(formatProgressLine(at(events, 0))).not.toContain("ignored");
  });

  test("--verbose adds the batch id and names every unit kind", () => {
    const events = driveBatches({
      batches: [completion({ kinds: ["route", "data-access"] }), completion()],
    });
    const plain = formatProgressLine(at(events, 0));
    const loud = formatProgressLine(at(events, 0), { verbose: true });
    expect(plain).not.toContain("appsec-route-0001");
    expect(plain).toContain("route × 14");
    expect(loud).toContain("appsec-route-0001");
    expect(loud).toContain("route, data-access × 14");
  });

  test("falls back to the batch's domain when it carries no kind at all", () => {
    const events = driveBatches({ batches: [completion({ kinds: [] }), completion()] });
    expect(formatProgressLine(at(events, 0))).toContain("appsec × 14");
  });

  test("one finding is not `1 findings`", () => {
    const events = driveBatches({ batches: [completion({ findings: 1 }), completion()] });
    expect(formatProgressLine(at(events, 0))).toContain("1 finding ·");
  });
});

describe("the JSON line", () => {
  test("is one object per batch, with `estimating` spelled out beside the projection", () => {
    const events = driveBatches({ batches: eightBatches() });
    const early = JSON.parse(formatProgressJson(at(events, 0)));
    expect(early.event).toBe(PROGRESS_EVENT);
    expect(early.remainingMs).toBeNull();
    expect(early.estimating).toBe(true);

    const later = JSON.parse(formatProgressJson(at(events, 5)));
    expect(later.estimating).toBe(false);
    expect(later).toMatchObject({
      batchId: "appsec-route-0006",
      domain: "appsec",
      kinds: ["route"],
      status: "audited",
      batchesDone: 6,
      batchesTotal: 8,
      unitsAudited: 84,
      unitsDispatched: 84,
      unitsTotal: 112,
      findings: 2,
    });
    expect(typeof later.remainingMs).toBe("number");
  });

  test("carries the failure classification a prose line puts in brackets", () => {
    const events = driveBatches({
      batches: [
        completion({ status: "failed", failure: "quota", verdicts: 0, reason: "limit reached" }),
        completion(),
      ],
    });
    const payload = JSON.parse(formatProgressJson(at(events, 0)));
    expect(payload).toMatchObject({ status: "failed", failure: "quota", reason: "limit reached" });
  });

  test("is one line, so a consumer can read it a line at a time", () => {
    const events = driveBatches({ batches: eightBatches() });
    expect(formatProgressJson(at(events, 0))).not.toContain("\n");
  });
});

describe("the writer the CLI builds", () => {
  /** A pair of string streams, like the CLI's `write` and `writeError`. */
  function streams(): { out: string[]; err: string[] } {
    return { out: [], err: [] };
  }

  test("writes prose to stdout, one line per batch", () => {
    const { out, err } = streams();
    const writer = createProgressWriter({
      write: (text) => void out.push(text),
      writeError: (text) => void err.push(text),
    });
    expect(writer).toBeDefined();
    // The tracker is driven through the writer, which is how the CLI wires it.
    for (const event of driveBatches({ batches: eightBatches() })) writer?.(event);
    expect(out).toHaveLength(8);
    expect(out[0]).toEndWith("\n");
    expect(out[0]).toStartWith("[1/8] route × 14 · ");
    expect(err).toHaveLength(0);
  });

  test("--quiet builds no writer at all, so nothing is even counted", () => {
    const { out, err } = streams();
    const writer = createProgressWriter({
      write: (text) => void out.push(text),
      writeError: (text) => void err.push(text),
      quiet: true,
    });
    expect(writer).toBeUndefined();
  });

  test("--json goes to stderr, so stdout stays one document", () => {
    const { out, err } = streams();
    const writer = createProgressWriter({
      write: (text) => void out.push(text),
      writeError: (text) => void err.push(text),
      json: true,
    });
    for (const event of driveBatches({ batches: eightBatches() })) writer?.(event);
    expect(out).toHaveLength(0);
    expect(err).toHaveLength(8);
    for (const line of err) {
      expect(line).toEndWith("\n");
      expect(JSON.parse(line).event).toBe(PROGRESS_EVENT);
    }
  });

  test("--json wins over --verbose: a machine surface is not made chattier", () => {
    const { out, err } = streams();
    const writer = createProgressWriter({
      write: (text) => void out.push(text),
      writeError: (text) => void err.push(text),
      json: true,
      verbose: true,
    });
    for (const event of driveBatches({ batches: [completion(), completion()] })) writer?.(event);
    expect(out).toHaveLength(0);
    expect(JSON.parse(err[0] ?? "{}").batchId).toBe("appsec-route-0001");
  });

  test("--verbose writes the louder prose line", () => {
    const { out, err } = streams();
    const writer = createProgressWriter({
      write: (text) => void out.push(text),
      writeError: (text) => void err.push(text),
      verbose: true,
    });
    for (const event of driveBatches({ batches: [completion(), completion()] })) writer?.(event);
    expect(out[0]).toContain("appsec-route-0001");
    expect(err).toHaveLength(0);
  });
});
