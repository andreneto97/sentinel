import { describe, expect, test } from "bun:test";
import { FakeClock, createSystemClock } from "./clock.ts";

describe("createSystemClock", () => {
  test("now tracks wall-clock time", () => {
    const clock = createSystemClock();
    const before = Date.now();
    const now = clock.now();
    expect(now).toBeGreaterThanOrEqual(before);
    expect(now).toBeLessThanOrEqual(Date.now());
  });

  test("sleep actually waits", async () => {
    const clock = createSystemClock();
    const started = performance.now();
    await clock.sleep(30);
    expect(performance.now() - started).toBeGreaterThanOrEqual(25);
  });

  test("a non-positive sleep resolves immediately", async () => {
    const clock = createSystemClock();
    const started = performance.now();
    await clock.sleep(0);
    expect(performance.now() - started).toBeLessThan(50);
  });
});

describe("FakeClock", () => {
  test("time only moves when the test moves it", async () => {
    const clock = new FakeClock(1_000);
    expect(clock.now()).toBe(1_000);
    await clock.advance(500);
    expect(clock.now()).toBe(1_500);
    clock.set(42);
    expect(clock.now()).toBe(42);
  });

  test("sleep resolves when time passes its deadline", async () => {
    const clock = new FakeClock(0);
    const woken: string[] = [];
    void clock.sleep(100).then(() => woken.push("late"));
    void clock.sleep(10).then(() => woken.push("early"));
    expect(clock.pendingSleeps).toBe(2);

    await clock.advance(10);
    expect(woken).toEqual(["early"]);
    expect(clock.now()).toBe(10);

    await clock.advance(50);
    expect(woken).toEqual(["early"]);
    expect(clock.pendingSleeps).toBe(1);

    await clock.advance(40);
    expect(woken).toEqual(["early", "late"]);
    expect(clock.pendingSleeps).toBe(0);
    expect(clock.now()).toBe(100);
  });

  test("a sleeper sees the clock at its own deadline, not past it", async () => {
    const clock = new FakeClock(0);
    let observed = -1;
    void clock.sleep(25).then(() => {
      observed = clock.now();
    });
    await clock.advance(1_000);
    expect(observed).toBe(25);
    expect(clock.now()).toBe(1_000);
  });

  test("drives a retry backoff loop without real waiting", async () => {
    const clock = new FakeClock(0);
    const attempts: number[] = [];
    const work = (async () => {
      for (let attempt = 1; attempt <= 3; attempt += 1) {
        attempts.push(clock.now());
        if (attempt < 3) await clock.sleep(attempt * 100);
      }
    })();

    await clock.advance(100);
    await clock.advance(200);
    await work;
    expect(attempts).toEqual([0, 100, 300]);
  });
});
