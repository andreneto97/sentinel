import { describe, expect, test } from "bun:test";
import { DEFAULT_CONCURRENCY, createSemaphore, mapWithConcurrency } from "./pool.ts";

/** A task that resolves when the test says so, recording overlap while it runs. */
function tracker() {
  let active = 0;
  let peak = 0;
  const gates: Array<() => void> = [];
  return {
    peak: () => peak,
    releaseAll: () => {
      for (const gate of gates.splice(0)) gate();
    },
    task: async (): Promise<number> => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise<void>((resolve) => gates.push(resolve));
      active -= 1;
      return peak;
    },
  };
}

describe("createSemaphore", () => {
  test("defaults matter: the subscription is throttled, so two is the fan-out", () => {
    expect(DEFAULT_CONCURRENCY).toBe(2);
  });

  test("never runs more than the limit at once", async () => {
    const semaphore = createSemaphore(2);
    const { task, peak, releaseAll } = tracker();
    const running = [1, 2, 3, 4, 5].map(() => semaphore.run(task));

    await Promise.resolve();
    expect(semaphore.active).toBe(2);
    expect(semaphore.waiting).toBe(3);

    const pump = setInterval(releaseAll, 1);
    await Promise.all(running);
    clearInterval(pump);

    expect(peak()).toBe(2);
    expect(semaphore.active).toBe(0);
  });

  test("a failing task still frees its slot", async () => {
    const semaphore = createSemaphore(1);
    await semaphore.run(async () => Promise.reject(new Error("boom"))).catch(() => undefined);
    expect(semaphore.active).toBe(0);
    await expect(semaphore.run(async () => "next")).resolves.toBe("next");
  });

  test("clamps a nonsensical limit to one rather than deadlocking", async () => {
    const semaphore = createSemaphore(0);
    expect(semaphore.limit).toBe(1);
    await expect(semaphore.run(async () => "ok")).resolves.toBe("ok");
  });

  test("admits waiting tasks in the order they arrived", async () => {
    const semaphore = createSemaphore(1);
    const order: number[] = [];
    const runs = [1, 2, 3].map((index) =>
      semaphore.run(async () => {
        order.push(index);
      }),
    );
    await Promise.all(runs);
    expect(order).toEqual([1, 2, 3]);
  });
});

describe("mapWithConcurrency", () => {
  test("keeps input order in the result", async () => {
    const out = await mapWithConcurrency([10, 20, 30, 40], 2, async (item, index) => {
      await Bun.sleep(item % 30);
      return `${index}:${item}`;
    });
    expect(out).toEqual(["0:10", "1:20", "2:30", "3:40"]);
  });

  test("rejects with the first failure", async () => {
    await expect(
      mapWithConcurrency([1, 2, 3], 2, async (item) => {
        if (item === 2) throw new Error("batch 2 failed");
        return item;
      }),
    ).rejects.toThrow("batch 2 failed");
  });
});
