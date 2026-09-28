/**
 * The dispatch pool.
 *
 * Sentinel's AI phases run on a Claude subscription, not an API key: the
 * throughput ceiling is the plan's, not ours, and firing twenty batches at
 * once buys nothing but twenty ways to hit it at the same moment. Fan-out is
 * therefore small and explicit, and the effective value is recorded in the run
 * metadata so a slow run can be explained afterwards.
 */

/** Sensible fan-out for a subscription-backed run. */
export const DEFAULT_CONCURRENCY = 2;

/** A counting semaphore that runs tasks FIFO, at most `limit` at a time. */
export interface Semaphore {
  /** Greatest number of tasks allowed to run at once. */
  readonly limit: number;
  /** Tasks running right now. */
  readonly active: number;
  /** Tasks admitted but not yet started. */
  readonly waiting: number;
  /** Runs `task` once a slot is free; the slot is released even if it throws. */
  run<T>(task: () => Promise<T>): Promise<T>;
}

/** Creates a semaphore admitting at most `limit` concurrent tasks (minimum 1). */
export function createSemaphore(limit: number): Semaphore {
  const capacity = Math.max(1, Math.floor(limit));
  const queue: Array<() => void> = [];
  let active = 0;

  const release = (): void => {
    active -= 1;
    const next = queue.shift();
    if (next !== undefined) next();
  };

  const acquire = async (): Promise<void> => {
    if (active < capacity) {
      active += 1;
      return;
    }
    await new Promise<void>((resolve) => {
      queue.push(() => {
        active += 1;
        resolve();
      });
    });
  };

  return {
    limit: capacity,
    get active(): number {
      return active;
    },
    get waiting(): number {
      return queue.length;
    },
    async run<T>(task: () => Promise<T>): Promise<T> {
      await acquire();
      try {
        return await task();
      } finally {
        release();
      }
    },
  };
}

/**
 * Maps `items` through `fn` with at most `limit` in flight, preserving input
 * order in the result. Rejects with the first failure, like `Promise.all`.
 */
export async function mapWithConcurrency<I, O>(
  items: readonly I[],
  limit: number,
  fn: (item: I, index: number) => Promise<O>,
): Promise<O[]> {
  const semaphore = createSemaphore(limit);
  return await Promise.all(items.map((item, index) => semaphore.run(() => fn(item, index))));
}
