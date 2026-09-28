/**
 * Time seam.
 *
 * Run ids, artifact timestamps and retry backoff all read the clock; taking it
 * as an argument is what keeps those deterministic under test.
 */

/** The time operations Sentinel needs. */
export interface Clock {
  /** Current wall-clock time, epoch milliseconds. */
  now(): number;
  /** Resolves after `ms`; a fake clock resolves it when the test advances time. */
  sleep(ms: number): Promise<void>;
}

/** Creates the real clock, backed by `Date.now` and `setTimeout`. */
export function createSystemClock(): Clock {
  return {
    now(): number {
      return Date.now();
    },
    sleep(ms: number): Promise<void> {
      if (ms <= 0) return Promise.resolve();
      return new Promise((resolve) => {
        setTimeout(resolve, ms);
      });
    },
  };
}

/** A sleeper waiting for the fake clock to reach `at`. */
interface PendingSleep {
  readonly at: number;
  readonly resolve: () => void;
}

/** A Clock whose time only moves when a test moves it; `sleep` resolves on `advance`. */
export class FakeClock implements Clock {
  #now: number;
  #pending: PendingSleep[] = [];

  constructor(start = 0) {
    this.#now = start;
  }

  /** Current fake time, epoch milliseconds. */
  now(): number {
    return this.#now;
  }

  /** Resolves once {@link FakeClock.advance} moves time past the deadline. */
  sleep(ms: number): Promise<void> {
    if (ms <= 0) return Promise.resolve();
    const at = this.#now + ms;
    return new Promise<void>((resolve) => {
      this.#pending.push({ at, resolve });
      this.#pending.sort((a, b) => a.at - b.at);
    });
  }

  /** Moves time forward, waking sleepers in order and letting them run. */
  async advance(ms: number): Promise<void> {
    const target = this.#now + ms;
    for (;;) {
      const next = this.#pending[0];
      if (next === undefined || next.at > target) break;
      this.#pending.shift();
      this.#now = next.at;
      next.resolve();
      // Yield so the woken continuation runs before the next deadline fires.
      await Promise.resolve();
    }
    this.#now = target;
    await Promise.resolve();
  }

  /** Jumps to an absolute time without waking anything; for seeding a run id. */
  set(epochMs: number): void {
    this.#now = epochMs;
  }

  /** How many sleepers are still waiting — handy to assert a retry is pending. */
  get pendingSleeps(): number {
    return this.#pending.length;
  }
}
