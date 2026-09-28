/**
 * Token and cost accounting for the AI phases.
 *
 * THE ONE RULE OF THIS FILE: usage is recorded exactly once per dispatch, at
 * the single call to {@link UsageLedger.record} inside `runtime.ts`, and the
 * phase total is `UsageLedger.total()` — never a second sum computed by the
 * caller.
 *
 * `StructuredResult.usage` is the per-dispatch slice of that same ledger
 * entry, handed back so a batch can be attributed. Adding those per-dispatch
 * figures on top of the ledger total is a double count, and a double count here
 * is silent: nothing fails, the run simply reports twice the spend, so an
 * effective budget cap trips at half the real figure and cuts the run short of
 * batches it has already paid for. If you need a phase total, read the ledger.
 * If you need a batch total, read the result. Never add them together.
 */

import { z } from "zod";

/** Tokens and estimated cost attributable to one dispatch, or to a whole phase. */
export interface AgentUsage {
  readonly inputTokens: number;
  readonly outputTokens: number;
  readonly cacheReadInputTokens: number;
  readonly cacheCreationInputTokens: number;
  /** Estimated, not a billing statement; on a subscription run it is informational. */
  readonly costUsd: number;
}

/** Usage as it appears in a recorded transcript; every field defaults to zero. */
export const AgentUsageSchema = z.object({
  inputTokens: z.number().nonnegative().default(0),
  outputTokens: z.number().nonnegative().default(0),
  cacheReadInputTokens: z.number().nonnegative().default(0),
  cacheCreationInputTokens: z.number().nonnegative().default(0),
  costUsd: z.number().nonnegative().default(0),
});

/** No tokens spent. */
export const ZERO_USAGE: AgentUsage = {
  inputTokens: 0,
  outputTokens: 0,
  cacheReadInputTokens: 0,
  cacheCreationInputTokens: 0,
  costUsd: 0,
};

/** Field-wise sum of two usage records. */
export function addUsage(left: AgentUsage, right: AgentUsage): AgentUsage {
  return {
    inputTokens: left.inputTokens + right.inputTokens,
    outputTokens: left.outputTokens + right.outputTokens,
    cacheReadInputTokens: left.cacheReadInputTokens + right.cacheReadInputTokens,
    cacheCreationInputTokens: left.cacheCreationInputTokens + right.cacheCreationInputTokens,
    costUsd: left.costUsd + right.costUsd,
  };
}

/** Total tokens billed as input, cached reads and cache writes included. */
export function totalInputTokens(usage: AgentUsage): number {
  return usage.inputTokens + usage.cacheReadInputTokens + usage.cacheCreationInputTokens;
}

/**
 * The run's single accounting point. One instance per runtime; the runtime is
 * the only thing that calls `record`.
 */
export class UsageLedger {
  #total: AgentUsage = ZERO_USAGE;
  #dispatches = 0;

  /** Adds one dispatch's usage. Called once per dispatch, from one place. */
  record(usage: AgentUsage): void {
    this.#total = addUsage(this.#total, usage);
    this.#dispatches += 1;
  }

  /** The phase total. Do not add `StructuredResult.usage` on top of this. */
  total(): AgentUsage {
    return this.#total;
  }

  /** How many dispatches (including retried attempts) contributed to the total. */
  get dispatches(): number {
    return this.#dispatches;
  }
}
