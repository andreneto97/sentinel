import { describe, expect, test } from "bun:test";
import { AgentUsageSchema, UsageLedger, ZERO_USAGE, addUsage, totalInputTokens } from "./usage.ts";

const ONE = {
  inputTokens: 2,
  outputTokens: 300,
  cacheReadInputTokens: 10,
  cacheCreationInputTokens: 728,
  costUsd: 0.0118,
};

describe("addUsage", () => {
  test("sums field by field", () => {
    expect(addUsage(ONE, ONE)).toEqual({
      inputTokens: 4,
      outputTokens: 600,
      cacheReadInputTokens: 20,
      cacheCreationInputTokens: 1456,
      costUsd: 0.0236,
    });
  });

  test("zero is the identity", () => {
    expect(addUsage(ONE, ZERO_USAGE)).toEqual(ONE);
  });
});

describe("totalInputTokens", () => {
  test("counts fresh, cached and cache-written input together", () => {
    expect(totalInputTokens(ONE)).toBe(740);
  });
});

describe("UsageLedger", () => {
  test("is the single phase total; per-dispatch figures are not added on top", () => {
    const ledger = new UsageLedger();
    ledger.record(ONE);
    ledger.record(ONE);

    expect(ledger.dispatches).toBe(2);
    expect(ledger.total().outputTokens).toBe(600);
    // Taking the ledger total AND re-adding each dispatch's own total doubles
    // the spend, which trips an effective budget cap at half the real figure.
    const doubleCounted = ledger.total().outputTokens + ONE.outputTokens * 2;
    expect(doubleCounted).not.toBe(ledger.total().outputTokens);
  });

  test("starts at zero", () => {
    const ledger = new UsageLedger();
    expect(ledger.total()).toEqual(ZERO_USAGE);
    expect(ledger.dispatches).toBe(0);
  });
});

describe("AgentUsageSchema", () => {
  test("fills every absent field with zero, so a sparse transcript still adds up", () => {
    expect(AgentUsageSchema.parse({ outputTokens: 5 })).toEqual({
      inputTokens: 0,
      outputTokens: 5,
      cacheReadInputTokens: 0,
      cacheCreationInputTokens: 0,
      costUsd: 0,
    });
  });

  test("rejects negative counts", () => {
    expect(AgentUsageSchema.safeParse({ outputTokens: -1 }).success).toBe(false);
  });
});
