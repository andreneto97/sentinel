import { describe, expect, test } from "bun:test";
import {
  AGENT_FAILURE_KINDS,
  AgentError,
  AgentFailureKindSchema,
  emptyFailureCounts,
  isAgentError,
  isFatal,
  isRetryable,
  toAgentError,
} from "./errors.ts";

describe("AgentError", () => {
  test("carries the kind in the message and the context in fields", () => {
    const error = new AgentError("timeout", "no reply within 1000ms", {
      batchId: "routes-001",
      attempt: 2,
    });
    expect(error.message).toBe("timeout: no reply within 1000ms");
    expect(error.name).toBe("AgentError");
    expect(error.kind).toBe("timeout");
    expect(error.batchId).toBe("routes-001");
    expect(error.attempt).toBe(2);
    expect(isAgentError(error)).toBe(true);
    expect(isAgentError(new Error("plain"))).toBe(false);
  });
});

describe("retry policy", () => {
  test("a subscription limit is never retried and always stops the phase", () => {
    const quota = new AgentError("quota", "You've reached your usage limit.");
    expect(isRetryable(quota)).toBe(false);
    expect(isFatal(quota)).toBe(true);
  });

  test("a refusal is not retried: the same prompt earns the same refusal", () => {
    const refusal = new AgentError("refusal", "declined");
    expect(isRetryable(refusal)).toBe(false);
    expect(isFatal(refusal)).toBe(false);
  });

  test("malformed, truncated, timeout and transient failures may be retried", () => {
    for (const kind of ["malformed-output", "truncated-output", "timeout", "transient"] as const) {
      expect(isRetryable(new AgentError(kind, "x"))).toBe(true);
      expect(isFatal(new AgentError(kind, "x"))).toBe(false);
    }
  });

  test("an explicit override beats the kind's default", () => {
    expect(isRetryable(new AgentError("transient", "x", { retryable: false }))).toBe(false);
  });
});

describe("toAgentError", () => {
  test("passes an AgentError through untouched", () => {
    const original = new AgentError("quota", "spent");
    expect(toAgentError(original)).toBe(original);
  });

  test("wraps an unclassified throw as a transient failure that is not retried", () => {
    const wrapped = toAgentError(new TypeError("x.map is not a function"), { batchId: "b" });
    expect(wrapped.kind).toBe("transient");
    expect(isRetryable(wrapped)).toBe(false);
    expect(wrapped.detail).toBe("x.map is not a function");
    expect(wrapped.batchId).toBe("b");
  });

  test("wraps a non-Error throw", () => {
    expect(toAgentError("boom").detail).toBe("boom");
  });
});

describe("emptyFailureCounts", () => {
  test("has a zeroed row for every kind, so a report table has no gaps", () => {
    const counts = emptyFailureCounts();
    expect(Object.keys(counts).sort()).toEqual([...AGENT_FAILURE_KINDS].sort());
    expect(Object.values(counts).every((value) => value === 0)).toBe(true);
  });

  test("the schema accepts exactly the known kinds", () => {
    for (const kind of AGENT_FAILURE_KINDS) {
      expect(AgentFailureKindSchema.safeParse(kind).success).toBe(true);
    }
    expect(AgentFailureKindSchema.safeParse("exploded").success).toBe(false);
  });
});
