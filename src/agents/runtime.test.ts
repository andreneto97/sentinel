import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { z } from "zod";
import { createMemoryLogger } from "../ports/logger.ts";
import { MemoryRawLogFileSystem } from "./__fixtures__/memory-file-system.ts";
import { type AgentError, isAgentError } from "./errors.ts";
import { createFixtureRuntime } from "./fixture-runtime.ts";
import { agentsRawDir } from "./raw-log.ts";
import { type AgentTranscript, parseAgentTranscript } from "./transcript.ts";
import type { AgentDispatchRequest, AgentDispatcher } from "./types.ts";
import { ZERO_USAGE } from "./usage.ts";

const RUN_DIR = "/runs/20260922T120000-abcdef12";

/** Loads one of the committed transcripts. */
async function transcript(name: string): Promise<AgentTranscript> {
  const raw = await Bun.file(join(import.meta.dir, `__fixtures__/transcripts/${name}.json`)).text();
  const parsed = parseAgentTranscript(raw);
  if (!parsed.ok) throw new Error(`${name}: ${parsed.reason}`);
  return parsed.transcript;
}

const RECORDED = await transcript("routes-recorded");
const HANDWRITTEN = await transcript("failures-handwritten");

const VerdictsSchema = z.object({
  verdicts: z.array(
    z.object({
      unitId: z.string(),
      ownershipChecked: z.boolean(),
      evidenceLine: z.number().int().positive(),
    }),
  ),
});

/** The stricter schema whose extra field forced the recorded corrective re-prompt. */
const StrictVerdictsSchema = z.object({
  verdicts: z
    .array(
      z.object({
        unitId: z.string(),
        ownershipChecked: z.boolean(),
        evidenceLine: z.number().int().positive(),
        severity: z.enum(["critical", "high", "medium", "low", "info"]),
      }),
    )
    .min(1),
});

/** A request with the two prompt halves every batch carries. */
function request(batchId: string, prompt: string) {
  return { batchId, systemPrompt: "You are Sentinel's auditor.", prompt };
}

describe("createAgentRuntime over a recorded transcript", () => {
  test("validates a clean batch in one attempt", async () => {
    const { runtime, dispatcher } = createFixtureRuntime({ transcript: RECORDED });
    const result = await runtime.runStructured(
      request("appsec-routes-001", "## unit: route-002 GET /api/orders/:id"),
      VerdictsSchema,
    );

    expect(result.attempts).toBe(1);
    expect(result.value.verdicts).toHaveLength(2);
    expect(result.value.verdicts[1]?.ownershipChecked).toBe(true);
    expect(dispatcher.calls).toHaveLength(1);
    expect(runtime.stats().retries).toBe(0);
  });

  test("a schema violation is re-prompted once, with the violation named, and then succeeds", async () => {
    const { runtime, dispatcher } = createFixtureRuntime({ transcript: RECORDED });
    const result = await runtime.runStructured(
      request("appsec-routes-correction", "## unit: route-001 GET /api/invoices/:id"),
      StrictVerdictsSchema,
    );

    expect(result.attempts).toBe(2);
    expect(result.value.verdicts[0]?.severity).toBe("high");

    // The fixture's `expectPromptContains` already proves the correction block
    // and the field name reached the model; assert the wording here too.
    const second = dispatcher.calls[1];
    expect(second?.prompt).toContain("## Correction required");
    expect(second?.prompt).toContain("verdicts.0.severity");
    expect(second?.prompt).toContain("## unit: route-001");

    const stats = runtime.stats();
    expect(stats.retries).toBe(1);
    expect(stats.dispatches).toBe(2);
    expect(stats.failures["malformed-output"]).toBe(1);
  });

  test("usage is summed once per dispatch and the batch total matches the phase total", async () => {
    const { runtime } = createFixtureRuntime({ transcript: RECORDED });
    const result = await runtime.runStructured(
      request("appsec-routes-correction", "## unit: route-001"),
      StrictVerdictsSchema,
    );

    // Both recorded turns: 43 + 218 output tokens.
    expect(result.usage.outputTokens).toBe(261);
    // One batch only, so the phase total is exactly the batch total. Adding
    // them together would give 522, which is the double count usage.ts warns about.
    expect(runtime.stats().usage.outputTokens).toBe(261);
    expect(runtime.stats().usage.costUsd).toBeCloseTo(result.usage.costUsd, 10);
  });
});

describe("createAgentRuntime failure handling", () => {
  test("quota fails immediately, is not retried, and latches the phase shut", async () => {
    const { runtime, dispatcher } = createFixtureRuntime({ transcript: HANDWRITTEN });

    const first = await runtime
      .runStructured(request("quota-batch", "anything"), VerdictsSchema)
      .catch((error: unknown) => error);
    expect(isAgentError(first)).toBe(true);
    expect((first as AgentError).kind).toBe("quota");
    expect(dispatcher.calls).toHaveLength(1);

    // Every later batch fails without reaching the transport at all.
    const second = await runtime
      .runStructured(request("transient-batch", "anything"), VerdictsSchema)
      .catch((error: unknown) => error);
    expect(second).toBe(first);
    expect(dispatcher.calls).toHaveLength(1);
    expect(runtime.stats().quotaExhausted).toBe(true);
  });

  test("a truncated reply is classified and retried to the cap, never forever", async () => {
    const { runtime, dispatcher } = createFixtureRuntime({ transcript: HANDWRITTEN });

    const error = await runtime
      .runStructured(request("truncated-batch", "anything"), VerdictsSchema)
      .catch((thrown: unknown) => thrown);

    expect(isAgentError(error)).toBe(true);
    expect((error as AgentError).kind).toBe("truncated-output");
    // Three attempts, not the four turns the fixture holds.
    expect(dispatcher.calls).toHaveLength(3);
    expect(runtime.stats().failures["truncated-output"]).toBe(3);
    expect(dispatcher.remaining()).toContainEqual({
      batchId: "truncated-batch",
      unplayedTurns: 1,
    });
  });

  test("a truncated reply is retried without a corrective block: there is nothing to correct", async () => {
    const { runtime, dispatcher } = createFixtureRuntime({ transcript: HANDWRITTEN });
    await runtime
      .runStructured(request("truncated-batch", "anything"), VerdictsSchema)
      .catch(() => undefined);
    expect(dispatcher.calls[1]?.prompt).not.toContain("## Correction required");
  });

  test("a model that ignores the correction is given up on, not re-prompted again", async () => {
    const { runtime, dispatcher } = createFixtureRuntime({ transcript: HANDWRITTEN });

    const error = await runtime
      .runStructured(request("stubborn-batch", "anything"), VerdictsSchema)
      .catch((thrown: unknown) => thrown);

    expect((error as AgentError).kind).toBe("malformed-output");
    // Two attempts, although the cap is three: one correction is the limit.
    expect(dispatcher.calls).toHaveLength(2);
    expect(dispatcher.calls[1]?.prompt).toContain("## Correction required");
  });

  test("a transient failure is retried and the batch still succeeds", async () => {
    const { runtime, dispatcher } = createFixtureRuntime({ transcript: HANDWRITTEN });
    const result = await runtime.runStructured(
      request("transient-batch", "anything"),
      VerdictsSchema,
    );
    expect(result.attempts).toBe(2);
    expect(dispatcher.calls).toHaveLength(2);
    expect(runtime.stats().failures.transient).toBe(1);
  });

  test("a refusal is not retried", async () => {
    const { runtime, dispatcher } = createFixtureRuntime({ transcript: HANDWRITTEN });
    const error = await runtime
      .runStructured(request("refusal-batch", "anything"), VerdictsSchema)
      .catch((thrown: unknown) => thrown);
    expect((error as AgentError).kind).toBe("refusal");
    expect(dispatcher.calls).toHaveLength(1);
    expect(runtime.stats().quotaExhausted).toBe(false);
  });

  test("a failure is logged with its kind", async () => {
    const { logger, records } = createMemoryLogger();
    const { runtime } = createFixtureRuntime({ transcript: HANDWRITTEN, logger });
    await runtime.runStructured(request("quota-batch", "x"), VerdictsSchema).catch(() => undefined);
    const line = records.find((record) => record.level === "error");
    expect(line?.fields.kind).toBe("quota");
    expect(line?.fields.batchId).toBe("quota-batch");
  });
});

describe("createAgentRuntime transcripts", () => {
  test("writes the prompt and the reply of every attempt under raw/agents", async () => {
    const fs = new MemoryRawLogFileSystem();
    const { runtime } = createFixtureRuntime({ transcript: RECORDED, fs, runDir: RUN_DIR });

    const result = await runtime.runStructured(
      request("appsec-routes-correction", "## unit: route-001"),
      StrictVerdictsSchema,
    );

    const dir = agentsRawDir(RUN_DIR);
    expect(fs.paths()).toEqual([
      join(dir, "appsec-routes-correction.attempt-2.prompt.txt"),
      join(dir, "appsec-routes-correction.attempt-2.reply.txt"),
      join(dir, "appsec-routes-correction.prompt.txt"),
      join(dir, "appsec-routes-correction.reply.txt"),
    ]);
    expect(result.transcripts).toHaveLength(4);

    const firstPrompt = fs.files.get(join(dir, "appsec-routes-correction.prompt.txt")) ?? "";
    expect(firstPrompt).toContain("You are Sentinel's auditor.");
    expect(firstPrompt).toContain("## unit: route-001");
    expect(firstPrompt).not.toContain("## Correction required");

    const retryPrompt =
      fs.files.get(join(dir, "appsec-routes-correction.attempt-2.prompt.txt")) ?? "";
    expect(retryPrompt).toContain("## Correction required");

    const firstReply = fs.files.get(join(dir, "appsec-routes-correction.reply.txt")) ?? "";
    expect(firstReply.trim()).toBe(
      '{"verdicts":[{"unitId":"route-001","ownershipChecked":false,"evidenceLine":13}]}',
    );
  });

  test("a failed attempt still leaves a reply file, so a gap is never silent", async () => {
    const fs = new MemoryRawLogFileSystem();
    const { runtime } = createFixtureRuntime({ transcript: HANDWRITTEN, fs, runDir: RUN_DIR });

    await runtime.runStructured(request("quota-batch", "x"), VerdictsSchema).catch(() => undefined);

    const body = fs.files.get(join(agentsRawDir(RUN_DIR), "quota-batch.reply.txt")) ?? "";
    expect(body).toContain("kind:   quota");
    expect(body).toContain("You've reached your usage limit");
  });

  test("writes nothing when the run has no run directory", async () => {
    const fs = new MemoryRawLogFileSystem();
    const { runtime } = createFixtureRuntime({ transcript: RECORDED, fs });
    const result = await runtime.runStructured(
      request("appsec-routes-001", "## unit: route-002"),
      VerdictsSchema,
    );
    expect(result.transcripts).toEqual([]);
    expect(fs.paths()).toEqual([]);
  });
});

describe("createAgentRuntime concurrency", () => {
  /** A transport that never resolves until the test lets it, so overlap is observable. */
  function gatedDispatcher(): {
    dispatcher: AgentDispatcher;
    release: () => void;
    peak: () => number;
  } {
    const pending: Array<() => void> = [];
    let active = 0;
    let peak = 0;
    return {
      dispatcher: {
        kind: "fixture",
        async dispatch(_request: AgentDispatchRequest) {
          active += 1;
          peak = Math.max(peak, active);
          await new Promise<void>((resolve) => pending.push(resolve));
          active -= 1;
          return { text: '{"verdicts":[]}', usage: ZERO_USAGE };
        },
      },
      release: () => {
        for (const resolve of pending.splice(0)) resolve();
      },
      peak: () => peak,
    };
  }

  test("defaults to two batches in flight", async () => {
    const { dispatcher, release, peak } = gatedDispatcher();
    const { createAgentRuntime } = await import("./runtime.ts");
    const runtime = createAgentRuntime({ dispatcher });
    expect(runtime.metadata.concurrency).toBe(2);

    const batches = [0, 1, 2, 3, 4].map((index) =>
      runtime.runStructured(request(`batch-${index}`, "x"), VerdictsSchema),
    );
    await Promise.resolve();
    await Promise.resolve();
    release();
    // Later batches are admitted as slots free up; keep releasing until done.
    const results = await Promise.all(
      batches.map((promise) => {
        const pump = setInterval(release, 1);
        return promise.finally(() => clearInterval(pump));
      }),
    );

    expect(results).toHaveLength(5);
    expect(peak()).toBeLessThanOrEqual(2);
  });

  test("records the effective fan-out in the run metadata", async () => {
    const { runtime } = createFixtureRuntime({ transcript: RECORDED, concurrency: 4 });
    expect(runtime.metadata.concurrency).toBe(4);
    expect(runtime.metadata.kind).toBe("fixture");
    expect(runtime.stats().metadata.concurrency).toBe(4);
  });

  test("a handwritten transcript marks the run synthetic; a recorded one does not", async () => {
    expect(createFixtureRuntime({ transcript: HANDWRITTEN }).runtime.metadata.synthetic).toBe(true);
    expect(createFixtureRuntime({ transcript: RECORDED }).runtime.metadata.synthetic).toBe(false);
  });
});
