import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { z } from "zod";
import { AgentError, isRetryable } from "./errors.ts";
import {
  createFixtureDispatcher,
  createFixtureRuntime,
  loadAgentTranscript,
} from "./fixture-runtime.ts";
import { createRecordingDispatcher } from "./record.ts";
import { type AgentTranscript, parseAgentTranscript, serializeTranscript } from "./transcript.ts";
import type { AgentDispatchRequest, AgentDispatcher } from "./types.ts";
import { ZERO_USAGE } from "./usage.ts";

const DIR = join(import.meta.dir, "__fixtures__/transcripts");

/** The real filesystem port's `readFile`, narrowed to what the loader needs. */
const diskFs = { readFile: (path: string) => Bun.file(path).text() };

const REQUEST: AgentDispatchRequest = {
  batchId: "appsec-routes-001",
  attempt: 1,
  systemPrompt: "system",
  prompt: "## unit: route-002 GET /api/orders/:id",
  timeoutMs: 1_000,
};

/** The committed live recording, loaded through the loader under test. */
const recorded: AgentTranscript = await loadAgentTranscript(
  diskFs,
  join(DIR, "routes-recorded.json"),
);

describe("loadAgentTranscript", () => {
  test("loads and validates a committed transcript", () => {
    expect(recorded.entries).toHaveLength(2);
    expect(recorded.source).toBe("recorded");
  });

  test("rejects a file that is not a transcript, naming why", async () => {
    await expect(
      loadAgentTranscript({ readFile: async () => '{"schemaVersion":"9.9"}' }, "/x.json"),
    ).rejects.toThrow("invalid agent transcript");
  });
});

describe("createFixtureDispatcher", () => {
  test("replays the recorded turns of a batch in order", async () => {
    const dispatcher = createFixtureDispatcher({ transcript: recorded });
    const reply = await dispatcher.dispatch(REQUEST);
    expect(reply.text).toContain('"unitId":"route-001"');
    expect(reply.usage.outputTokens).toBe(300);
    expect(reply.model).toBe("claude-opus-5-5");
    expect(dispatcher.calls).toHaveLength(1);
  });

  test("a scripted failure is thrown as the classified AgentError it names", async () => {
    const transcript = parseAgentTranscript(
      serializeTranscript({
        schemaVersion: "1.0",
        source: "handwritten",
        entries: [{ batchId: "b", turns: [{ failure: { kind: "quota", detail: "spent" } }] }],
      }),
    );
    expect(transcript.ok).toBe(true);
    if (!transcript.ok) return;

    const dispatcher = createFixtureDispatcher({ transcript: transcript.transcript });
    const error = await dispatcher
      .dispatch({ ...REQUEST, batchId: "b" })
      .catch((thrown: unknown) => thrown);
    expect(error).toBeInstanceOf(AgentError);
    expect((error as AgentError).kind).toBe("quota");
  });

  test("an unknown batch is a loud, non-retryable test bug, not a model failure", async () => {
    const dispatcher = createFixtureDispatcher({ transcript: recorded });
    const error = await dispatcher
      .dispatch({ ...REQUEST, batchId: "never-recorded" })
      .catch((thrown: unknown) => thrown);
    expect((error as AgentError).detail).toContain("FIXTURE TRANSCRIPT MISS");
    expect(isRetryable(error as AgentError)).toBe(false);
  });

  test("running past the recorded turns is reported with the counts", async () => {
    const dispatcher = createFixtureDispatcher({ transcript: recorded });
    await dispatcher.dispatch(REQUEST);
    const error = await dispatcher
      .dispatch({ ...REQUEST, attempt: 2 })
      .catch((thrown: unknown) => thrown);
    expect((error as AgentError).detail).toContain("has 1 turn(s), asked for 2");
  });

  test("a prompt expectation that misses fails the replay instead of answering anyway", async () => {
    const dispatcher = createFixtureDispatcher({ transcript: recorded });
    const error = await dispatcher
      .dispatch({ ...REQUEST, prompt: "a completely different batch" })
      .catch((thrown: unknown) => thrown);
    expect((error as AgentError).detail).toContain("does not contain");
  });

  test("reports the turns no test consumed", async () => {
    const dispatcher = createFixtureDispatcher({ transcript: recorded });
    await dispatcher.dispatch(REQUEST);
    expect(dispatcher.remaining()).toEqual([
      { batchId: "appsec-routes-correction", unplayedTurns: 2 },
    ]);
  });
});

describe("createFixtureRuntime", () => {
  test("builds a working runtime with zero retry backoff", async () => {
    const { runtime } = createFixtureRuntime({ transcript: recorded });
    const result = await runtime.runStructured(
      { batchId: "appsec-routes-001", systemPrompt: "s", prompt: REQUEST.prompt },
      z.object({ verdicts: z.array(z.object({ unitId: z.string() })) }),
    );
    expect(result.value.verdicts).toHaveLength(2);
    expect(runtime.metadata.kind).toBe("fixture");
  });
});

describe("createRecordingDispatcher", () => {
  /** A transport that answers once and then fails, so both branches are recorded. */
  function flaky(): AgentDispatcher {
    let calls = 0;
    return {
      kind: "claude-agent-sdk",
      model: "claude-opus-5-5",
      async dispatch(_request: AgentDispatchRequest) {
        calls += 1;
        if (calls === 1) return { text: '{"ok":true}', usage: { ...ZERO_USAGE, outputTokens: 7 } };
        throw new AgentError("quota", "spent");
      },
    };
  }

  test("captures replies and failures as a replayable transcript", async () => {
    const recorder = createRecordingDispatcher(flaky());
    await recorder.dispatch({ ...REQUEST, batchId: "batch-a" });
    await recorder.dispatch({ ...REQUEST, batchId: "batch-a", attempt: 2 }).catch(() => undefined);

    const text = serializeTranscript(recorder.transcript("smoke"));
    const parsed = parseAgentTranscript(text);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;

    expect(parsed.transcript.source).toBe("recorded");
    expect(parsed.transcript.model).toBe("claude-opus-5-5");
    const turns = parsed.transcript.entries[0]?.turns ?? [];
    expect(turns[0]?.reply).toBe('{"ok":true}');
    expect(turns[0]?.usage?.outputTokens).toBe(7);
    expect(turns[1]?.failure).toEqual({ kind: "quota", detail: "spent" });
  });

  test("the captured transcript replays identically", async () => {
    const recorder = createRecordingDispatcher(flaky());
    await recorder.dispatch({ ...REQUEST, batchId: "batch-a" });
    const parsed = parseAgentTranscript(serializeTranscript(recorder.transcript()));
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;

    const replay = createFixtureDispatcher({ transcript: parsed.transcript });
    const reply = await replay.dispatch({ ...REQUEST, batchId: "batch-a" });
    expect(reply.text).toBe('{"ok":true}');
  });
});
