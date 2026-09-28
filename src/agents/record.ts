/**
 * Capturing a real dispatch as a replayable transcript.
 *
 * Wrap the live transport in `createRecordingDispatcher`, run a phase once
 * against the subscription, and write the result under `__fixtures__/` with
 * `source: "recorded"`. Every later test replays it for free. This is the only
 * supported way to produce a `recorded` transcript — a fixture written by hand
 * must say `handwritten`, because a test that replays invented answers proves
 * the wiring and nothing else.
 */

import type { AgentTranscriptInput } from "./transcript.ts";
import { TRANSCRIPT_SCHEMA_VERSION } from "./transcript.ts";
import type { AgentDispatchReply, AgentDispatchRequest, AgentDispatcher } from "./types.ts";

/** A transport that also remembers what it was asked and what came back. */
export interface RecordingDispatcher extends AgentDispatcher {
  /** The transcript captured so far, ready for `serializeTranscript`. */
  transcript(note?: string): AgentTranscriptInput;
}

/** Wraps a transport so every dispatch is appended to a transcript. */
export function createRecordingDispatcher(inner: AgentDispatcher): RecordingDispatcher {
  const order: string[] = [];
  const turns = new Map<string, AgentTranscriptInput["entries"][number]["turns"]>();

  const push = (
    batchId: string,
    turn: AgentTranscriptInput["entries"][number]["turns"][number],
  ): void => {
    const existing = turns.get(batchId);
    if (existing === undefined) {
      order.push(batchId);
      turns.set(batchId, [turn]);
      return;
    }
    existing.push(turn);
  };

  return {
    kind: inner.kind,
    ...(inner.model === undefined ? {} : { model: inner.model }),
    async dispatch(request: AgentDispatchRequest): Promise<AgentDispatchReply> {
      try {
        const reply = await inner.dispatch(request);
        push(request.batchId, { reply: reply.text, usage: reply.usage });
        return reply;
      } catch (thrown) {
        const failure = thrown as { kind?: unknown; detail?: unknown; message?: unknown };
        push(request.batchId, {
          failure: {
            kind: typeof failure.kind === "string" ? (failure.kind as never) : "transient",
            detail: String(failure.detail ?? failure.message ?? "unknown failure"),
          },
        });
        throw thrown;
      }
    },
    transcript(note?: string): AgentTranscriptInput {
      return {
        schemaVersion: TRANSCRIPT_SCHEMA_VERSION,
        source: "recorded",
        recordedAt: new Date().toISOString(),
        ...(inner.model === undefined ? {} : { model: inner.model }),
        ...(note === undefined ? {} : { note }),
        entries: order.map((batchId) => ({ batchId, turns: turns.get(batchId) ?? [] })),
      };
    },
  };
}
