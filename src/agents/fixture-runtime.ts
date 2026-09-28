/**
 * The replay transport.
 *
 * Every test of an AI phase runs through this: the recorded transcript answers
 * in the transport's place, so no test touches the network, the subscription,
 * or the user's rate limit. It is also how a failure path gets covered at all
 * — scripting "quota on the third batch" against a real model is not something
 * anyone can do on demand.
 */

import { AgentError } from "./errors.ts";
import { type AgentRuntimeOptions, createAgentRuntime } from "./runtime.ts";
import {
  type AgentTranscript,
  type TranscriptEntry,
  type TranscriptTurn,
  parseAgentTranscript,
} from "./transcript.ts";
import type {
  AgentDispatchReply,
  AgentDispatchRequest,
  AgentDispatcher,
  AgentRuntime,
} from "./types.ts";
import { ZERO_USAGE } from "./usage.ts";

/** Anything left unplayed when the phase finished, so a test can assert coverage. */
export interface TranscriptRemainder {
  readonly batchId: string;
  readonly unplayedTurns: number;
}

/** A dispatcher backed by a transcript, plus the bookkeeping a test asserts on. */
export interface FixtureDispatcher extends AgentDispatcher {
  /** Every dispatch this transport was asked for, in order. */
  readonly calls: readonly AgentDispatchRequest[];
  /** Batches whose turns were not all consumed. */
  remaining(): TranscriptRemainder[];
}

/** Everything `createFixtureDispatcher` takes. */
export interface FixtureDispatcherOptions {
  readonly transcript: AgentTranscript;
}

/** Playback position for one batch. */
interface Cursor {
  readonly entry: TranscriptEntry;
  index: number;
}

/**
 * A fixture miss is a bug in the test, not a failure of the model, so it is
 * marked non-retryable: the test sees one loud error instead of three quiet
 * ones followed by a misleading `transient`.
 */
function miss(detail: string, request: AgentDispatchRequest): AgentError {
  return new AgentError("transient", `FIXTURE TRANSCRIPT MISS: ${detail}`, {
    batchId: request.batchId,
    attempt: request.attempt,
    retryable: false,
  });
}

/** Builds a transport that replays `transcript`. */
export function createFixtureDispatcher(options: FixtureDispatcherOptions): FixtureDispatcher {
  const cursors = new Map<string, Cursor>();
  for (const entry of options.transcript.entries) {
    cursors.set(entry.batchId, { entry, index: 0 });
  }
  const calls: AgentDispatchRequest[] = [];
  const model = options.transcript.model;

  const play = (turn: TranscriptTurn, request: AgentDispatchRequest): AgentDispatchReply => {
    for (const needle of turn.expectPromptContains) {
      if (!request.prompt.includes(needle)) {
        throw miss(
          `prompt for "${request.batchId}" does not contain ${JSON.stringify(needle)}`,
          request,
        );
      }
    }
    if (turn.failure !== undefined) {
      throw new AgentError(turn.failure.kind, turn.failure.detail, {
        batchId: request.batchId,
        attempt: request.attempt,
      });
    }
    return {
      text: turn.reply ?? "",
      usage: turn.usage ?? ZERO_USAGE,
      ...(model === undefined ? {} : { model }),
    };
  };

  return {
    kind: "fixture",
    ...(model === undefined ? {} : { model }),
    calls,
    async dispatch(request: AgentDispatchRequest): Promise<AgentDispatchReply> {
      calls.push(request);
      const cursor = cursors.get(request.batchId);
      if (cursor === undefined) {
        throw miss(`no entry for batch "${request.batchId}"`, request);
      }
      const turn = cursor.entry.turns[cursor.index];
      if (turn === undefined) {
        throw miss(
          `batch "${request.batchId}" has ${cursor.entry.turns.length} turn(s), asked for ${cursor.index + 1}`,
          request,
        );
      }
      cursor.index += 1;
      return play(turn, request);
    },
    remaining(): TranscriptRemainder[] {
      const out: TranscriptRemainder[] = [];
      for (const [batchId, cursor] of cursors) {
        const unplayed = cursor.entry.turns.length - cursor.index;
        if (unplayed > 0) out.push({ batchId, unplayedTurns: unplayed });
      }
      return out;
    },
  };
}

/** Everything `createFixtureRuntime` takes: the transcript plus the runtime's own knobs. */
export interface FixtureRuntimeOptions extends Omit<AgentRuntimeOptions, "dispatcher"> {
  readonly transcript: AgentTranscript;
}

/** A runtime plus the transport underneath it, so a test can assert on both. */
export interface FixtureRuntime {
  readonly runtime: AgentRuntime;
  readonly dispatcher: FixtureDispatcher;
}

/**
 * Builds the replay runtime. Retry backoff defaults to zero here: a test
 * asserting the corrective re-prompt should not also wait a second for it.
 */
export function createFixtureRuntime(options: FixtureRuntimeOptions): FixtureRuntime {
  const { transcript, ...rest } = options;
  const dispatcher = createFixtureDispatcher({ transcript });
  const runtime = createAgentRuntime({
    ...rest,
    dispatcher,
    retryDelayMs: rest.retryDelayMs ?? 0,
    synthetic: rest.synthetic ?? transcript.source === "handwritten",
  });
  return { runtime, dispatcher };
}

/** The slice of the filesystem port needed to load a transcript from disk. */
export interface TranscriptFileSystem {
  readFile(path: string): Promise<string>;
}

/** Loads and validates a transcript file; rejects with the reason it is not one. */
export async function loadAgentTranscript(
  fs: TranscriptFileSystem,
  path: string,
): Promise<AgentTranscript> {
  const parsed = parseAgentTranscript(await fs.readFile(path));
  if (!parsed.ok) throw new Error(`invalid agent transcript at ${path}: ${parsed.reason}`);
  return parsed.transcript;
}
