/**
 * The AI runtime: retries, validation, transcripts, accounting and fan-out,
 * around whichever transport is answering.
 *
 * Nothing in here knows how to talk to Claude — that is `claude-dispatcher.ts`
 * — and nothing in here reads the target repository. The prompt it sends is
 * the prompt it was given; the code an agent reasons about was extracted from
 * disk by the inventory phase and pasted into that prompt, because an agent
 * with file tools is an agent that can read the wrong directory and say
 * nothing about it.
 */

import type { z } from "zod";
import { type Clock, createSystemClock } from "../ports/clock.ts";
import { type Logger, silentLogger } from "../ports/logger.ts";
import {
  AgentError,
  type AgentFailureKind,
  emptyFailureCounts,
  isFatal,
  isRetryable,
  toAgentError,
} from "./errors.ts";
import { parseStructured } from "./json.ts";
import { DEFAULT_CONCURRENCY, createSemaphore } from "./pool.ts";
import {
  type RawLogFileSystem,
  type RawLogSink,
  createRawLogSink,
  nullRawLogSink,
  renderPromptFile,
} from "./raw-log.ts";
import type {
  AgentDispatcher,
  AgentRequest,
  AgentRunStats,
  AgentRuntime,
  AgentRuntimeMetadata,
  StructuredResult,
} from "./types.ts";
import { UsageLedger, ZERO_USAGE, addUsage } from "./usage.ts";

/** Attempts per batch, the first one included. */
export const DEFAULT_MAX_ATTEMPTS = 3;

/** Wall-clock budget for one attempt. A batch carries a lot of code; give it room. */
export const DEFAULT_TIMEOUT_MS = 240_000;

/** Base backoff between attempts; doubles each time. */
export const DEFAULT_RETRY_DELAY_MS = 1_000;

/** At most one corrective re-prompt per batch: a model that ignores it twice will ignore it thrice. */
const MAX_CORRECTIONS = 1;

/** Everything `createAgentRuntime` takes. */
export interface AgentRuntimeOptions {
  /** The transport. `createClaudeDispatcher()` in production, a fixture in tests. */
  readonly dispatcher: AgentDispatcher;
  /** Filesystem port; without it no transcripts are written. */
  readonly fs?: RawLogFileSystem | undefined;
  /** Run directory; transcripts land in `<runDir>/raw/agents/`. */
  readonly runDir?: string | undefined;
  /** Batches in flight at once. Default 2 — the subscription is the bottleneck. */
  readonly concurrency?: number | undefined;
  /** Attempts per batch. Default 3. */
  readonly maxAttempts?: number | undefined;
  /** Wall-clock budget per attempt. Default 240s. */
  readonly timeoutMs?: number | undefined;
  /** Base retry backoff. Default 1s, doubling. Set 0 in tests. */
  readonly retryDelayMs?: number | undefined;
  /** Marks the run's answers as not coming from a real model. */
  readonly synthetic?: boolean | undefined;
  readonly logger?: Logger | undefined;
  readonly clock?: Clock | undefined;
  /** Cancels every in-flight and queued dispatch. */
  readonly signal?: AbortSignal | undefined;
}

/**
 * The corrective re-prompt. It names the violation rather than saying "that
 * was wrong", because a model cannot fix an error it has not been shown, and
 * it repeats the no-prose instruction because the usual failure is a model
 * wrapping correct JSON in an apology.
 */
export function correctionBlock(violation: string): string {
  return [
    "## Correction required",
    "",
    "Your previous reply could not be used. It failed validation as follows:",
    "",
    violation,
    "",
    "Send the whole document again, corrected. Reply with the JSON document and",
    "nothing else: no explanation before it, no commentary after it, no markdown",
    "fence. Change only what the violation above names; keep every other field",
    "exactly as you had it.",
  ].join("\n");
}

/** Renders the failure of an attempt into the reply transcript, so a gap is never silent. */
function renderFailureFile(error: AgentError): string {
  return [
    "=== sentinel agent failure ======================================",
    `kind:   ${error.kind}`,
    `detail: ${error.detail}`,
    "",
    "No reply text was received for this attempt.",
    "",
  ].join("\n");
}

/**
 * Builds the runtime. The returned object is safe to share across the whole
 * phase: one semaphore, one ledger, one quota latch.
 */
export function createAgentRuntime(options: AgentRuntimeOptions): AgentRuntime {
  const logger = (options.logger ?? silentLogger).child({ phase: "agents" });
  const clock = options.clock ?? createSystemClock();
  const dispatcher = options.dispatcher;

  const metadata: AgentRuntimeMetadata = {
    kind: dispatcher.kind,
    model: dispatcher.model,
    concurrency: Math.max(1, Math.floor(options.concurrency ?? DEFAULT_CONCURRENCY)),
    maxAttempts: Math.max(1, Math.floor(options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS)),
    timeoutMs: Math.max(1, Math.floor(options.timeoutMs ?? DEFAULT_TIMEOUT_MS)),
    synthetic: options.synthetic ?? dispatcher.kind === "fixture",
  };

  const semaphore = createSemaphore(metadata.concurrency);
  const ledger = new UsageLedger();
  const failures = emptyFailureCounts();
  const retryDelayMs = Math.max(0, options.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS);
  const sink: RawLogSink =
    options.fs !== undefined && options.runDir !== undefined
      ? createRawLogSink(options.fs, options.runDir)
      : nullRawLogSink;

  let dispatches = 0;
  let retries = 0;
  /** Latched by the first `quota` failure; every later call fails without dispatching. */
  let quotaFailure: AgentError | undefined;

  const countFailure = (kind: AgentFailureKind): void => {
    failures[kind] += 1;
  };

  const runOnce = async <S extends z.ZodType>(
    request: AgentRequest,
    schema: S,
  ): Promise<StructuredResult<z.infer<S>>> => {
    const maxAttempts = Math.max(1, Math.floor(request.maxAttempts ?? metadata.maxAttempts));
    const timeoutMs = Math.max(1, Math.floor(request.timeoutMs ?? metadata.timeoutMs));
    const log = logger.child({ batchId: request.batchId, ...(request.logFields ?? {}) });

    const transcripts: string[] = [];
    let dispatchUsage = ZERO_USAGE;
    let correction: string | undefined;
    let corrections = 0;
    let lastError: AgentError | undefined;

    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      if (quotaFailure !== undefined) throw quotaFailure;
      if (options.signal?.aborted === true) {
        throw new AgentError("timeout", "the run was cancelled", {
          batchId: request.batchId,
          attempt,
          retryable: false,
        });
      }
      dispatches += 1;
      if (attempt > 1) retries += 1;

      const prompt =
        correction === undefined
          ? request.prompt
          : `${request.prompt}\n\n${correctionBlock(correction)}`;

      const promptPath = await sink.writePrompt(
        request.batchId,
        attempt,
        renderPromptFile({
          batchId: request.batchId,
          attempt,
          model: dispatcher.model,
          systemPrompt: request.systemPrompt,
          prompt,
        }),
      );
      if (promptPath !== null) transcripts.push(promptPath);

      let reply: Awaited<ReturnType<AgentDispatcher["dispatch"]>>;
      try {
        reply = await dispatcher.dispatch({
          batchId: request.batchId,
          attempt,
          systemPrompt: request.systemPrompt,
          prompt,
          timeoutMs,
          ...(options.signal === undefined ? {} : { signal: options.signal }),
        });
      } catch (thrown) {
        const error = toAgentError(thrown, { batchId: request.batchId, attempt });
        countFailure(error.kind);
        const failurePath = await sink.writeReply(
          request.batchId,
          attempt,
          renderFailureFile(error),
        );
        if (failurePath !== null) transcripts.push(failurePath);

        if (isFatal(error)) {
          // A subscription limit does not heal by retrying: latch the whole
          // runtime shut so the queued batches fail instantly and the phase
          // can report exactly how far it got.
          quotaFailure = error;
          log.error("agent dispatch hit a subscription limit; stopping the phase", {
            kind: error.kind,
            detail: error.detail,
          });
          throw error;
        }
        log.warn("agent dispatch failed", { attempt, kind: error.kind, detail: error.detail });
        lastError = error;
        if (!isRetryable(error) || attempt === maxAttempts) throw error;
        await clock.sleep(retryDelayMs * 2 ** (attempt - 1));
        continue;
      }

      // The one and only usage accounting point in the codebase. See usage.ts.
      ledger.record(reply.usage);
      dispatchUsage = addUsage(dispatchUsage, reply.usage);

      const replyPath = await sink.writeReply(request.batchId, attempt, reply.text);
      if (replyPath !== null) transcripts.push(replyPath);

      const parsed = parseStructured(reply.text, schema);
      if (parsed.ok) {
        log.debug("agent batch validated", {
          attempt,
          strategy: parsed.strategy,
          outputTokens: reply.usage.outputTokens,
        });
        return {
          value: parsed.value,
          raw: reply.text,
          usage: dispatchUsage,
          attempts: attempt,
          transcripts,
        };
      }

      const error = new AgentError(parsed.failure.kind, parsed.failure.detail, {
        batchId: request.batchId,
        attempt,
      });
      countFailure(error.kind);
      log.warn("agent reply rejected", { attempt, kind: error.kind, detail: error.detail });
      lastError = error;

      if (attempt === maxAttempts) throw error;
      if (error.kind === "malformed-output") {
        // One corrective re-prompt, then give up on this batch: a model that
        // ignores a named violation once will ignore it again, and the run
        // has other batches to spend its quota on.
        if (corrections >= MAX_CORRECTIONS) throw error;
        corrections += 1;
        correction = error.detail;
        continue;
      }
      // Truncated output: nothing to correct, just try again.
      correction = undefined;
      await clock.sleep(retryDelayMs * 2 ** (attempt - 1));
    }

    throw (
      lastError ?? new AgentError("transient", "no attempt was made", { batchId: request.batchId })
    );
  };

  return {
    metadata,
    async runStructured<S extends z.ZodType>(
      request: AgentRequest,
      schema: S,
    ): Promise<StructuredResult<z.infer<S>>> {
      if (quotaFailure !== undefined) throw quotaFailure;
      return await semaphore.run(() => runOnce(request, schema));
    },
    stats(): AgentRunStats {
      return {
        metadata,
        dispatches,
        retries,
        failures: { ...failures },
        usage: ledger.total(),
        quotaExhausted: quotaFailure !== undefined,
      };
    },
  };
}
