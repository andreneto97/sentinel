/**
 * The contract between Sentinel's AI phases and whatever is answering them.
 *
 * The central rule, which every type here exists to enforce: **Sentinel feeds
 * the code to the model; the model never reads files.** A request carries a
 * system prompt and a user prompt, and nothing else — no working directory, no
 * tool list, no file handles. The inventory phase has already extracted every
 * source slice the agent is allowed to reason about and pasted it into
 * `prompt`. Whatever comes back is re-verified against disk by `src/verify/`
 * anyway, so a citation the model invented cannot survive to the report.
 */

import type { z } from "zod";
import type { AgentFailureKind } from "./errors.ts";
import type { AgentUsage } from "./usage.ts";

/** Which transport answered a run; recorded in the run metadata. */
export type AgentRuntimeKind = "claude-agent-sdk" | "fixture";

/** One unit of work handed to the model. */
export interface AgentRequest {
  /**
   * Identifies the batch across the run. Used as the transcript file name and
   * as the replay key of a recorded transcript, so it must be stable for a
   * given inventory — derive it from the batch's contents, not from a counter.
   */
  readonly batchId: string;
  /** The role and the rules. Constant across a phase, so the prompt cache can hold it. */
  readonly systemPrompt: string;
  /** The work: the units, their attributes, and the source slices read from disk. */
  readonly prompt: string;
  /** Overrides the runtime's per-dispatch wall-clock budget. */
  readonly timeoutMs?: number | undefined;
  /** Overrides the runtime's attempt cap for this request. */
  readonly maxAttempts?: number | undefined;
  /** Free-form fields merged into the run log for this dispatch. */
  readonly logFields?: Readonly<Record<string, unknown>> | undefined;
}

/** A validated structured answer, with everything needed to audit how it arrived. */
export interface StructuredResult<T> {
  /** The schema-validated payload. */
  readonly value: T;
  /** The exact reply text the value was extracted from. */
  readonly raw: string;
  /**
   * Usage for THIS dispatch only, summed across its attempts. The phase total
   * is `AgentRuntime.stats().usage`; adding this on top of that double counts.
   */
  readonly usage: AgentUsage;
  /** How many attempts it took, including the corrective re-prompt. */
  readonly attempts: number;
  /** Paths written under `<runDir>/raw/agents/`, in the order they were written. */
  readonly transcripts: readonly string[];
}

/** One attempt, as the transport sees it. */
export interface AgentDispatchRequest {
  readonly batchId: string;
  /** 1-based. Attempt 2 of a malformed reply carries the corrective prompt. */
  readonly attempt: number;
  readonly systemPrompt: string;
  readonly prompt: string;
  /** Wall-clock budget for this attempt. */
  readonly timeoutMs: number;
  /** Cancels the attempt; the runtime forwards the run's signal. */
  readonly signal?: AbortSignal | undefined;
}

/** What a transport returns for one attempt. */
export interface AgentDispatchReply {
  /** The model's final text, untouched. */
  readonly text: string;
  /** Usage for this attempt, read once from the transport's own accounting. */
  readonly usage: AgentUsage;
  /** The model that answered, when the transport reports one. */
  readonly model?: string | undefined;
}

/**
 * The seam between the retry/validation logic and the thing that talks to
 * Claude. Implemented twice: once over the Claude Agent SDK, once over a
 * recorded transcript so the whole pipeline is testable offline.
 */
export interface AgentDispatcher {
  readonly kind: AgentRuntimeKind;
  /** The model the transport will use, when it is pinned. */
  readonly model?: string | undefined;
  /** Runs one attempt. Rejects with an `AgentError` and nothing else. */
  dispatch(request: AgentDispatchRequest): Promise<AgentDispatchReply>;
}

/** The effective settings of a runtime, for `run-metadata.json` and the report. */
export interface AgentRuntimeMetadata {
  readonly kind: AgentRuntimeKind;
  readonly model: string | undefined;
  /** The effective fan-out, after defaults and clamping. */
  readonly concurrency: number;
  readonly maxAttempts: number;
  readonly timeoutMs: number;
  /**
   * True when the answers came from a hand-written fixture rather than a real
   * model. The report must disclose it: a green run against handwritten
   * transcripts is a wiring guard, not evidence about the code.
   */
  readonly synthetic: boolean;
}

/** What the phase reports about its AI spend and its failures. */
export interface AgentRunStats {
  readonly metadata: AgentRuntimeMetadata;
  /** Attempts that reached the transport, retries included. */
  readonly dispatches: number;
  /** Attempts beyond the first. */
  readonly retries: number;
  readonly failures: Readonly<Record<AgentFailureKind, number>>;
  /** The phase total. Never add `StructuredResult.usage` to this. */
  readonly usage: AgentUsage;
  /** True once a quota failure latched the runtime shut. */
  readonly quotaExhausted: boolean;
}

/** What the audit and dead-code phases call. */
export interface AgentRuntime {
  readonly metadata: AgentRuntimeMetadata;
  /**
   * Sends one batch, validates the reply against `schema`, and retries a
   * malformed body once with a corrective reminder that names the violation.
   * Rejects with an `AgentError` when every attempt failed; a `quota`
   * rejection means the phase must stop rather than move to the next batch.
   */
  runStructured<S extends z.ZodType>(
    request: AgentRequest,
    schema: S,
  ): Promise<StructuredResult<z.infer<S>>>;
  /** Spend and failure counts so far. */
  stats(): AgentRunStats;
}
