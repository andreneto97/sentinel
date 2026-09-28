/**
 * How an AI dispatch can fail, and what Sentinel is allowed to do about it.
 *
 * The taxonomy is deliberately small and closed: the score and report phases
 * read these kinds to explain a partial run, so a new failure mode has to be
 * classified rather than logged as "something went wrong".
 */

import { z } from "zod";

/** Every way a dispatch can fail. Closed set: the report renders one line per kind. */
export const AGENT_FAILURE_KINDS = [
  "malformed-output",
  "truncated-output",
  "timeout",
  "quota",
  "transient",
  "refusal",
] as const;

/** One of {@link AGENT_FAILURE_KINDS}. */
export type AgentFailureKind = (typeof AGENT_FAILURE_KINDS)[number];

/** Validates a failure kind read from a recorded transcript. */
export const AgentFailureKindSchema = z.enum(AGENT_FAILURE_KINDS);

/**
 * Whether another attempt at the same dispatch can plausibly succeed.
 *
 * `quota` is false on purpose: a subscription limit is a wall clock, not a
 * flaky socket, and retrying into it only burns the rest of the run's budget
 * of wall time. `refusal` is false because the model declined the request
 * itself — the same prompt produces the same refusal.
 */
const RETRYABLE_BY_KIND: Readonly<Record<AgentFailureKind, boolean>> = {
  "malformed-output": true,
  "truncated-output": true,
  timeout: true,
  quota: false,
  transient: true,
  refusal: false,
};

/**
 * Whether this kind ends the whole phase rather than just this batch.
 *
 * Only `quota`: once the subscription refuses to serve, every remaining batch
 * would fail the same way. Stopping on the first one lets the dossier name the
 * wall — "the handlers after this point were not audited: the subscription ran
 * out" — where grinding on turns the same outcome into a pile of timeouts that
 * look like the model's fault and say nothing about why the run is short.
 */
const FATAL_BY_KIND: Readonly<Record<AgentFailureKind, boolean>> = {
  "malformed-output": false,
  "truncated-output": false,
  timeout: false,
  quota: true,
  transient: false,
  refusal: false,
};

/** Extra context attached to a failure. */
export interface AgentErrorOptions {
  /** Batch the dispatch belonged to, when the failure happened inside one. */
  readonly batchId?: string | undefined;
  /** 1-based attempt number within the dispatch. */
  readonly attempt?: number | undefined;
  /** Overrides the kind's default retry policy; used for failures that are not the model's. */
  readonly retryable?: boolean | undefined;
  readonly cause?: unknown;
}

/** A classified AI failure. The dispatcher and runtime throw nothing else. */
export class AgentError extends Error {
  readonly kind: AgentFailureKind;
  /** Short, human-readable cause, safe to render in the report. */
  readonly detail: string;
  readonly batchId: string | undefined;
  readonly attempt: number | undefined;
  /** Set only when the caller overrode the kind's default retry policy. */
  readonly retryableOverride: boolean | undefined;

  constructor(kind: AgentFailureKind, detail: string, options: AgentErrorOptions = {}) {
    super(`${kind}: ${detail}`, options.cause === undefined ? {} : { cause: options.cause });
    this.name = "AgentError";
    this.kind = kind;
    this.detail = detail;
    this.batchId = options.batchId;
    this.attempt = options.attempt;
    this.retryableOverride = options.retryable;
  }
}

/** True when `value` is an {@link AgentError}. */
export function isAgentError(value: unknown): value is AgentError {
  return value instanceof AgentError;
}

/** Whether this failure may be attempted again. */
export function isRetryable(error: AgentError): boolean {
  return error.retryableOverride ?? RETRYABLE_BY_KIND[error.kind];
}

/** Whether this failure must stop the phase, not only the batch. */
export function isFatal(error: AgentError): boolean {
  return FATAL_BY_KIND[error.kind];
}

/**
 * Wraps anything thrown below the dispatcher in the taxonomy. An unclassified
 * exception is treated as transient but not retried: a bug in Sentinel should
 * surface on the first batch, not three times on every batch.
 */
export function toAgentError(value: unknown, options: AgentErrorOptions = {}): AgentError {
  if (isAgentError(value)) return value;
  const detail = value instanceof Error ? value.message : String(value);
  return new AgentError("transient", detail, { ...options, retryable: false, cause: value });
}

/** A zeroed counter for every kind, so a report table has no missing rows. */
export function emptyFailureCounts(): Record<AgentFailureKind, number> {
  return {
    "malformed-output": 0,
    "truncated-output": 0,
    timeout: 0,
    quota: 0,
    transient: 0,
    refusal: 0,
  };
}
