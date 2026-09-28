/**
 * Phase 4/5 AI runtime.
 *
 * Sentinel feeds the code to the model; the model never reads files. The
 * agents this module drives have no filesystem, no shell, no MCP server and no
 * skills — the source slices they reason about arrive in the prompt, and every
 * citation they return is re-verified against disk by `src/verify/`.
 */

export {
  AGENT_FAILURE_KINDS,
  AgentError,
  AgentFailureKindSchema,
  emptyFailureCounts,
  isAgentError,
  isFatal,
  isRetryable,
  toAgentError,
} from "./errors.ts";
export type { AgentErrorOptions, AgentFailureKind } from "./errors.ts";

export { extractJson, formatSchemaViolation, parseStructured } from "./json.ts";
export type {
  JsonExtraction,
  JsonExtractionFailure,
  JsonStrategy,
  StructuredFailure,
  StructuredParse,
} from "./json.ts";

export { DEFAULT_CONCURRENCY, createSemaphore, mapWithConcurrency } from "./pool.ts";
export type { Semaphore } from "./pool.ts";

export {
  AGENTS_RAW_DIR,
  agentsRawDir,
  createRawLogSink,
  nullRawLogSink,
  renderPromptFile,
  safeBatchId,
  transcriptStem,
} from "./raw-log.ts";
export type { RawLogFileSystem, RawLogSink } from "./raw-log.ts";

export {
  DEFAULT_MAX_ATTEMPTS,
  DEFAULT_RETRY_DELAY_MS,
  DEFAULT_TIMEOUT_MS,
  correctionBlock,
  createAgentRuntime,
} from "./runtime.ts";
export type { AgentRuntimeOptions } from "./runtime.ts";

export {
  DENIED_TOOLS,
  STRIPPED_ENV_VARS,
  buildEnv,
  buildQueryOptions,
  classifyAssistantError,
  classifyErrorText,
  createClaudeAgentRuntime,
  createClaudeDispatcher,
  emptyDraft,
  finishDraft,
  isUsageLimitText,
  reduceMessage,
  usageFromResult,
} from "./claude-dispatcher.ts";
export type {
  ClaudeAgentRuntimeOptions,
  ClaudeDispatcherOptions,
  ClaudeOutcome,
  ClaudeReplyDraft,
  QueryLike,
} from "./claude-dispatcher.ts";

export {
  createFixtureDispatcher,
  createFixtureRuntime,
  loadAgentTranscript,
} from "./fixture-runtime.ts";
export type {
  FixtureDispatcher,
  FixtureDispatcherOptions,
  FixtureRuntime,
  FixtureRuntimeOptions,
  TranscriptFileSystem,
  TranscriptRemainder,
} from "./fixture-runtime.ts";

export { createRecordingDispatcher } from "./record.ts";
export type { RecordingDispatcher } from "./record.ts";

export {
  AgentTranscriptSchema,
  TRANSCRIPT_SCHEMA_VERSION,
  TranscriptEntrySchema,
  TranscriptTurnSchema,
  parseAgentTranscript,
  serializeTranscript,
} from "./transcript.ts";
export type {
  AgentTranscript,
  AgentTranscriptInput,
  TranscriptEntry,
  TranscriptParse,
  TranscriptTurn,
} from "./transcript.ts";

export type {
  AgentDispatchReply,
  AgentDispatchRequest,
  AgentDispatcher,
  AgentRequest,
  AgentRunStats,
  AgentRuntime,
  AgentRuntimeKind,
  AgentRuntimeMetadata,
  StructuredResult,
} from "./types.ts";

export { AgentUsageSchema, UsageLedger, ZERO_USAGE, addUsage, totalInputTokens } from "./usage.ts";
export type { AgentUsage } from "./usage.ts";
