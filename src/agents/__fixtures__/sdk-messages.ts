import type {
  ModelUsage,
  SDKAssistantMessage,
  SDKAssistantMessageError,
  SDKMessage,
  SDKResultMessage,
} from "@anthropic-ai/claude-agent-sdk";

/**
 * Builders for the SDK message shapes `claude-dispatcher.ts` reduces, so its
 * classification logic is exercised against the real union without spawning
 * the Claude Code process.
 */

const SESSION = "11111111-2222-4333-8444-555555555555";
let uuidCounter = 0;

/** The SDK types message uuids as `crypto.UUID`, which is this template literal. */
type MessageUuid = `${string}-${string}-${string}-${string}-${string}`;

/** A fresh message uuid. */
function nextUuid(): MessageUuid {
  uuidCounter += 1;
  return `00000000-0000-4000-8000-${String(uuidCounter).padStart(12, "0")}`;
}

/** Per-model usage totals as a real result message carries them. */
export function modelUsage(input: Partial<ModelUsage> = {}): ModelUsage {
  return {
    inputTokens: 0,
    outputTokens: 0,
    cacheReadInputTokens: 0,
    cacheCreationInputTokens: 0,
    webSearchRequests: 0,
    costUSD: 0,
    contextWindow: 200_000,
    maxOutputTokens: 32_000,
    ...input,
  };
}

/**
 * The main-loop `usage` blob. Its type is every `BetaUsage` field made
 * non-nullable — a dozen fields the dispatcher never reads — so the four that
 * matter are spelled out and the rest are filled in through one cast, which is
 * exactly what a test double is for.
 */
function usageBlob(input: {
  input_tokens: number;
  output_tokens: number;
  cache_read_input_tokens: number;
  cache_creation_input_tokens: number;
}): SDKResultMessage["usage"] {
  return {
    ...input,
    cache_creation: { ephemeral_1h_input_tokens: 0, ephemeral_5m_input_tokens: 0 },
    server_tool_use: { web_search_requests: 0 },
    service_tier: "standard",
  } as unknown as SDKResultMessage["usage"];
}

/** An assistant frame carrying one text block. */
export function assistantText(
  text: string,
  options: { model?: string; error?: SDKAssistantMessageError } = {},
): SDKAssistantMessage {
  return {
    type: "assistant",
    message: {
      id: "msg_test",
      type: "message",
      role: "assistant",
      model: options.model ?? "claude-opus-5-5",
      content: [{ type: "text", text, citations: null }],
      stop_reason: "end_turn",
      stop_sequence: null,
      usage: usageBlob({
        input_tokens: 0,
        output_tokens: 0,
        cache_read_input_tokens: 0,
        cache_creation_input_tokens: 0,
      }),
    } as unknown as SDKAssistantMessage["message"],
    parent_tool_use_id: null,
    ...(options.error === undefined ? {} : { error: options.error }),
    uuid: nextUuid(),
    session_id: SESSION,
  };
}

/** A successful result message; `result` holds the turn's final text. */
export function resultSuccess(
  text: string,
  options: { isError?: boolean; usage?: Partial<ModelUsage>; costUsd?: number } = {},
): SDKResultMessage {
  const per = modelUsage(options.usage ?? {});
  return {
    type: "result",
    subtype: "success",
    duration_ms: 1200,
    duration_api_ms: 1100,
    is_error: options.isError ?? false,
    num_turns: 1,
    result: text,
    stop_reason: "end_turn",
    total_cost_usd: options.costUsd ?? per.costUSD,
    usage: usageBlob({
      input_tokens: per.inputTokens,
      output_tokens: per.outputTokens,
      cache_read_input_tokens: per.cacheReadInputTokens,
      cache_creation_input_tokens: per.cacheCreationInputTokens,
    }),
    modelUsage: { "claude-opus-5-5": per },
    permission_denials: [],
    uuid: nextUuid(),
    session_id: SESSION,
  };
}

/** An error result message of the given subtype. */
export function resultError(
  subtype: Extract<SDKResultMessage, { errors: string[] }>["subtype"],
  errors: readonly string[] = [],
): SDKResultMessage {
  return {
    type: "result",
    subtype,
    duration_ms: 900,
    duration_api_ms: 800,
    is_error: true,
    num_turns: 1,
    stop_reason: null,
    total_cost_usd: 0,
    usage: usageBlob({
      input_tokens: 0,
      output_tokens: 0,
      cache_read_input_tokens: 0,
      cache_creation_input_tokens: 0,
    }),
    modelUsage: {},
    permission_denials: [],
    errors: [...errors],
    uuid: nextUuid(),
    session_id: SESSION,
  };
}

/** A rate-limit event; `rejected` is the subscription saying no. */
export function rateLimitEvent(status: "allowed" | "allowed_warning" | "rejected"): SDKMessage {
  return {
    type: "rate_limit_event",
    rate_limit_info: { status, rateLimitType: "five_hour" },
    uuid: nextUuid(),
    session_id: SESSION,
  };
}

/** The system frame emitted when the model refuses and no fallback runs. */
export function refusalMessage(content: string): SDKMessage {
  return {
    type: "system",
    subtype: "model_refusal_no_fallback",
    original_model: "claude-opus-5-5",
    request_id: null,
    content,
    uuid: nextUuid(),
    session_id: SESSION,
  };
}

/** Wraps messages in the async iterable `query()` returns. */
export function streamOf(messages: readonly SDKMessage[]): AsyncIterable<SDKMessage> {
  return {
    async *[Symbol.asyncIterator]() {
      for (const message of messages) yield message;
    },
  };
}
