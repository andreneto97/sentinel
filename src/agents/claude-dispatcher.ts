/**
 * The only module in Sentinel that talks to Claude.
 *
 * It runs on the user's **Claude subscription** through
 * `@anthropic-ai/claude-agent-sdk`: no API key, no `@anthropic-ai/sdk` client,
 * no `ANTHROPIC_API_KEY` path. `query()` spawns the bundled Claude Code
 * executable, which authenticates the way the user's CLI already does.
 *
 * ## The agent gets no tools
 *
 * `buildQueryOptions` disables every built-in tool (`tools: []`), grants
 * nothing (`allowedTools: []`), names the filesystem and shell tools again in
 * `disallowedTools`, refuses every MCP server, loads no settings, no skills
 * and no plugins, and answers no permission prompt (`permissionPrompts:
 * "none"` with `permissionMode: "dontAsk"`, which denies anything that is not
 * pre-approved — and nothing is). The code the agent reasons about arrives in
 * the prompt, extracted from disk by the inventory phase.
 *
 * This is not belt-and-braces for its own sake. The agent is given the code in
 * its prompt rather than tools to fetch it, so a finding cannot rest on
 * something the model could not read: a tool rooted at the wrong directory
 * fails every read silently, and a model that cannot read answers from whatever
 * is already in its context rather than saying so. An agent that cannot read is
 * an agent that cannot read the wrong thing.
 */

import {
  ORG_POLICY_LIMIT_PREFIXES,
  USAGE_LIMIT_ERROR_PREFIXES,
  query,
} from "@anthropic-ai/claude-agent-sdk";
import type {
  Options,
  SDKAssistantMessageError,
  SDKMessage,
  SDKResultMessage,
} from "@anthropic-ai/claude-agent-sdk";
import { type Logger, silentLogger } from "../ports/logger.ts";
import { AgentError, type AgentFailureKind } from "./errors.ts";
import { type AgentRuntimeOptions, createAgentRuntime } from "./runtime.ts";
import type {
  AgentDispatchReply,
  AgentDispatchRequest,
  AgentDispatcher,
  AgentRuntime,
} from "./types.ts";
import { type AgentUsage, ZERO_USAGE, addUsage } from "./usage.ts";

/**
 * The slice of the SDK's `query()` this dispatcher uses. Narrowed to an async
 * iterable so a test can hand it a generator of real-shaped messages without
 * spawning anything.
 */
export type QueryLike = (params: {
  prompt: string;
  options?: Options;
}) => AsyncIterable<SDKMessage>;

/**
 * Tool names denied by name as well as by the empty `tools` list. Belt and
 * braces: `tools: []` already removes them, and a future SDK that changes that
 * default would still find them here.
 */
export const DENIED_TOOLS: readonly string[] = [
  "Bash",
  "BashOutput",
  "Edit",
  "Glob",
  "Grep",
  "KillShell",
  "NotebookEdit",
  "Read",
  "Skill",
  "SlashCommand",
  "Task",
  "TodoWrite",
  "WebFetch",
  "WebSearch",
  "Write",
];

/**
 * Environment variables stripped from the subprocess unless the caller opts
 * back in. PLAN.md is explicit that AI phases run on the subscription at $0
 * per run; leaving a stray `ANTHROPIC_API_KEY` in the environment would
 * silently bill the user's API account instead, which is not a surprise a
 * dossier tool is allowed to spring.
 */
export const STRIPPED_ENV_VARS: readonly string[] = ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"];

/** Turns to allow. One round trip is the intent; the slack covers thinking continuations. */
const MAX_TURNS = 4;

/** Everything `createClaudeDispatcher` takes. */
export interface ClaudeDispatcherOptions {
  /** Pin a model, e.g. `claude-sonnet-5`. Unset uses the CLI's default. */
  readonly model?: string | undefined;
  /** Working directory of the spawned process. Irrelevant to the agent: it has no tools. */
  readonly cwd?: string | undefined;
  /** Keep `ANTHROPIC_API_KEY` in the subprocess environment. Off by default; see above. */
  readonly inheritApiKeyEnv?: boolean | undefined;
  /** Process environment to derive the subprocess environment from. Defaults to `process.env`. */
  readonly env?: Readonly<Record<string, string | undefined>> | undefined;
  /** Injected for tests; defaults to the SDK's `query`. */
  readonly query?: QueryLike | undefined;
  readonly logger?: Logger | undefined;
}

/** Builds the subprocess environment: inherited, minus the API-key path, plus our UA tag. */
export function buildEnv(
  source: Readonly<Record<string, string | undefined>>,
  inheritApiKeyEnv: boolean,
): Record<string, string | undefined> {
  const env: Record<string, string | undefined> = { ...source };
  if (!inheritApiKeyEnv) {
    for (const name of STRIPPED_ENV_VARS) delete env[name];
  }
  env.CLAUDE_AGENT_SDK_CLIENT_APP = "sentinel";
  return env;
}

/**
 * The options every dispatch runs with. Exported so a test can assert the
 * agent is toolless without spawning a process — the guarantee this module
 * exists to make is worth asserting on.
 */
export function buildQueryOptions(input: {
  readonly systemPrompt: string;
  readonly model?: string | undefined;
  readonly cwd?: string | undefined;
  readonly abortController: AbortController;
  readonly env: Record<string, string | undefined>;
  readonly onStderr?: ((data: string) => void) | undefined;
}): Options {
  return {
    systemPrompt: { type: "custom", prompt: input.systemPrompt, snapshot: true },
    // No tools at all. The prompt carries the code.
    tools: [],
    allowedTools: [],
    disallowedTools: [...DENIED_TOOLS],
    mcpServers: {},
    strictMcpConfig: true,
    skills: [],
    plugins: [],
    // SDK isolation mode: no ~/.claude settings, no project settings, no CLAUDE.md.
    settingSources: [],
    permissionMode: "dontAsk",
    permissionPrompts: "none",
    maxTurns: MAX_TURNS,
    persistSession: false,
    includePartialMessages: false,
    // The prompt is assembled from repository source, not typed by a user:
    // `@path` mentions and leading slashes in it are code, not commands.
    verbatimPrompts: true,
    abortController: input.abortController,
    env: input.env,
    ...(input.model === undefined ? {} : { model: input.model }),
    ...(input.cwd === undefined ? {} : { cwd: input.cwd }),
    ...(input.onStderr === undefined ? {} : { stderr: input.onStderr }),
  };
}

/** True when `text` starts with one of the SDK's "a limit was genuinely reached" messages. */
export function isUsageLimitText(text: string): boolean {
  const body = text.trimStart();
  const prefixes: readonly string[] = [...USAGE_LIMIT_ERROR_PREFIXES, ...ORG_POLICY_LIMIT_PREFIXES];
  return prefixes.some((prefix) => body.startsWith(prefix));
}

/**
 * Maps an error text onto the failure taxonomy. The SDK's own prefix list is
 * authoritative for "the subscription is spent"; the regexes below only cover
 * what reaches us as free prose.
 */
export function classifyErrorText(text: string): AgentFailureKind {
  if (isUsageLimitText(text)) return "quota";
  if (/usage limit|out of usage|credit balance|insufficient credit/i.test(text)) return "quota";
  if (/\btimed? ?out\b|ETIMEDOUT|deadline exceeded/i.test(text)) return "timeout";
  if (/\brefus(al|ed)\b|declined to respond/i.test(text)) return "refusal";
  if (/max_output_tokens|output token limit/i.test(text)) return "truncated-output";
  return "transient";
}

/**
 * Maps the SDK's assistant-level error code onto the taxonomy.
 *
 * Judgement call: `rate_limit`, `billing_error`, `account_on_hold` and the
 * authentication codes all become `quota`. On a subscription run they mean the
 * same operational thing — the plan will not serve this request, and no number
 * of retries changes that — and folding them into one fatal kind is what makes
 * the phase stop and disclose instead of grinding through 200 batches. The
 * precise code is kept in the error's `detail`.
 */
export function classifyAssistantError(code: SDKAssistantMessageError): AgentFailureKind {
  switch (code) {
    case "rate_limit":
    case "billing_error":
    case "account_on_hold":
    case "authentication_failed":
    case "oauth_org_not_allowed":
    case "verification_required":
    case "cloud_credential_error":
      return "quota";
    case "max_output_tokens":
      return "truncated-output";
    case "overloaded":
    case "server_error":
      return "transient";
    case "invalid_request":
    case "model_not_found":
    case "unknown":
      return "transient";
    default:
      return "transient";
  }
}

/**
 * Usage for one dispatch, read once.
 *
 * `modelUsage` is the SDK's own documented field for token accounting and is
 * cumulative across the turns of a single `query()` call; each dispatch is one
 * such call, so reading the single result message is the whole story. `usage`
 * is main-loop only and is used only as a fallback.
 */
export function usageFromResult(result: SDKResultMessage): AgentUsage {
  const perModel = Object.values(result.modelUsage ?? {});
  if (perModel.length > 0) {
    const tokens = perModel.reduce<AgentUsage>(
      (total, entry) =>
        addUsage(total, {
          inputTokens: entry.inputTokens,
          outputTokens: entry.outputTokens,
          cacheReadInputTokens: entry.cacheReadInputTokens,
          cacheCreationInputTokens: entry.cacheCreationInputTokens,
          costUsd: 0,
        }),
      ZERO_USAGE,
    );
    return { ...tokens, costUsd: result.total_cost_usd };
  }
  const usage = result.usage;
  return {
    inputTokens: usage.input_tokens,
    outputTokens: usage.output_tokens,
    cacheReadInputTokens: usage.cache_read_input_tokens,
    cacheCreationInputTokens: usage.cache_creation_input_tokens,
    costUsd: result.total_cost_usd,
  };
}

/** What one message stream added up to. */
export interface ClaudeReplyDraft {
  /** Assistant text blocks, concatenated in arrival order. */
  text: string;
  result: SDKResultMessage | undefined;
  /** Set by a `model_refusal_no_fallback` system message. */
  refusal: string | undefined;
  /** Set by an assistant frame carrying an error code. */
  assistantError: SDKAssistantMessageError | undefined;
  /** Set by a `rate_limit_event` whose status is `rejected`. */
  rateLimitRejected: string | undefined;
  /** Model names seen on assistant frames. */
  model: string | undefined;
}

/** A fresh, empty draft. */
export function emptyDraft(): ClaudeReplyDraft {
  return {
    text: "",
    result: undefined,
    refusal: undefined,
    assistantError: undefined,
    rateLimitRejected: undefined,
    model: undefined,
  };
}

/** Concatenates the text blocks of an assistant message. */
function textOf(content: unknown): string {
  if (!Array.isArray(content)) return "";
  let out = "";
  for (const block of content) {
    if (typeof block !== "object" || block === null) continue;
    const typed = block as { type?: unknown; text?: unknown };
    if (typed.type === "text" && typeof typed.text === "string") out += typed.text;
  }
  return out;
}

/** Folds one SDK message into the draft. Pure, so the whole stream is testable. */
export function reduceMessage(draft: ClaudeReplyDraft, message: SDKMessage): ClaudeReplyDraft {
  if (message.type === "assistant") {
    // Subagent frames would carry a parent_tool_use_id; with no tools there
    // are none, but ignoring them keeps the text clean if that ever changes.
    if (message.parent_tool_use_id !== null) return draft;
    draft.text += textOf(message.message.content);
    if (message.error !== undefined) draft.assistantError = message.error;
    const model = (message.message as { model?: unknown }).model;
    if (typeof model === "string" && model !== "") draft.model = model;
    return draft;
  }
  if (message.type === "result") {
    draft.result = message;
    return draft;
  }
  if (message.type === "rate_limit_event") {
    if (message.rate_limit_info.status === "rejected") {
      draft.rateLimitRejected = `rate limit rejected (${message.rate_limit_info.rateLimitType ?? "unknown window"})`;
    }
    return draft;
  }
  if (message.type === "system" && message.subtype === "model_refusal_no_fallback") {
    draft.refusal = message.content;
    return draft;
  }
  return draft;
}

/** Either the reply text plus its usage, or the classified failure. */
export type ClaudeOutcome =
  | { readonly ok: true; readonly reply: AgentDispatchReply }
  | { readonly ok: false; readonly kind: AgentFailureKind; readonly detail: string };

/** Turns a completed draft into a dispatch outcome. */
export function finishDraft(draft: ClaudeReplyDraft): ClaudeOutcome {
  if (draft.rateLimitRejected !== undefined) {
    return { ok: false, kind: "quota", detail: draft.rateLimitRejected };
  }
  if (draft.refusal !== undefined) {
    return { ok: false, kind: "refusal", detail: draft.refusal };
  }
  if (draft.assistantError !== undefined) {
    return {
      ok: false,
      kind: classifyAssistantError(draft.assistantError),
      detail: `the model returned error "${draft.assistantError}"`,
    };
  }

  const result = draft.result;
  if (result === undefined) {
    return { ok: false, kind: "transient", detail: "the query ended without a result message" };
  }

  const usage = usageFromResult(result);
  const model = draft.model;

  if (result.subtype === "success") {
    if (result.is_error) {
      const text = result.result;
      return { ok: false, kind: classifyErrorText(text), detail: text.slice(0, 500) };
    }
    const text = result.result !== "" ? result.result : draft.text;
    if (text.trim() === "") {
      return { ok: false, kind: "malformed-output", detail: "the agent returned no text" };
    }
    return {
      ok: true,
      reply: { text, usage, ...(model === undefined ? {} : { model }) },
    };
  }

  const errors = result.errors.join("; ");
  switch (result.subtype) {
    case "error_max_turns":
      // The loop stopped before the model finished answering: what we have, if
      // anything, is a partial document.
      return { ok: false, kind: "truncated-output", detail: "the agent ran out of turns" };
    case "error_max_budget_usd":
      return { ok: false, kind: "quota", detail: "the per-query budget was exhausted" };
    case "error_max_structured_output_retries":
      return { ok: false, kind: "malformed-output", detail: "structured output never validated" };
    default:
      return {
        ok: false,
        kind: classifyErrorText(errors),
        detail: errors === "" ? "the query failed during execution" : errors.slice(0, 500),
      };
  }
}

/** Creates the subscription-backed dispatcher. */
export function createClaudeDispatcher(options: ClaudeDispatcherOptions = {}): AgentDispatcher {
  const logger = (options.logger ?? silentLogger).child({ transport: "claude-agent-sdk" });
  const run = options.query ?? (query as QueryLike);
  const env = buildEnv(options.env ?? process.env, options.inheritApiKeyEnv ?? false);

  return {
    kind: "claude-agent-sdk",
    ...(options.model === undefined ? {} : { model: options.model }),
    async dispatch(request: AgentDispatchRequest): Promise<AgentDispatchReply> {
      const controller = new AbortController();
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        controller.abort();
      }, request.timeoutMs);
      const onAbort = (): void => controller.abort();
      request.signal?.addEventListener("abort", onAbort, { once: true });

      const draft = emptyDraft();
      try {
        const stream = run({
          prompt: request.prompt,
          options: buildQueryOptions({
            systemPrompt: request.systemPrompt,
            model: options.model,
            cwd: options.cwd,
            abortController: controller,
            env,
            onStderr: (data: string) => logger.debug("claude stderr", { data: data.trimEnd() }),
          }),
        });
        for await (const message of stream) {
          reduceMessage(draft, message);
          // Single-prompt mode ends at the result; anything after it is
          // informational and would only keep the subprocess alive.
          if (draft.result !== undefined) break;
        }
      } catch (thrown) {
        const detail = thrown instanceof Error ? thrown.message : String(thrown);
        if (timedOut) {
          throw new AgentError("timeout", `no reply within ${request.timeoutMs}ms`, {
            batchId: request.batchId,
            attempt: request.attempt,
            cause: thrown,
          });
        }
        if (request.signal?.aborted === true) {
          throw new AgentError("timeout", "the run was cancelled", {
            batchId: request.batchId,
            attempt: request.attempt,
            retryable: false,
            cause: thrown,
          });
        }
        throw new AgentError(classifyErrorText(detail), detail, {
          batchId: request.batchId,
          attempt: request.attempt,
          cause: thrown,
        });
      } finally {
        clearTimeout(timer);
        request.signal?.removeEventListener("abort", onAbort);
      }

      const denials = draft.result?.permission_denials ?? [];
      if (denials.length > 0) {
        // Nothing should be reachable, so a denial means a tool leaked into
        // the agent's context. Loud, because it is the guarantee this module
        // exists to make.
        logger.error("the agent attempted a tool call; it should have none", {
          batchId: request.batchId,
          denied: denials.length,
        });
      }

      const outcome = finishDraft(draft);
      if (!outcome.ok) {
        throw new AgentError(outcome.kind, outcome.detail, {
          batchId: request.batchId,
          attempt: request.attempt,
        });
      }
      return outcome.reply;
    },
  };
}

/** Everything `createClaudeAgentRuntime` takes: the transport's knobs plus the runtime's. */
export interface ClaudeAgentRuntimeOptions
  extends ClaudeDispatcherOptions,
    Omit<AgentRuntimeOptions, "dispatcher" | "logger"> {
  readonly logger?: Logger | undefined;
}

/** The production runtime: subscription transport, pool of 2, transcripts under `raw/agents/`. */
export function createClaudeAgentRuntime(options: ClaudeAgentRuntimeOptions = {}): AgentRuntime {
  const { model, cwd, inheritApiKeyEnv, env, query: queryFn, ...runtimeOptions } = options;
  return createAgentRuntime({
    ...runtimeOptions,
    dispatcher: createClaudeDispatcher({
      ...(model === undefined ? {} : { model }),
      ...(cwd === undefined ? {} : { cwd }),
      ...(inheritApiKeyEnv === undefined ? {} : { inheritApiKeyEnv }),
      ...(env === undefined ? {} : { env }),
      ...(queryFn === undefined ? {} : { query: queryFn }),
      ...(options.logger === undefined ? {} : { logger: options.logger }),
    }),
    synthetic: false,
  });
}
