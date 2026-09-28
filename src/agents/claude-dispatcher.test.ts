import { describe, expect, test } from "bun:test";
import type { Options, SDKMessage } from "@anthropic-ai/claude-agent-sdk";
import { createMemoryLogger } from "../ports/logger.ts";
import {
  assistantText,
  rateLimitEvent,
  refusalMessage,
  resultError,
  resultSuccess,
  streamOf,
} from "./__fixtures__/sdk-messages.ts";
import {
  DENIED_TOOLS,
  STRIPPED_ENV_VARS,
  buildEnv,
  buildQueryOptions,
  classifyAssistantError,
  classifyErrorText,
  createClaudeDispatcher,
  emptyDraft,
  finishDraft,
  isUsageLimitText,
  reduceMessage,
  usageFromResult,
} from "./claude-dispatcher.ts";
import { AgentError } from "./errors.ts";
import type { AgentDispatchRequest } from "./types.ts";

const REQUEST: AgentDispatchRequest = {
  batchId: "appsec-routes-001",
  attempt: 1,
  systemPrompt: "You are Sentinel's auditor.",
  prompt: "## unit: route-001",
  timeoutMs: 5_000,
};

/** Folds a whole stream into a finished draft, the way `dispatch` does. */
function finish(messages: readonly SDKMessage[]) {
  const draft = emptyDraft();
  for (const message of messages) {
    reduceMessage(draft, message);
    if (draft.result !== undefined) break;
  }
  return finishDraft(draft);
}

describe("buildQueryOptions", () => {
  const options: Options = buildQueryOptions({
    systemPrompt: "system",
    abortController: new AbortController(),
    env: {},
  });

  test("grants the agent no tools at all", () => {
    // The guarantee this module exists to make: the prompt carries the code,
    // and the agent has no way to read anything else.
    expect(options.tools).toEqual([]);
    expect(options.allowedTools).toEqual([]);
    expect(options.disallowedTools).toEqual([...DENIED_TOOLS]);
    expect(options.disallowedTools).toContain("Read");
    expect(options.disallowedTools).toContain("Bash");
    expect(options.disallowedTools).toContain("Glob");
  });

  test("admits no MCP server, skill or plugin", () => {
    expect(options.mcpServers).toEqual({});
    expect(options.strictMcpConfig).toBe(true);
    expect(options.skills).toEqual([]);
    expect(options.plugins).toEqual([]);
  });

  test("answers no permission prompt, so anything not pre-approved is denied", () => {
    expect(options.permissionMode).toBe("dontAsk");
    expect(options.permissionPrompts).toBe("none");
  });

  test("loads no settings, so the target repo's CLAUDE.md cannot steer the audit", () => {
    expect(options.settingSources).toEqual([]);
  });

  test("sends the prompt verbatim, because it is source code and not a typed message", () => {
    expect(options.verbatimPrompts).toBe(true);
  });

  test("uses a custom system prompt rather than the Claude Code preset", () => {
    expect(options.systemPrompt).toEqual({ type: "custom", prompt: "system", snapshot: true });
  });

  test("omits the model when none is pinned and sets it when one is", () => {
    expect(options.model).toBeUndefined();
    const pinned = buildQueryOptions({
      systemPrompt: "system",
      model: "claude-sonnet-5",
      abortController: new AbortController(),
      env: {},
    });
    expect(pinned.model).toBe("claude-sonnet-5");
  });
});

describe("buildEnv", () => {
  test("strips the API-key path so a stray variable cannot bill the API account", () => {
    const env = buildEnv({ PATH: "/bin", ANTHROPIC_API_KEY: "sk-secret" }, false);
    for (const name of STRIPPED_ENV_VARS) expect(env[name]).toBeUndefined();
    expect(env.PATH).toBe("/bin");
    expect(env.CLAUDE_AGENT_SDK_CLIENT_APP).toBe("sentinel");
  });

  test("keeps it when the caller opts in", () => {
    expect(buildEnv({ ANTHROPIC_API_KEY: "sk-secret" }, true).ANTHROPIC_API_KEY).toBe("sk-secret");
  });
});

describe("classification", () => {
  test("recognises the SDK's own usage-limit messages", () => {
    expect(isUsageLimitText("You've reached your usage limit for Claude Code.")).toBe(true);
    expect(isUsageLimitText("You're out of usage credits")).toBe(true);
    expect(isUsageLimitText("This service is disabled for your org")).toBe(true);
    expect(isUsageLimitText("Something else went wrong")).toBe(false);
  });

  test("maps error prose onto the taxonomy", () => {
    expect(classifyErrorText("You've hit your five-hour limit")).toBe("quota");
    expect(classifyErrorText("request timed out after 60s")).toBe("timeout");
    expect(classifyErrorText("upstream connect error: 503")).toBe("transient");
    expect(classifyErrorText("the model declined to respond")).toBe("refusal");
    expect(classifyErrorText("stopped at max_output_tokens")).toBe("truncated-output");
  });

  test("treats every 'the plan will not serve this' code as quota", () => {
    expect(classifyAssistantError("rate_limit")).toBe("quota");
    expect(classifyAssistantError("billing_error")).toBe("quota");
    expect(classifyAssistantError("authentication_failed")).toBe("quota");
    expect(classifyAssistantError("max_output_tokens")).toBe("truncated-output");
    expect(classifyAssistantError("overloaded")).toBe("transient");
  });
});

describe("reduceMessage and finishDraft", () => {
  test("takes the final text and the usage from the result message", () => {
    const outcome = finish([
      assistantText('{"verdicts":[]}'),
      resultSuccess('{"verdicts":[]}', {
        usage: { inputTokens: 2, outputTokens: 300, cacheCreationInputTokens: 728 },
        costUsd: 0.0118,
      }),
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.reply.text).toBe('{"verdicts":[]}');
    expect(outcome.reply.model).toBe("claude-opus-5-5");
    expect(outcome.reply.usage).toEqual({
      inputTokens: 2,
      outputTokens: 300,
      cacheReadInputTokens: 0,
      cacheCreationInputTokens: 728,
      costUsd: 0.0118,
    });
  });

  test("falls back to the streamed assistant text when the result carries none", () => {
    const outcome = finish([assistantText("streamed body"), resultSuccess("")]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.reply.text).toBe("streamed body");
  });

  test("an empty turn is malformed output, not an empty success", () => {
    const outcome = finish([resultSuccess("")]);
    expect(outcome).toMatchObject({ ok: false, kind: "malformed-output" });
  });

  test("a rejected rate-limit event is quota, whatever the result says", () => {
    const outcome = finish([rateLimitEvent("rejected"), resultSuccess('{"ok":true}')]);
    expect(outcome).toMatchObject({ ok: false, kind: "quota" });
  });

  test("an allowed rate-limit event changes nothing", () => {
    const outcome = finish([rateLimitEvent("allowed_warning"), resultSuccess('{"ok":true}')]);
    expect(outcome.ok).toBe(true);
  });

  test("a model refusal is classified as a refusal", () => {
    const outcome = finish([refusalMessage("I can't help with that."), resultSuccess("")]);
    expect(outcome).toMatchObject({ ok: false, kind: "refusal" });
  });

  test("an assistant-level error wins over the result", () => {
    const outcome = finish([
      assistantText("", { error: "overloaded" }),
      resultSuccess("", { isError: true }),
    ]);
    expect(outcome).toMatchObject({ ok: false, kind: "transient" });
  });

  test("a success result flagged is_error is classified from its text", () => {
    const outcome = finish([resultSuccess("You've reached your usage limit.", { isError: true })]);
    expect(outcome).toMatchObject({ ok: false, kind: "quota" });
  });

  test("running out of turns means the answer is truncated", () => {
    expect(finish([resultError("error_max_turns")])).toMatchObject({
      ok: false,
      kind: "truncated-output",
    });
  });

  test("the per-query budget cap is a quota failure", () => {
    expect(finish([resultError("error_max_budget_usd")])).toMatchObject({
      ok: false,
      kind: "quota",
    });
  });

  test("an execution error is classified from the errors it carries", () => {
    expect(finish([resultError("error_during_execution", ["socket hang up"])])).toMatchObject({
      ok: false,
      kind: "transient",
    });
  });

  test("a stream that ends with no result message is transient", () => {
    expect(finish([assistantText("half an answer")])).toMatchObject({
      ok: false,
      kind: "transient",
    });
  });

  test("ignores subagent frames", () => {
    const sub = { ...assistantText("subagent noise"), parent_tool_use_id: "toolu_1" };
    const outcome = finish([sub, assistantText("real answer"), resultSuccess("")]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.reply.text).toBe("real answer");
  });
});

describe("usageFromResult", () => {
  test("prefers modelUsage and takes the cost from the result total", () => {
    const usage = usageFromResult(
      resultSuccess("x", { usage: { inputTokens: 7, outputTokens: 9 }, costUsd: 0.5 }),
    );
    expect(usage.inputTokens).toBe(7);
    expect(usage.outputTokens).toBe(9);
    expect(usage.costUsd).toBe(0.5);
  });

  test("falls back to the main-loop usage when modelUsage is empty", () => {
    const usage = usageFromResult(resultError("error_during_execution"));
    expect(usage).toEqual({
      inputTokens: 0,
      outputTokens: 0,
      cacheReadInputTokens: 0,
      cacheCreationInputTokens: 0,
      costUsd: 0,
    });
  });
});

describe("createClaudeDispatcher", () => {
  test("returns the reply and its usage for a healthy stream", async () => {
    const dispatcher = createClaudeDispatcher({
      env: {},
      query: () =>
        streamOf([
          assistantText('{"verdicts":[]}'),
          resultSuccess('{"verdicts":[]}', { usage: { outputTokens: 12 }, costUsd: 0.01 }),
        ]),
    });
    const reply = await dispatcher.dispatch(REQUEST);
    expect(reply.text).toBe('{"verdicts":[]}');
    expect(reply.usage.outputTokens).toBe(12);
    expect(dispatcher.kind).toBe("claude-agent-sdk");
  });

  test("passes the system prompt and the toolless options through to query", async () => {
    let seen: { prompt: string; options?: Options } | undefined;
    const dispatcher = createClaudeDispatcher({
      env: {},
      query: (params) => {
        seen = params;
        return streamOf([resultSuccess("{}")]);
      },
    });
    await dispatcher.dispatch(REQUEST);
    expect(seen?.prompt).toBe("## unit: route-001");
    expect(seen?.options?.tools).toEqual([]);
    expect(seen?.options?.systemPrompt).toMatchObject({ prompt: "You are Sentinel's auditor." });
  });

  test("stops reading the stream once the result arrives", async () => {
    let yielded = 0;
    const dispatcher = createClaudeDispatcher({
      env: {},
      query: () => ({
        async *[Symbol.asyncIterator]() {
          yielded += 1;
          yield resultSuccess("{}");
          yielded += 1;
          yield assistantText("trailing noise");
        },
      }),
    });
    await dispatcher.dispatch(REQUEST);
    expect(yielded).toBe(1);
  });

  test("turns a failure outcome into a classified AgentError", async () => {
    const dispatcher = createClaudeDispatcher({
      env: {},
      query: () => streamOf([resultSuccess("You've hit your limit.", { isError: true })]),
    });
    const error = await dispatcher.dispatch(REQUEST).catch((thrown: unknown) => thrown);
    expect(error).toBeInstanceOf(AgentError);
    expect((error as AgentError).kind).toBe("quota");
    expect((error as AgentError).batchId).toBe("appsec-routes-001");
  });

  test("classifies a thrown transport error rather than letting it escape raw", async () => {
    const dispatcher = createClaudeDispatcher({
      env: {},
      query: () => ({
        // biome-ignore lint/correctness/useYield: the generator throws before yielding.
        async *[Symbol.asyncIterator](): AsyncGenerator<SDKMessage> {
          throw new Error("socket hang up");
        },
      }),
    });
    const error = await dispatcher.dispatch(REQUEST).catch((thrown: unknown) => thrown);
    expect(error).toBeInstanceOf(AgentError);
    expect((error as AgentError).kind).toBe("transient");
  });

  test("reports a hung query as a timeout once its budget is spent", async () => {
    const dispatcher = createClaudeDispatcher({
      env: {},
      query: (params) => ({
        async *[Symbol.asyncIterator](): AsyncGenerator<SDKMessage> {
          await new Promise<void>((resolve) => {
            params.options?.abortController?.signal.addEventListener("abort", () => resolve(), {
              once: true,
            });
          });
          throw new Error("aborted");
        },
      }),
    });
    const error = await dispatcher
      .dispatch({ ...REQUEST, timeoutMs: 10 })
      .catch((thrown: unknown) => thrown);
    expect((error as AgentError).kind).toBe("timeout");
    expect((error as AgentError).detail).toContain("10ms");
  });

  test("shouts when the agent attempted a tool call, because it should have none", async () => {
    const { logger, records } = createMemoryLogger();
    const result = resultSuccess("{}");
    const withDenial: SDKMessage = {
      ...result,
      permission_denials: [
        { tool_name: "Read", tool_use_id: "toolu_1", tool_input: { file_path: "/etc/passwd" } },
      ],
    };
    const dispatcher = createClaudeDispatcher({
      env: {},
      logger,
      query: () => streamOf([withDenial]),
    });
    await dispatcher.dispatch(REQUEST);
    const line = records.find((record) => record.level === "error");
    expect(line?.message).toContain("attempted a tool call");
  });
});
