import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { MemoryRawLogFileSystem } from "./__fixtures__/memory-file-system.ts";
import {
  agentsRawDir,
  createRawLogSink,
  nullRawLogSink,
  renderPromptFile,
  safeBatchId,
  transcriptStem,
} from "./raw-log.ts";

const RUN_DIR = "/runs/20260922T120000-abcdef12";

describe("agentsRawDir", () => {
  test("sits beside every other analyzer's untouched output", () => {
    expect(agentsRawDir(RUN_DIR)).toBe(join(RUN_DIR, "raw", "agents"));
  });
});

describe("safeBatchId", () => {
  test("keeps a plain id untouched", () => {
    expect(safeBatchId("appsec-routes-001")).toBe("appsec-routes-001");
  });

  test("flattens a path-shaped id instead of writing into a missing directory", () => {
    expect(safeBatchId("routes/src/api/users.ts")).toBe("routes-src-api-users.ts");
  });

  test("never returns an empty name", () => {
    expect(safeBatchId("///")).toBe("batch");
  });

  test("caps the length so the path stays writable", () => {
    expect(safeBatchId("a".repeat(500))).toHaveLength(120);
  });
});

describe("transcriptStem", () => {
  test("the first attempt keeps the plain name the report cites", () => {
    expect(transcriptStem("routes-001", 1)).toBe("routes-001");
  });

  test("a retry is suffixed, so the corrective re-prompt does not erase its cause", () => {
    expect(transcriptStem("routes-001", 2)).toBe("routes-001.attempt-2");
    expect(transcriptStem("routes-001", 3)).toBe("routes-001.attempt-3");
  });
});

describe("createRawLogSink", () => {
  test("writes both halves of a dispatch under raw/agents", async () => {
    const fs = new MemoryRawLogFileSystem();
    const sink = createRawLogSink(fs, RUN_DIR);

    const promptPath = await sink.writePrompt("routes-001", 1, "prompt body");
    const replyPath = await sink.writeReply("routes-001", 1, "reply body");

    expect(promptPath).toBe(join(agentsRawDir(RUN_DIR), "routes-001.prompt.txt"));
    expect(replyPath).toBe(join(agentsRawDir(RUN_DIR), "routes-001.reply.txt"));
    expect(fs.files.get(promptPath ?? "")).toBe("prompt body\n");
    expect(fs.files.get(replyPath ?? "")).toBe("reply body\n");
  });

  test("creates the directory once, not once per write", async () => {
    const fs = new MemoryRawLogFileSystem();
    let made = 0;
    const counting = {
      writeFile: (path: string, data: string) => fs.writeFile(path, data),
      mkdirp: async (path: string) => {
        made += 1;
        await fs.mkdirp(path);
      },
    };
    const sink = createRawLogSink(counting, RUN_DIR);
    await sink.writePrompt("a", 1, "x");
    await sink.writeReply("a", 1, "y");
    await sink.writePrompt("b", 1, "z");
    expect(made).toBe(1);
  });

  test("does not double a trailing newline", async () => {
    const fs = new MemoryRawLogFileSystem();
    const sink = createRawLogSink(fs, RUN_DIR);
    const path = await sink.writeReply("routes-001", 1, "already ends\n");
    expect(fs.files.get(path ?? "")).toBe("already ends\n");
  });
});

describe("nullRawLogSink", () => {
  test("writes nothing and reports no path", async () => {
    expect(await nullRawLogSink.writePrompt("a", 1, "x")).toBeNull();
    expect(await nullRawLogSink.writeReply("a", 1, "x")).toBeNull();
  });
});

describe("renderPromptFile", () => {
  test("holds both halves, because neither alone explains the reply", () => {
    const text = renderPromptFile({
      batchId: "routes-001",
      attempt: 2,
      model: "claude-opus-5-5",
      systemPrompt: "You are Sentinel's auditor.",
      prompt: "## unit: route-001",
    });
    expect(text).toContain("batch:   routes-001");
    expect(text).toContain("attempt: 2");
    expect(text).toContain("model:   claude-opus-5-5");
    expect(text).toContain("--- system ---");
    expect(text).toContain("You are Sentinel's auditor.");
    expect(text).toContain("--- user ---");
    expect(text).toContain("## unit: route-001");
  });

  test("omits the model line when none is pinned", () => {
    const text = renderPromptFile({
      batchId: "b",
      attempt: 1,
      systemPrompt: "s",
      prompt: "p",
    });
    expect(text).not.toContain("model:");
  });
});
