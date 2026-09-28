/**
 * The audit trail for every AI dispatch.
 *
 * A dossier a client pays for has to be defensible months later, which means
 * the exact prompt an agent was given and the exact bytes it replied with are
 * artifacts of the run, not console noise. Everything lands under
 * `<runDir>/raw/agents/<batchId>.{prompt,reply}.txt`, next to the untouched
 * output of every other analyzer.
 */

import { join } from "node:path";

/** The slice of `src/ports/file-system.ts` this sink needs. */
export interface RawLogFileSystem {
  writeFile(path: string, data: string): Promise<void>;
  mkdirp(path: string): Promise<void>;
}

/** Where a dispatch's prompt and reply are written. */
export interface RawLogSink {
  /** Writes the prompt for one attempt; returns the path, or null when disabled. */
  writePrompt(batchId: string, attempt: number, content: string): Promise<string | null>;
  /** Writes the raw reply (or the failure text) for one attempt. */
  writeReply(batchId: string, attempt: number, content: string): Promise<string | null>;
}

/** Sub-directory of `raw/` holding the agent transcripts. */
export const AGENTS_RAW_DIR = "agents";

/** Absolute path of `<runDir>/raw/agents`. */
export function agentsRawDir(runDir: string): string {
  return join(runDir, "raw", AGENTS_RAW_DIR);
}

/**
 * Makes a batch id safe as a file name. Batch ids are built by Sentinel, not
 * by a model, but they carry paths (`routes/src-api-users-ts`), and a `/` in a
 * file name silently writes into a directory that does not exist.
 */
export function safeBatchId(batchId: string): string {
  const cleaned = batchId.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
  return cleaned === "" ? "batch" : cleaned.slice(0, 120);
}

/**
 * File stem for one attempt. Attempt 1 keeps the plain `<batchId>` stem, which
 * is the common case and the name the report cites; a retry is suffixed so a
 * corrective re-prompt does not overwrite the reply that caused it.
 */
export function transcriptStem(batchId: string, attempt: number): string {
  const base = safeBatchId(batchId);
  return attempt <= 1 ? base : `${base}.attempt-${attempt}`;
}

/** Writes prompts and replies under `<runDir>/raw/agents/`. */
export function createRawLogSink(fs: RawLogFileSystem, runDir: string): RawLogSink {
  const dir = agentsRawDir(runDir);
  let ensured: Promise<void> | undefined;

  const ensureDir = (): Promise<void> => {
    ensured ??= fs.mkdirp(dir);
    return ensured;
  };

  const write = async (stem: string, suffix: string, content: string): Promise<string> => {
    await ensureDir();
    const path = join(dir, `${stem}.${suffix}.txt`);
    await fs.writeFile(path, content.endsWith("\n") ? content : `${content}\n`);
    return path;
  };

  return {
    writePrompt: (batchId, attempt, content) =>
      write(transcriptStem(batchId, attempt), "prompt", content),
    writeReply: (batchId, attempt, content) =>
      write(transcriptStem(batchId, attempt), "reply", content),
  };
}

/** A sink that writes nothing; used by unit tests and by a run with no run directory. */
export const nullRawLogSink: RawLogSink = {
  writePrompt: async () => null,
  writeReply: async () => null,
};

/**
 * Renders the prompt file: the system prompt and the user prompt in one
 * document, because the pair is what produced the reply and reading either
 * alone misleads.
 */
export function renderPromptFile(input: {
  readonly batchId: string;
  readonly attempt: number;
  readonly model?: string | undefined;
  readonly systemPrompt: string;
  readonly prompt: string;
}): string {
  return [
    "=== sentinel agent prompt =========================================",
    `batch:   ${input.batchId}`,
    `attempt: ${input.attempt}`,
    ...(input.model === undefined ? [] : [`model:   ${input.model}`]),
    "",
    "--- system ------------------------------------------------------",
    input.systemPrompt,
    "",
    "--- user --------------------------------------------------------",
    input.prompt,
    "",
  ].join("\n");
}
