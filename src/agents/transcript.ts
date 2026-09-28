/**
 * Recorded agent transcripts.
 *
 * Every downstream test — the audit phase, the dead-code verifier, the CLI
 * end-to-end run — replays one of these instead of reaching the network or the
 * user's subscription. A transcript is keyed by `batchId` and holds the turns
 * of that batch in order, so a test can script "malformed, then correct" or
 * "quota on the second batch" without faking the transport itself.
 *
 * `source` is an honesty flag, and it is load-bearing: a `handwritten`
 * transcript proves the wiring works and proves nothing whatsoever about what
 * a real model would say. Anything reporting on a replayed run has to repeat
 * that distinction rather than let a green test read as agent quality.
 */

import { z } from "zod";
import { AgentFailureKindSchema } from "./errors.ts";
import { AgentUsageSchema } from "./usage.ts";

/** Bumped when the transcript format changes incompatibly. */
export const TRANSCRIPT_SCHEMA_VERSION = "1.0";

/** One scripted turn: either a reply or a failure, never both. */
export const TranscriptTurnSchema = z
  .object({
    /** Exact text the transport returns. */
    reply: z.string().optional(),
    /** A scripted transport failure instead of a reply. */
    failure: z
      .object({
        kind: AgentFailureKindSchema,
        detail: z.string().default("scripted failure"),
      })
      .optional(),
    usage: AgentUsageSchema.optional(),
    /** Substrings the prompt for this turn must contain; a miss fails the replay loudly. */
    expectPromptContains: z.array(z.string()).default([]),
  })
  .refine((turn) => (turn.reply === undefined) !== (turn.failure === undefined), {
    message: "a turn carries exactly one of `reply` or `failure`",
  });
export type TranscriptTurn = z.infer<typeof TranscriptTurnSchema>;

/** Every turn recorded for one batch, in order. */
export const TranscriptEntrySchema = z.object({
  batchId: z.string().min(1),
  turns: z.array(TranscriptTurnSchema).min(1),
});
export type TranscriptEntry = z.infer<typeof TranscriptEntrySchema>;

/** A whole transcript file. */
export const AgentTranscriptSchema = z.object({
  schemaVersion: z.literal(TRANSCRIPT_SCHEMA_VERSION),
  /**
   * `recorded` — captured from a real dispatch against the subscription.
   * `handwritten` — written by hand to exercise a path. Never label a
   * handwritten transcript `recorded`; the distinction is the point.
   */
  source: z.enum(["recorded", "handwritten"]),
  recordedAt: z.string().optional(),
  model: z.string().optional(),
  note: z.string().optional(),
  entries: z.array(TranscriptEntrySchema),
});
export type AgentTranscript = z.infer<typeof AgentTranscriptSchema>;
/** What a caller may hand `serializeTranscript`, before defaults are filled in. */
export type AgentTranscriptInput = z.input<typeof AgentTranscriptSchema>;

/** Either the validated transcript or why the file is not one. */
export type TranscriptParse =
  | { readonly ok: true; readonly transcript: AgentTranscript }
  | { readonly ok: false; readonly reason: string };

/** Validates a transcript document. Transcript files are external input like any other. */
export function parseAgentTranscript(raw: string): TranscriptParse {
  let json: unknown;
  try {
    json = JSON.parse(raw) as unknown;
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? error.message : String(error) };
  }
  const result = AgentTranscriptSchema.safeParse(json);
  if (!result.success) {
    const issue = result.error.issues[0];
    const path = issue === undefined ? "" : issue.path.map(String).join(".");
    return {
      ok: false,
      reason: `${path === "" ? "(root)" : path}: ${issue?.message ?? "invalid"}`,
    };
  }
  return { ok: true, transcript: result.data };
}

/** Renders a transcript as the JSON that belongs under `__fixtures__/transcripts/`. */
export function serializeTranscript(transcript: AgentTranscriptInput): string {
  return `${JSON.stringify(AgentTranscriptSchema.parse(transcript), null, 2)}\n`;
}
