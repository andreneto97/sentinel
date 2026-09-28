/**
 * Turning an agent's reply into a validated value.
 *
 * Agent output is untrusted input: it arrives as prose that may or may not
 * contain the document we asked for, and it is parsed here and validated
 * against a Zod schema before any other module sees it. The three extraction
 * strategies exist because models fence, un-fence and pad JSON inconsistently,
 * and a run that fails on a stray "Here is the result:" line is a run wasted.
 */

import type { z } from "zod";

/** Which shape the reply turned out to have. Recorded for the run log. */
export type JsonStrategy = "fenced" | "bare" | "brace-span";

/** Why a reply yielded no JSON value. */
export type JsonExtractionFailure =
  /** Nothing but whitespace came back. */
  | "empty"
  /** No `{`/`[` anywhere: the model answered in prose. */
  | "no-json"
  /** A document starts but never closes: the reply was cut off mid-answer. */
  | "unterminated"
  /** A document was found and is not valid JSON. */
  | "invalid-json";

/** The outcome of pulling a JSON value out of a reply. */
export type JsonExtraction =
  | {
      readonly ok: true;
      readonly value: unknown;
      /** The exact substring that parsed, kept so a failed schema check can quote it. */
      readonly text: string;
      readonly strategy: JsonStrategy;
    }
  | { readonly ok: false; readonly reason: JsonExtractionFailure; readonly detail: string };

/** Matches a closed markdown fence, with or without a language tag. */
const FENCE = /```(?:json5?|jsonc)?[ \t]*\r?\n([\s\S]*?)```/g;

/** Parses `text` as JSON, returning undefined rather than throwing. */
function tryParse(text: string): { value: unknown } | undefined {
  try {
    return { value: JSON.parse(text) as unknown };
  } catch {
    return undefined;
  }
}

/**
 * Index of the character closing the document that opens at `start`, or null
 * when it never closes. String-aware, so a brace inside a string literal — a
 * code snippet quoted back at us, for instance — does not move the depth.
 */
function spanEnd(text: string, start: number): number | null {
  const open = text[start];
  if (open !== "{" && open !== "[") return null;
  const close = open === "{" ? "}" : "]";
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let index = start; index < text.length; index += 1) {
    const char = text[index];
    if (char === undefined) break;
    if (inString) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') inString = true;
    else if (char === open) depth += 1;
    else if (char === close) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return null;
}

/** First index at or after `from` holding `{` or `[`, or -1. */
function nextOpener(text: string, from: number): number {
  for (let index = from; index < text.length; index += 1) {
    const char = text[index];
    if (char === "{" || char === "[") return index;
  }
  return -1;
}

/**
 * Pulls the JSON document out of a reply: a fenced block first, then the whole
 * body, then the first balanced brace span. An unbalanced span is reported as
 * `unterminated` rather than as bad JSON, because that is the signature of a
 * reply that hit the output limit — a different failure with a different cure.
 */
export function extractJson(reply: string): JsonExtraction {
  const body = reply.trim();
  if (body === "") return { ok: false, reason: "empty", detail: "the agent returned no text" };

  FENCE.lastIndex = 0;
  for (const match of body.matchAll(FENCE)) {
    const inner = match[1]?.trim();
    if (inner === undefined || inner === "") continue;
    const parsed = tryParse(inner);
    if (parsed !== undefined)
      return { ok: true, value: parsed.value, text: inner, strategy: "fenced" };
  }

  const whole = tryParse(body);
  if (whole !== undefined) return { ok: true, value: whole.value, text: body, strategy: "bare" };

  let cursor = nextOpener(body, 0);
  if (cursor === -1) {
    return { ok: false, reason: "no-json", detail: "the reply contains no JSON document" };
  }

  let sawUnterminated = false;
  while (cursor !== -1) {
    const end = spanEnd(body, cursor);
    if (end === null) {
      sawUnterminated = true;
      break;
    }
    const candidate = body.slice(cursor, end + 1);
    const parsed = tryParse(candidate);
    if (parsed !== undefined) {
      return { ok: true, value: parsed.value, text: candidate, strategy: "brace-span" };
    }
    cursor = nextOpener(body, cursor + 1);
  }

  if (sawUnterminated) {
    return {
      ok: false,
      reason: "unterminated",
      detail: "the JSON document opens but never closes: the reply was cut off",
    };
  }
  return { ok: false, reason: "invalid-json", detail: "the JSON document could not be parsed" };
}

/** How many issues a correction message names before it starts eliding. */
const MAX_REPORTED_ISSUES = 8;

/** Renders Zod issues as `path: message` lines a corrective re-prompt can quote. */
export function formatSchemaViolation(error: z.ZodError): string {
  const lines = error.issues.slice(0, MAX_REPORTED_ISSUES).map((issue) => {
    const path = issue.path.map((segment) => String(segment)).join(".");
    return `- ${path === "" ? "(root)" : path}: ${issue.message}`;
  });
  const hidden = error.issues.length - lines.length;
  if (hidden > 0) lines.push(`- ...and ${hidden} more issue${hidden === 1 ? "" : "s"}`);
  return lines.join("\n");
}

/** A parse that failed, already mapped onto the failure taxonomy. */
export interface StructuredFailure {
  readonly kind: "malformed-output" | "truncated-output";
  /** Names the violation precisely enough to put in a corrective re-prompt. */
  readonly detail: string;
}

/** Either the validated value or the reason it is not usable. */
export type StructuredParse<T> =
  | { readonly ok: true; readonly value: T; readonly strategy: JsonStrategy }
  | { readonly ok: false; readonly failure: StructuredFailure };

/** Extracts the JSON document from a reply and validates it against `schema`. */
export function parseStructured<S extends z.ZodType>(
  reply: string,
  schema: S,
): StructuredParse<z.infer<S>> {
  const extracted = extractJson(reply);
  if (!extracted.ok) {
    return {
      ok: false,
      failure: {
        kind: extracted.reason === "unterminated" ? "truncated-output" : "malformed-output",
        detail: extracted.detail,
      },
    };
  }

  const result = schema.safeParse(extracted.value);
  if (result.success) {
    return { ok: true, value: result.data as z.infer<S>, strategy: extracted.strategy };
  }
  return {
    ok: false,
    failure: {
      kind: "malformed-output",
      detail: `the JSON does not match the schema:\n${formatSchemaViolation(result.error)}`,
    },
  };
}
