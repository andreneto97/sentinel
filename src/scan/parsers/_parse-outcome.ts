/**
 * The result type every phase 1 parser returns.
 *
 * Tool output is untrusted input: a parser validates it with Zod and reports a
 * failure as a value, so a malformed payload degrades the step that produced it
 * instead of unwinding the whole run.
 */

import type { ZodType } from "zod";

/** A parse that either produced a typed value or the reason it could not. */
export type ParseOutcome<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: string };

/** Wraps a successfully parsed value. */
export function parsed<T>(value: T): ParseOutcome<T> {
  return { ok: true, value };
}

/** Wraps the reason a payload was refused. */
export function unparseable<T>(error: string): ParseOutcome<T> {
  return { ok: false, error };
}

/** The first few Zod issues, rendered as `path: message`, for an error line. */
function describeIssues(issues: readonly { path: PropertyKey[]; message: string }[]): string {
  return issues
    .slice(0, 3)
    .map((issue) => {
      const path = issue.path.map((part) => String(part)).join(".");
      return path === "" ? issue.message : `${path}: ${issue.message}`;
    })
    .join("; ");
}

/**
 * Parses raw tool output as JSON and validates it against `schema`. Never
 * throws: a syntax error and a shape mismatch both come back as `ok: false`.
 */
export function parseJsonWith<T>(raw: string, schema: ZodType<T>, label: string): ParseOutcome<T> {
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch (cause) {
    const detail = cause instanceof Error ? cause.message : String(cause);
    return unparseable(`${label} did not produce valid JSON: ${detail}`);
  }
  const result = schema.safeParse(json);
  if (result.success) return parsed(result.data);
  return unparseable(
    `${label} produced an unexpected shape: ${describeIssues(result.error.issues)}`,
  );
}
