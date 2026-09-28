/**
 * The fixture repository's own validation helper, and its environment schema.
 *
 * Phase 0 records the file that validates the environment as the evidence for
 * `config-validation`, and the batching phase quotes it as the shared context so
 * the audit knows what this codebase means by "validated".
 */

/** The fields a request body may carry, and how each one is narrowed. */
export interface Narrowing {
  readonly field: string;
  readonly kind: "string" | "number" | "uuid";
}

/** Reads the environment, failing at startup rather than at the first request. */
export function readEnv(source: Record<string, string | undefined>): { databaseUrl: string } {
  const databaseUrl = source.DATABASE_URL;
  if (databaseUrl === undefined || databaseUrl === "") {
    throw new Error("DATABASE_URL is required");
  }
  return { databaseUrl };
}

/** Keeps only the declared fields, so nothing else can reach a write. */
export function narrow(
  body: Record<string, unknown>,
  fields: readonly Narrowing[],
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const field of fields) {
    const value = body[field.field];
    if (value === undefined) continue;
    if (field.kind === "number" && typeof value !== "number") continue;
    if (field.kind !== "number" && typeof value !== "string") continue;
    out[field.field] = value;
  }
  return out;
}
