import { SCHEMA_VERSION } from "../contracts/findings.ts";
import type { ProposalAnswer, ScopeDecision, SentinelConfig } from "../contracts/proposal.ts";
import { SentinelConfigSchema } from "../contracts/proposal.ts";
import { answersFromDecision } from "./decide.ts";

/** The file in the target repo that remembers what was answered last time. */
export const SENTINEL_CONFIG_FILENAME = "sentinel.config.json";

/** A config with no memory: every proposal will be asked. */
export function emptySentinelConfig(): SentinelConfig {
  return SentinelConfigSchema.parse({ schemaVersion: SCHEMA_VERSION });
}

/** A parsed config plus anything that made Sentinel ignore part of the file. */
export interface ConfigParseResult {
  readonly config: SentinelConfig;
  /** Surfaced to the operator; a stale config must never fail a run silently. */
  readonly warnings: readonly string[];
}

/**
 * Parses `sentinel.config.json`. Unreadable or mismatched content degrades to
 * an empty config with a warning rather than throwing: the worst case is that
 * Sentinel asks again, which is the safe direction.
 */
export function parseSentinelConfig(raw: string): ConfigParseResult {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return {
      config: emptySentinelConfig(),
      warnings: [`${SENTINEL_CONFIG_FILENAME} is not valid JSON (${reason}); ignoring it.`],
    };
  }

  const version =
    typeof data === "object" && data !== null && "schemaVersion" in data
      ? (data as { schemaVersion: unknown }).schemaVersion
      : undefined;
  if (version !== undefined && version !== SCHEMA_VERSION) {
    return {
      config: emptySentinelConfig(),
      warnings: [
        `${SENTINEL_CONFIG_FILENAME} was written for schema ${String(version)}, this build ` +
          `speaks ${SCHEMA_VERSION}; every proposal will be asked again.`,
      ],
    };
  }

  const parsed = SentinelConfigSchema.safeParse(data);
  if (!parsed.success) {
    return {
      config: emptySentinelConfig(),
      warnings: [
        `${SENTINEL_CONFIG_FILENAME} does not match the expected shape (${parsed.error.issues.map((issue) => issue.path.join(".") || "root").join(", ")}); ignoring it.`,
      ],
    };
  }
  return { config: parsed.data, warnings: [] };
}

/** Folds a decision's answers into a config, so the next run does not re-ask. */
export function mergeDecisionIntoConfig(
  config: SentinelConfig,
  decision: ScopeDecision,
): SentinelConfig {
  const answers: Record<string, ProposalAnswer> = {
    ...config.answers,
    ...answersFromDecision(decision),
  };
  // Untouched proposals keep whatever the file already said; if it said
  // nothing, they stay absent and get asked again.
  return SentinelConfigSchema.parse({ ...config, answers });
}

/** Serialises a config for `util/atomic-write`, newline-terminated and stable. */
export function serializeSentinelConfig(config: SentinelConfig): string {
  const validated = SentinelConfigSchema.parse(config);
  const answers = Object.fromEntries(
    Object.entries(validated.answers).sort(([a], [b]) => a.localeCompare(b)),
  );
  return `${JSON.stringify({ ...validated, answers }, null, 2)}\n`;
}
