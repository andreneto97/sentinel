/**
 * Logging seam.
 *
 * Structured JSON lines on stderr, so stdout stays clean for machine-readable
 * CLI output (`doctor --json`, `analyze --propose-only`) and a run's log can be
 * piped into jq without parsing prose.
 */

import type { Clock } from "./clock.ts";
import { createSystemClock } from "./clock.ts";

/** Severity of a log line. */
export type LogLevel = "debug" | "info" | "warn" | "error";

/** Minimum level a logger emits; "silent" drops everything. */
export type LogThreshold = LogLevel | "silent";

/** Structured context attached to a log line. */
export type LogFields = Record<string, unknown>;

/** A captured log line, as the in-memory test logger records it. */
export interface LogRecord {
  readonly ts: string;
  readonly level: LogLevel;
  readonly message: string;
  readonly fields: LogFields;
}

/** The logging operations Sentinel needs. */
export interface Logger {
  debug(message: string, fields?: LogFields): void;
  info(message: string, fields?: LogFields): void;
  warn(message: string, fields?: LogFields): void;
  error(message: string, fields?: LogFields): void;
  /** Returns a logger that adds `fields` to every line, e.g. `{ phase: "scan" }`. */
  child(fields: LogFields): Logger;
  /** True when a line at this level would be emitted; guards expensive field building. */
  enabled(level: LogLevel): boolean;
}

/** Numeric ranking used for threshold comparison. */
const LEVEL_RANK: Readonly<Record<LogThreshold, number>> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
  silent: 100,
};

const LEVELS: readonly LogLevel[] = ["debug", "info", "warn", "error"];

/** Options for {@link createJsonLogger}. */
export interface JsonLoggerOptions {
  /** Minimum level to emit. Default "info". */
  readonly level?: LogThreshold;
  /** Where a finished line goes, newline included. Default: stderr. */
  readonly write?: (line: string) => void;
  /** Clock for timestamps; inject a FakeClock to get deterministic output. */
  readonly clock?: Clock;
  /** Fields merged into every line, before per-call fields. */
  readonly base?: LogFields;
}

/**
 * JSON.stringify replacer that survives what real log fields contain: Errors
 * (which serialise to `{}`), BigInt (which throws) and circular references.
 */
function createReplacer(): (key: string, value: unknown) => unknown {
  const seen = new WeakSet<object>();
  return function replace(_key: string, value: unknown): unknown {
    if (typeof value === "bigint") return value.toString();
    if (value instanceof Error) {
      return { name: value.name, message: value.message, stack: value.stack };
    }
    if (typeof value === "object" && value !== null) {
      if (seen.has(value)) return "[circular]";
      seen.add(value);
    }
    return value;
  };
}

/** Serialises a record to one JSON line; a logger must never throw at a call site. */
function formatLine(record: LogRecord): string {
  const payload = { ts: record.ts, level: record.level, msg: record.message, ...record.fields };
  try {
    return JSON.stringify(payload, createReplacer());
  } catch (error) {
    return JSON.stringify({
      ts: record.ts,
      level: record.level,
      msg: record.message,
      logError: error instanceof Error ? error.message : String(error),
    });
  }
}

/** Builds a Logger around an emit function, so every implementation shares level/child logic. */
function buildLogger(
  threshold: LogThreshold,
  base: LogFields,
  emit: (record: LogRecord) => void,
  clock: Clock,
): Logger {
  const isEnabled = (level: LogLevel): boolean => LEVEL_RANK[level] >= LEVEL_RANK[threshold];

  const log = (level: LogLevel, message: string, fields?: LogFields): void => {
    if (!isEnabled(level)) return;
    emit({
      ts: new Date(clock.now()).toISOString(),
      level,
      message,
      fields: { ...base, ...fields },
    });
  };

  return {
    debug: (message, fields) => log("debug", message, fields),
    info: (message, fields) => log("info", message, fields),
    warn: (message, fields) => log("warn", message, fields),
    error: (message, fields) => log("error", message, fields),
    child: (fields) => buildLogger(threshold, { ...base, ...fields }, emit, clock),
    enabled: isEnabled,
  };
}

/** Creates the real logger: one JSON object per line, on stderr. */
export function createJsonLogger(options: JsonLoggerOptions = {}): Logger {
  const write = options.write ?? ((line: string) => void process.stderr.write(`${line}\n`));
  return buildLogger(
    options.level ?? "info",
    options.base ?? {},
    (record) => write(formatLine(record)),
    options.clock ?? createSystemClock(),
  );
}

/** A logger that emits nothing; the default for tests and library use. */
export const silentLogger: Logger = buildLogger("silent", {}, () => undefined, createSystemClock());

/** Creates a logger that records lines in memory, for asserting on what was logged. */
export function createMemoryLogger(options: { level?: LogThreshold; clock?: Clock } = {}): {
  logger: Logger;
  records: LogRecord[];
} {
  const records: LogRecord[] = [];
  const logger = buildLogger(
    options.level ?? "debug",
    {},
    (record) => void records.push(record),
    options.clock ?? createSystemClock(),
  );
  return { logger, records };
}

/** Parses a threshold from user input (`--log-level`), falling back to a default. */
export function parseLogThreshold(value: string | undefined, fallback: LogThreshold): LogThreshold {
  if (value === undefined) return fallback;
  const candidate = value.toLowerCase();
  if (candidate === "silent") return "silent";
  const level = LEVELS.find((entry) => entry === candidate);
  return level ?? fallback;
}
