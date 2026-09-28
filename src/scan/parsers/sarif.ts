/**
 * SARIF 2.1.0 reader, shared by every analyzer Sentinel runs in SARIF mode.
 *
 * It is deliberately generic — `runs[].results[]`, the rule metadata in
 * `runs[].tool.driver.rules`, and the self-reported errors in
 * `runs[].invocations[]` — because gitleaks and opengrep disagree about almost
 * everything else. Tool output is untrusted input: nothing here throws, and a
 * payload that does not parse comes back as a reason string the caller turns
 * into a failed scan step.
 */

import { z } from "zod";
import type { Severity } from "../../contracts/findings.ts";

/** The four levels SARIF defines for a result. */
export type SarifLevel = "error" | "warning" | "note" | "none";

/** SARIF's own default when neither the result nor its rule states a level. */
const DEFAULT_LEVEL: SarifLevel = "warning";

const LEVELS: readonly string[] = ["error", "warning", "note", "none"];

/** Narrows a raw `level` string to a SARIF level, or null when it is not one. */
function toLevel(value: string | undefined): SarifLevel | null {
  if (value === undefined) return null;
  const lower = value.toLowerCase();
  return LEVELS.includes(lower) ? (lower as SarifLevel) : null;
}

// --- Schemas -----------------------------------------------------------------
// Every object is loose: a SARIF producer may add fields, and dropping a whole
// report because of one unexpected key would lose real findings.

const MessageSchema = z.looseObject({ text: z.string().optional() });

const ArtifactLocationSchema = z.looseObject({
  uri: z.string().optional(),
  uriBaseId: z.string().optional(),
});

const RegionSchema = z.looseObject({
  startLine: z.number().optional(),
  startColumn: z.number().optional(),
  endLine: z.number().optional(),
  endColumn: z.number().optional(),
  snippet: MessageSchema.optional(),
});

const PhysicalLocationSchema = z.looseObject({
  artifactLocation: ArtifactLocationSchema.optional(),
  region: RegionSchema.optional(),
});

const LocationSchema = z.looseObject({
  physicalLocation: PhysicalLocationSchema.optional(),
});

const PropertiesSchema = z.looseObject({
  tags: z.array(z.string()).optional(),
});

const ReportingDescriptorSchema = z.looseObject({
  id: z.string(),
  name: z.string().optional(),
  shortDescription: MessageSchema.optional(),
  fullDescription: MessageSchema.optional(),
  defaultConfiguration: z.looseObject({ level: z.string().optional() }).optional(),
  properties: PropertiesSchema.optional(),
});

const ResultSchema = z.looseObject({
  ruleId: z.string().optional(),
  ruleIndex: z.number().optional(),
  rule: z.looseObject({ id: z.string().optional(), index: z.number().optional() }).optional(),
  level: z.string().optional(),
  message: MessageSchema.optional(),
  locations: z.array(LocationSchema).optional(),
  fingerprints: z.record(z.string(), z.string()).optional(),
  partialFingerprints: z.record(z.string(), z.string()).optional(),
  properties: PropertiesSchema.optional(),
});

const ToolComponentSchema = z.looseObject({
  name: z.string().optional(),
  version: z.string().optional(),
  semanticVersion: z.string().optional(),
  rules: z.array(ReportingDescriptorSchema).optional(),
});

const NotificationSchema = z.looseObject({
  level: z.string().optional(),
  message: MessageSchema.optional(),
});

const InvocationSchema = z.looseObject({
  executionSuccessful: z.boolean().optional(),
  toolExecutionNotifications: z.array(NotificationSchema).optional(),
  toolConfigurationNotifications: z.array(NotificationSchema).optional(),
});

const RunSchema = z.looseObject({
  tool: z
    .looseObject({
      driver: ToolComponentSchema.optional(),
      extensions: z.array(ToolComponentSchema).optional(),
    })
    .optional(),
  results: z.array(ResultSchema).optional(),
  invocations: z.array(InvocationSchema).optional(),
});

const SarifLogSchema = z.looseObject({
  version: z.string().optional(),
  runs: z.array(RunSchema).optional(),
});

// --- Views -------------------------------------------------------------------

/** One physical location of a result, with SARIF's optionality resolved. */
export interface SarifLocation {
  /** `artifactLocation.uri`, with a `file://` scheme stripped. Relative when the tool emitted it so. */
  readonly file: string;
  /** SARIF defaults an absent `startLine` to 1. */
  readonly startLine: number;
  readonly startColumn: number | null;
  readonly endLine: number | null;
  readonly endColumn: number | null;
  /**
   * The snippet the tool printed. Never put this in a finding — report snippets
   * are extracted from disk by `src/verify`. It is useful only as a relocation
   * anchor and for masking a secret's exact span.
   */
  readonly snippet: string | null;
}

/** A rule as the tool described it in `tool.driver.rules`. */
export interface SarifRule {
  readonly id: string;
  readonly name: string | null;
  readonly shortDescription: string | null;
  readonly fullDescription: string | null;
  /** From `defaultConfiguration.level`; applies when a result carries no level of its own. */
  readonly defaultLevel: SarifLevel | null;
  readonly tags: readonly string[];
}

/** A result joined to its rule, which is the unit every normaliser works from. */
export interface SarifFinding {
  /** The rule id, or `""` when the producer omitted it entirely. */
  readonly ruleId: string;
  /** The result's level, falling back to the rule's default and then to SARIF's. */
  readonly level: SarifLevel;
  readonly message: string;
  readonly locations: readonly SarifLocation[];
  /** `locations[0]`, or null for a result with no physical location. */
  readonly primary: SarifLocation | null;
  /** `fingerprints` and `partialFingerprints` merged; gitleaks hides the commit here. */
  readonly fingerprints: Readonly<Record<string, string>>;
  readonly rule: SarifRule | null;
  /** The rule's tags, which is where Sentinel's own rule pack carries its routing. */
  readonly tags: readonly string[];
}

/** One `runs[]` entry. */
export interface SarifRun {
  readonly toolName: string;
  readonly toolVersion: string | null;
  readonly findings: readonly SarifFinding[];
  /**
   * What the tool said went wrong while it ran: an unparseable rule file, a
   * rule that crashed. opengrep reports an invalid config here *and still exits
   * with an empty, successful-looking report*, so a caller that ignores this
   * would read a broken scan as a clean one.
   */
  readonly errors: readonly string[];
}

/** A SARIF document that parsed. */
export interface SarifParsed {
  readonly ok: true;
  readonly runs: readonly SarifRun[];
  /** Every run's findings, in document order. */
  readonly findings: readonly SarifFinding[];
  /** Every run's tool-reported errors, in document order. */
  readonly errors: readonly string[];
}

/** A SARIF document that did not parse, with a reason fit for a scan-step message. */
export interface SarifUnparsed {
  readonly ok: false;
  readonly error: string;
}

/** The outcome of reading a SARIF payload. */
export type SarifParseResult = SarifParsed | SarifUnparsed;

// --- Parsing -----------------------------------------------------------------

/** Strips the `file://` scheme some producers put on an artifact uri. */
function normaliseUri(uri: string): string {
  if (uri.startsWith("file://")) {
    const stripped = uri.slice("file://".length);
    return stripped.startsWith("/") ? stripped : `/${stripped}`;
  }
  return uri;
}

/** A positive integer, or null — SARIF line/column numbers are 1-based. */
function positive(value: number | undefined): number | null {
  return value === undefined || !Number.isInteger(value) || value < 1 ? null : value;
}

type RawLocation = z.infer<typeof LocationSchema>;
type RawResult = z.infer<typeof ResultSchema>;
type RawRule = z.infer<typeof ReportingDescriptorSchema>;
type RawRun = z.infer<typeof RunSchema>;

/** Projects one SARIF location, dropping the ones that point at no file. */
function readLocation(raw: RawLocation): SarifLocation | null {
  const physical = raw.physicalLocation;
  const uri = physical?.artifactLocation?.uri;
  if (uri === undefined || uri === "") return null;
  const region = physical?.region;
  const snippet = region?.snippet?.text;
  return {
    file: normaliseUri(uri),
    startLine: positive(region?.startLine) ?? 1,
    startColumn: positive(region?.startColumn),
    endLine: positive(region?.endLine),
    endColumn: positive(region?.endColumn),
    snippet: snippet === undefined || snippet === "" ? null : snippet,
  };
}

/** Projects one rule descriptor. */
function readRule(raw: RawRule): SarifRule {
  return {
    id: raw.id,
    name: raw.name ?? null,
    shortDescription: raw.shortDescription?.text ?? null,
    fullDescription: raw.fullDescription?.text ?? null,
    defaultLevel: toLevel(raw.defaultConfiguration?.level),
    tags: raw.properties?.tags ?? [],
  };
}

/** Collects the driver's and every extension's rules, by id and by index. */
function indexRules(run: RawRun): { byId: Map<string, SarifRule>; byIndex: SarifRule[] } {
  const byId = new Map<string, SarifRule>();
  const byIndex: SarifRule[] = [];
  const components = [run.tool?.driver, ...(run.tool?.extensions ?? [])];
  for (const component of components) {
    for (const raw of component?.rules ?? []) {
      const rule = readRule(raw);
      // First definition wins: the driver is listed before its extensions.
      if (!byId.has(rule.id)) byId.set(rule.id, rule);
      if (component === run.tool?.driver) byIndex.push(rule);
    }
  }
  return { byId, byIndex };
}

/** Projects one result, resolving its rule by id and then by index. */
function readResult(raw: RawResult, rules: ReturnType<typeof indexRules>): SarifFinding {
  const ruleId = raw.ruleId ?? raw.rule?.id ?? "";
  const index = raw.ruleIndex ?? raw.rule?.index;
  const rule =
    rules.byId.get(ruleId) ??
    (index !== undefined && Number.isInteger(index) && index >= 0
      ? (rules.byIndex[index] ?? null)
      : null);

  const locations: SarifLocation[] = [];
  for (const entry of raw.locations ?? []) {
    const location = readLocation(entry);
    if (location !== null) locations.push(location);
  }

  return {
    ruleId: ruleId === "" ? (rule?.id ?? "") : ruleId,
    level: toLevel(raw.level) ?? rule?.defaultLevel ?? DEFAULT_LEVEL,
    message: raw.message?.text ?? "",
    locations,
    primary: locations[0] ?? null,
    fingerprints: { ...(raw.partialFingerprints ?? {}), ...(raw.fingerprints ?? {}) },
    rule,
    tags: rule?.tags ?? [],
  };
}

/** Collects the error-level notifications a run reported about itself. */
function readErrors(run: RawRun): string[] {
  const errors: string[] = [];
  for (const invocation of run.invocations ?? []) {
    const notifications = [
      ...(invocation.toolExecutionNotifications ?? []),
      ...(invocation.toolConfigurationNotifications ?? []),
    ];
    for (const notification of notifications) {
      if (toLevel(notification.level) !== "error") continue;
      const text = notification.message?.text?.trim();
      if (text !== undefined && text !== "") errors.push(text);
    }
    if (invocation.executionSuccessful === false && notifications.length === 0) {
      errors.push("the tool reported the run as unsuccessful without saying why");
    }
  }
  return errors;
}

/** How much of a malformed payload to quote back in the failure reason. */
const ERROR_EXCERPT = 200;

/** Shortens a parser complaint so it fits in a one-line scan-step message. */
function excerpt(value: string): string {
  const flat = value.replace(/\s+/g, " ").trim();
  return flat.length <= ERROR_EXCERPT ? flat : `${flat.slice(0, ERROR_EXCERPT)}...`;
}

/**
 * Reads a SARIF payload into flat findings. Never throws: malformed JSON, a
 * payload that is not SARIF at all, or a truncated report all come back as
 * `{ ok: false, error }`.
 */
export function parseSarif(raw: string): SarifParseResult {
  if (raw.trim() === "") return { ok: false, error: "the report file is empty" };

  let document: unknown;
  try {
    document = JSON.parse(raw);
  } catch (error) {
    return {
      ok: false,
      error: `the report is not valid JSON: ${excerpt(error instanceof Error ? error.message : String(error))}`,
    };
  }

  const parsed = SarifLogSchema.safeParse(document);
  if (!parsed.success) {
    return { ok: false, error: `the report is not valid SARIF: ${excerpt(parsed.error.message)}` };
  }
  if (parsed.data.runs === undefined) {
    return { ok: false, error: "the report has no `runs` array, so it is not a SARIF log" };
  }

  const runs: SarifRun[] = [];
  const findings: SarifFinding[] = [];
  const errors: string[] = [];
  for (const raw of parsed.data.runs) {
    const rules = indexRules(raw);
    const driver = raw.tool?.driver;
    const runFindings = (raw.results ?? []).map((result) => readResult(result, rules));
    const runErrors = readErrors(raw);
    runs.push({
      toolName: driver?.name ?? "unknown",
      toolVersion: driver?.semanticVersion ?? driver?.version ?? null,
      findings: runFindings,
      errors: runErrors,
    });
    findings.push(...runFindings);
    errors.push(...runErrors);
  }
  return { ok: true, runs, findings, errors };
}

// --- Helpers shared by the SARIF-based runners -------------------------------

/**
 * Reads the value of a `prefix:value` tag, which is how Sentinel's opengrep pack
 * smuggles its routing metadata through SARIF: the converter keeps
 * `metadata.tags` and drops every other custom metadata key.
 */
export function tagValue(tags: readonly string[], prefix: string): string | null {
  const marker = `${prefix}:`;
  for (const tag of tags) {
    if (tag.startsWith(marker)) {
      const value = tag.slice(marker.length).trim();
      if (value !== "") return value;
    }
  }
  return null;
}

/** Default severity for a SARIF level, used when a rule declares none of its own. */
export function levelToSeverity(level: SarifLevel): Severity {
  switch (level) {
    case "error":
      return "high";
    case "warning":
      return "medium";
    case "note":
      return "low";
    case "none":
      return "info";
  }
}
