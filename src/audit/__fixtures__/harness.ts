/**
 * Test harness for the audit phase.
 *
 * Two properties make these tests worth having.
 *
 * **The code is real.** Reads go through the real filesystem port against
 * `__fixtures__/audit-target`, and the batches' slices are produced by the real
 * slicer (`src/inventory/slice.ts`) from those files. So a citation a scripted
 * verdict returns is verified against a file that exists, its snippet is
 * extracted from disk, and the slice gate is tested against the line ranges the
 * production slicer would actually have pasted into the prompt — not against
 * ranges a test invented. Writes are captured in memory, so a test run leaves no
 * run directory behind.
 *
 * **No network, no subscription.** Every agent reply is replayed from a
 * handwritten transcript through `createFixtureRuntime`, which is also the only
 * way to script "quota on the second batch" at all.
 *
 * `VerdictBatchSchema` here is a **stand-in** for the one `src/audit/verdict.ts`
 * owns. It exists so this phase can be tested against its own documented
 * contract before the real schema lands; when it lands, it plugs into the same
 * {@link VerdictSource} slot and this stand-in stays as the contract's
 * executable statement.
 */

import { join } from "node:path";
import { z } from "zod";
import {
  type AgentTranscript,
  AgentTranscriptSchema,
  type FixtureRuntime,
  createFixtureRuntime,
} from "../../agents/index.ts";
import {
  type AuditUnit,
  ConfidenceSchema,
  type Domain,
  DomainSchema,
  SeveritySchema,
} from "../../contracts/findings.ts";
import { ATTRIBUTE, type AuditUnitKind } from "../../contracts/inventory.ts";
import { unitId } from "../../inventory/_unit-support.ts";
import {
  type CodeSlice,
  type SourceCache,
  createSourceCache,
  sliceCode,
} from "../../inventory/slice.ts";
import { type FileSystem, createFileSystem } from "../../ports/file-system.ts";
import { type Logger, silentLogger } from "../../ports/logger.ts";
import type {
  AuditBatch,
  AuditContext,
  AuditPrompt,
  BatchVerdicts,
  VerdictSource,
} from "../audit.ts";

/** Absolute path of the fixture repository these tests audit. */
export const FIXTURE_TARGET = join(import.meta.dir, "audit-target");

/** Where a fixture run pretends to write; nothing reaches this path. */
export const FIXTURE_RUN_DIR = "/tmp/sentinel-audit-fixture/20240101T000000-0000abcd";

/** A run id shaped like the real ones, so the documents look like real documents. */
export const FIXTURE_RUN_ID = "20240101T000000-0000abcd";

/** Repo-relative path of the clean handler. */
export const ORDERS_FILE = "src/api/orders.ts";

/** Repo-relative path of the handler with the IDOR. */
export const INVOICES_FILE = "src/api/invoices.ts";

/** Repo-relative path of the file no batch ever slices. */
export const LEGACY_FILE = "src/legacy/exports.ts";

/** A filesystem that reads the real fixtures and remembers what was written. */
export interface RecordingFileSystem extends FileSystem {
  readonly written: Map<string, string>;
}

/** Builds a filesystem whose reads are real and whose writes go nowhere. */
export function recordingFileSystem(): RecordingFileSystem {
  const real = createFileSystem();
  const written = new Map<string, string>();
  return {
    ...real,
    written,
    async writeFile(path: string, data: string | Uint8Array): Promise<void> {
      written.set(path, typeof data === "string" ? data : new TextDecoder().decode(data));
    },
    async mkdirp(): Promise<void> {
      // Writes are captured, so there is nothing to create.
    },
    async exists(path: string): Promise<boolean> {
      if (written.has(path)) return true;
      return await real.exists(path);
    },
    async readFile(path: string): Promise<string> {
      const captured = written.get(path);
      return captured ?? (await real.readFile(path));
    },
  };
}

/** Everything a test may want to swap out of the context. */
export interface FixtureContextOverrides {
  readonly fs?: RecordingFileSystem;
  readonly targetDir?: string;
  readonly logger?: Logger;
  readonly signal?: AbortSignal;
}

/** Builds an `AuditContext` pointed at the fixture repository. */
export function auditContext(overrides: FixtureContextOverrides = {}): AuditContext & {
  readonly fs: RecordingFileSystem;
} {
  return {
    fs: overrides.fs ?? recordingFileSystem(),
    targetDir: overrides.targetDir ?? FIXTURE_TARGET,
    runDir: FIXTURE_RUN_DIR,
    runId: FIXTURE_RUN_ID,
    logger: overrides.logger ?? silentLogger,
    ...(overrides.signal === undefined ? {} : { signal: overrides.signal }),
  };
}

/**
 * The 1-based line of the first fixture line containing `needle`.
 *
 * Tests cite lines by what the code says rather than by a hardcoded number, so
 * editing a fixture cannot silently turn an in-slice citation into an
 * out-of-slice one.
 */
export async function lineOf(file: string, needle: string): Promise<number> {
  const text = await createFileSystem().readFile(join(FIXTURE_TARGET, file));
  const lines = text.split("\n");
  const index = lines.findIndex((line) => line.includes(needle));
  if (index < 0)
    throw new Error(`fixture ${file} has no line containing ${JSON.stringify(needle)}`);
  return index + 1;
}

/** Builds a route unit the way the inventory would, id included. */
export function routeUnit(input: {
  readonly file: string;
  readonly symbol: string;
  readonly label: string;
  readonly line: number;
  readonly endLine?: number | undefined;
  readonly kind?: AuditUnitKind | undefined;
  readonly attributes?: Readonly<Record<string, string>> | undefined;
}): AuditUnit {
  const kind = input.kind ?? "route";
  return {
    id: unitId(kind, input.file, input.symbol),
    kind,
    label: input.label,
    location: {
      file: input.file,
      line: input.line,
      ...(input.endLine === undefined ? {} : { endLine: input.endLine }),
    },
    attributes: {
      [ATTRIBUTE.symbol]: input.symbol,
      ...(input.attributes ?? {}),
    },
  };
}

/** The clean handler, as a unit. */
export async function cleanUnit(): Promise<AuditUnit> {
  return routeUnit({
    file: ORDERS_FILE,
    symbol: "cancelOrder",
    label: "POST /api/orders/:id/cancel",
    line: await lineOf(ORDERS_FILE, "export async function cancelOrder"),
    attributes: { [ATTRIBUTE.method]: "POST", [ATTRIBUTE.path]: "/api/orders/:id/cancel" },
  });
}

/** The handler with the IDOR, as a unit. */
export async function brokenUnit(): Promise<AuditUnit> {
  return routeUnit({
    file: INVOICES_FILE,
    symbol: "voidInvoice",
    label: "POST /api/invoices/:id/void",
    line: await lineOf(INVOICES_FILE, "export async function voidInvoice"),
    attributes: { [ATTRIBUTE.method]: "POST", [ATTRIBUTE.path]: "/api/invoices/:id/void" },
  });
}

/**
 * Builds a batch whose slices come from the real slicer.
 *
 * This is the part of the harness that matters most: `sliceCode` is what
 * production uses to turn a unit's citation into prompt text, so the extents the
 * slice gate is tested against are the extents the agent would really have been
 * shown.
 */
export async function realBatch(
  id: string,
  units: readonly AuditUnit[],
  domain: Domain = "appsec",
  cache: SourceCache = createSourceCache(),
): Promise<AuditBatch> {
  const slices: CodeSlice[] = [];
  for (const unit of units) {
    const sliced = await sliceCode(unit.location, {
      fs: createFileSystem(),
      targetDir: FIXTURE_TARGET,
      cache,
    });
    if (!sliced.ok) throw new Error(`fixture slice failed for ${unit.id}: ${sliced.detail}`);
    slices.push(sliced.slice);
  }
  // Kept so the prompt builder can paste the same text the gate measures.
  SLICE_TEXT.set(id, slices);
  return { id, domain, units: [...units], slices };
}

/** The rendered slices of every batch `realBatch` built, keyed by batch id. */
const SLICE_TEXT = new Map<string, readonly CodeSlice[]>();

// ---------------------------------------------------------------------------
// The verdict contract, as a schema
// ---------------------------------------------------------------------------

/** A citation as the agent writes it. */
export const VerdictRefSchema = z.object({
  file: z.string().min(1),
  line: z.number().int().positive(),
  endLine: z.number().int().positive().optional(),
  note: z.string().optional(),
  /** The line as the agent read it; an anchor for relocation, never rendered. */
  quote: z.string().optional(),
});

/** A check the agent asserts a unit passes. */
export const VerdictCheckSchema = z.object({
  id: z.string().min(1),
  statement: z.string().min(1),
  subject: z.string().optional(),
  evidence: z.array(VerdictRefSchema).default([]),
});

/** A problem the agent claims. */
export const VerdictFindingSchema = z.object({
  rule: z.string().min(1),
  severity: SeveritySchema,
  confidence: ConfidenceSchema,
  title: z.string().min(1),
  description: z.string().min(1),
  impact: z.string().min(1),
  recommendation: z.string().min(1),
  location: VerdictRefSchema,
  domain: DomainSchema.optional(),
  evidence: z.array(VerdictRefSchema).default([]),
  exploitability: z.string().optional(),
  acceptanceCriteria: z.array(z.string()).default([]),
  cwe: z.array(z.string()).default([]),
  owasp: z.array(z.string()).default([]),
});

/** The agent's answer about one unit. */
export const UnitVerdictSchema = z.object({
  unitId: z.string().min(1),
  status: z.enum(["clean", "flagged", "inconclusive"]),
  checks: z.array(VerdictCheckSchema).default([]),
  findings: z.array(VerdictFindingSchema).default([]),
  note: z.string().optional(),
});

/** A finding as a scripted reply carries it, before Zod fills in the defaults. */
export type ScriptedFinding = z.input<typeof VerdictFindingSchema>;

/** A unit verdict as a scripted reply carries it. */
export type ScriptedVerdict = z.input<typeof UnitVerdictSchema>;

/** Stand-in for `src/audit/verdict.ts#VerdictBatchSchema`. */
export const VerdictBatchSchema = z.object({
  batchId: z.string().optional(),
  verdicts: z.array(UnitVerdictSchema),
});

/**
 * The adapter the phase is wired with. The identity `read` is the case the real
 * schema is expected to hit; a divergence would be absorbed here and nowhere
 * else.
 */
export const verdictSource: VerdictSource<typeof VerdictBatchSchema> = {
  schema: VerdictBatchSchema,
  read: (value): BatchVerdicts => value,
};

// ---------------------------------------------------------------------------
// Prompts and transcripts
// ---------------------------------------------------------------------------

/** The system prompt the fixture phase sends; constant, like the real one. */
export const FIXTURE_SYSTEM_PROMPT =
  "You audit the code in this message. You have no filesystem. Cite only lines shown below.";

/**
 * A prompt builder that pastes the batch's slices, which is the whole contract
 * `src/audit/prompts/` has to satisfy: the code is in the message.
 */
export function fixturePrompt(batch: AuditBatch): AuditPrompt {
  const units = batch.units
    .map(
      (unit) =>
        `- ${unit.id} ${unit.kind} ${unit.label} (${unit.location.file}:${unit.location.line})`,
    )
    .join("\n");
  const slices = (SLICE_TEXT.get(batch.id) ?? []).map((slice) => slice.text).join("\n\n");
  return {
    system: FIXTURE_SYSTEM_PROMPT,
    user: [`## Units\n${units}`, `## Code\n${slices}`].join("\n\n"),
  };
}

/** Serialises a scripted reply the way a model would send it. */
export function replyOf(payload: z.input<typeof VerdictBatchSchema>): string {
  return JSON.stringify(payload);
}

/** One batch's scripted turns. */
export interface ScriptedBatch {
  readonly batchId: string;
  readonly turns: ReadonlyArray<{
    readonly reply?: string;
    readonly failure?: { readonly kind: string; readonly detail?: string };
    readonly expectPromptContains?: readonly string[];
  }>;
}

/** Builds a handwritten transcript; `source` is never anything else here. */
export function transcriptOf(entries: readonly ScriptedBatch[]): AgentTranscript {
  return AgentTranscriptSchema.parse({
    schemaVersion: "1.0",
    source: "handwritten",
    note: "Handwritten for the audit phase tests: a wiring guard, not agent-quality evidence.",
    entries: entries.map((entry) => ({ batchId: entry.batchId, turns: [...entry.turns] })),
  });
}

/** Knobs a test turns on the replay runtime. */
export interface FixtureRuntimeOverrides {
  /** Batches in flight at once. 1 makes the order batches fail in deterministic. */
  readonly concurrency?: number | undefined;
  /** Attempts per batch. 1 means a scripted failure needs only one turn. */
  readonly maxAttempts?: number | undefined;
}

/** Builds the replay runtime over a scripted transcript. */
export function fixtureRuntime(
  entries: readonly ScriptedBatch[],
  overrides: FixtureRuntimeOverrides = {},
): FixtureRuntime {
  return createFixtureRuntime({
    transcript: transcriptOf(entries),
    concurrency: overrides.concurrency ?? 2,
    maxAttempts: overrides.maxAttempts ?? 3,
    retryDelayMs: 0,
  });
}
