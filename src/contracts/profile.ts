import { z } from "zod";
import { CodeRefSchema, ConfidenceSchema, SCHEMA_VERSION } from "./findings.ts";

/**
 * The closed vocabulary of facts phase 0 is allowed to state about a repository.
 *
 * A closed enum is deliberate: a detector that wants to say something new has to
 * add a kind here, which forces the downstream phases (and the scope proposal)
 * to acknowledge it instead of silently receiving free-form strings.
 */
export const FactKindSchema = z.enum([
  // Packaging, layout and language.
  "package-manager",
  "repo-layout",
  "workspace-package",
  "monorepo-tool",
  "language",
  "tsconfig",
  "module-system",
  "node-version",
  "build-tool",
  // Backend framework and where its routes live.
  "backend-framework",
  "next-router",
  "route-dir",
  // Data layer.
  "data-layer",
  "db-schema-file",
  "migrations-dir",
  "database-engine",
  // Authentication.
  "auth-provider",
  "auth-helper",
  "session-store",
  // Frontend presence.
  "frontend",
  // Serverless and async workloads.
  "serverless-platform",
  "serverless-manifest",
  "queue",
  "scheduler",
  "scheduled-job",
  // Delivery pipeline.
  "container",
  "ci",
  "iac",
  // Configuration surface.
  "env-file",
  "env-var",
  "config-validation",
]);
/** One of the facts phase 0 can prove; see `FactKindSchema`. */
export type FactKind = z.infer<typeof FactKindSchema>;

/**
 * A single proven fact about the target repository.
 *
 * `evidence` is non-empty by construction: downstream prompts quote these
 * pointers verbatim, so a fact nobody can check is worse than a missing one.
 * A fact is identified by `(kind, value)` — every proof of the same fact is
 * merged into one entry's `evidence`.
 */
export const DetectedFactSchema = z.object({
  kind: FactKindSchema,
  /** Normalised identifier, e.g. "prisma", "postgresql", "app/api". */
  value: z.string().min(1),
  /** Human-readable extra, e.g. a version range or a cron expression. */
  detail: z.string().optional(),
  confidence: ConfidenceSchema,
  evidence: z.array(CodeRefSchema).min(1),
});
/** A proven fact about the target repository. */
export type DetectedFact = z.infer<typeof DetectedFactSchema>;

/**
 * A kind that was looked for and not found — the honest counterpart of a fact.
 *
 * This is what lets Sentinel say "no frontend, so the frontend-role-gate checks
 * are not applicable" instead of quietly skipping them.
 */
export const AbsenceSchema = z.object({
  kind: FactKindSchema,
  /** What was inspected: dependency names, file paths, directory names. */
  searched: z.array(z.string()).default([]),
  note: z.string().optional(),
});
/** A kind that was probed and found absent. */
export type Absence = z.infer<typeof AbsenceSchema>;

/** How much of the repository the content scan actually read, so partial scans say so. */
export const ScanStatsSchema = z.object({
  filesSeen: z.number().int().nonnegative(),
  filesRead: z.number().int().nonnegative(),
  /** True when a cap stopped the scan before every candidate file was read. */
  truncated: z.boolean(),
});
/** Content-scan accounting for one profile run. */
export type ScanStats = z.infer<typeof ScanStatsSchema>;

/**
 * Which subtree the *analysis* covered, recorded on a profile that read all of it.
 *
 * Phase 0 always walks the whole repository, and has to: in a workspace layout
 * the `package.json`, the lockfile and the tsconfig that prove the stack sit
 * above `apps/api`, which has no manifest of its own. So the profile is a fact
 * about the repository — and this is the field that stops a reader concluding
 * the *run* was about the repository too.
 *
 * Absent on a whole-repository run. `paths` empty with the field present means
 * the same thing and is what a `--path .` writes.
 */
export const AnalysedSubtreeSchema = z.object({
  /** Repo-relative subtrees and globs the analysis covered; empty is everything. */
  paths: z.array(z.string()).default([]),
  /** Files the walk found inside those paths. */
  filesInScope: z.number().int().nonnegative(),
  /** Files the walk found in the whole repository. */
  filesTotal: z.number().int().nonnegative(),
});
/** Which subtree the analysis covered; see {@link AnalysedSubtreeSchema}. */
export type AnalysedSubtree = z.infer<typeof AnalysedSubtreeSchema>;

/** The phase 0 artifact: everything Sentinel proved about the stack, and what it could not. */
export const StackProfileSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  /** Absolute path of the profiled repository root. */
  target: z.string(),
  facts: z.array(DetectedFactSchema).default([]),
  absences: z.array(AbsenceSchema).default([]),
  /** Detection problems worth surfacing (unparseable manifest, several lockfiles…). */
  warnings: z.array(z.string()).default([]),
  scan: ScanStatsSchema,
  /** The subtree the run analysed; absent when it analysed the whole repository. */
  analysis: AnalysedSubtreeSchema.optional(),
});
/** The phase 0 artifact, written to `stack-profile.json`. */
export type StackProfile = z.infer<typeof StackProfileSchema>;
