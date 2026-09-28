import { z } from "zod";
import { DomainSchema, SCHEMA_VERSION } from "./findings.ts";

/** Whether the extra work described by a proposal runs. */
export const ProposalAnswerSchema = z.enum(["on", "off"]);
export type ProposalAnswer = z.infer<typeof ProposalAnswerSchema>;

/**
 * A proposal targets an analysis domain, or `scope` when accepting it changes
 * *what* gets analysed (an extra monorepo package) rather than which domain.
 */
export const ProposalDomainSchema = z.union([DomainSchema, z.literal("scope")]);
export type ProposalDomain = z.infer<typeof ProposalDomainSchema>;

/** What the profiler found, with the repo-relative paths that prove it. */
export const DetectionSchema = z.object({
  summary: z.string().min(1),
  /** Files or directories, repo-relative. Truncated to a readable sample. */
  evidence: z.array(z.string()).default([]),
  /** How many units of the detected thing exist, when countable. */
  count: z.number().int().nonnegative().optional(),
});
export type Detection = z.infer<typeof DetectionSchema>;

/** What accepting a proposal costs: wall clock, AI usage, and any external tool. */
export const ProposalCostSchema = z.object({
  estimatedSeconds: z.number().int().nonnegative(),
  usesAi: z.boolean(),
  /** External tool the work needs; a missing one becomes its own proposal. */
  requiresTool: z.string().optional(),
});
export type ProposalCost = z.infer<typeof ProposalCostSchema>;

/** One thing Sentinel noticed and will not check unless the operator says yes. */
export const ProposalSchema = z.object({
  /** Stable across runs so `sentinel.config.json` can remember the answer. */
  id: z.string().min(1),
  title: z.string().min(1),
  domain: ProposalDomainSchema,
  detected: DetectionSchema,
  /** What Sentinel would do if this is accepted. */
  wouldCheck: z.string().min(1),
  cost: ProposalCostSchema,
  /** What `--yes` would answer. An unanswered proposal is off regardless. */
  defaultAnswer: ProposalAnswerSchema,
  /** Short selectors `--include`/`--exclude` accept besides the full id. */
  aliases: z.array(z.string()).default([]),
  /** Machine-readable effect of accepting: `path`, `tool`, `language`… */
  attributes: z.record(z.string(), z.string()).default({}),
});
export type Proposal = z.infer<typeof ProposalSchema>;

/**
 * A check Sentinel deliberately does not run because the repo cannot trigger
 * it. Declared out loud so the report never reads as silent omission.
 */
export const NotApplicableSchema = z.object({
  id: z.string().min(1),
  domain: ProposalDomainSchema,
  category: z.string().min(1),
  reason: z.string().min(1),
  evidence: z.array(z.string()).default([]),
});
export type NotApplicable = z.infer<typeof NotApplicableSchema>;

/** Everything phase 0.5 produced before any answer is applied. */
export const ProposalSetSchema = z.object({
  proposals: z.array(ProposalSchema),
  notApplicable: z.array(NotApplicableSchema),
});
export type ProposalSet = z.infer<typeof ProposalSetSchema>;

/** `untouched` means offered and never answered — which counts as off. */
export const ProposalOutcomeSchema = z.enum(["accepted", "declined", "untouched"]);
export type ProposalOutcome = z.infer<typeof ProposalOutcomeSchema>;

/** Where an answer came from, so the report can attribute every decision. */
export const AnswerSourceSchema = z.enum(["flag", "config", "defaults", "unanswered"]);
export type AnswerSource = z.infer<typeof AnswerSourceSchema>;

/** A proposal plus the outcome it was given and where that outcome came from. */
export const DecidedProposalSchema = z.object({
  proposal: ProposalSchema,
  outcome: ProposalOutcomeSchema,
  source: AnswerSourceSchema,
});
export type DecidedProposal = z.infer<typeof DecidedProposalSchema>;

/** The resolved scope of a run: what is on, and every offer that did not make it. */
export const ScopeDecisionSchema = z.object({
  enabledDomains: z.array(DomainSchema),
  accepted: z.array(DecidedProposalSchema),
  declined: z.array(DecidedProposalSchema),
  /** Offered, never answered. Off, but visible in the report. */
  untouched: z.array(DecidedProposalSchema),
  notApplicable: z.array(NotApplicableSchema),
  /** `--include`/`--exclude` values that matched no proposal and no domain. */
  unknownSelectors: z.array(z.string()).default([]),
  /** Accepted work whose external tool is missing and not being installed. */
  blockedOnMissingTool: z
    .array(z.object({ proposalId: z.string().min(1), tool: z.string().min(1) }))
    .default([]),
  estimatedExtraSeconds: z.number().int().nonnegative(),
  usesAi: z.boolean(),
});
export type ScopeDecision = z.infer<typeof ScopeDecisionSchema>;

/** The `scope-proposal.json` artifact written into the run directory. */
export const ScopeProposalDocumentSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  runId: z.string().min(1),
  target: z.string().min(1),
  decision: ScopeDecisionSchema,
});
export type ScopeProposalDocument = z.infer<typeof ScopeProposalDocumentSchema>;

/** `sentinel.config.json` in the target repo: the answers a previous run got. */
export const SentinelConfigSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  /** Proposal id -> the answer given. Absent id means "ask again". */
  answers: z.record(z.string(), ProposalAnswerSchema).default({}),
  /** Domains forced on or off regardless of which proposals exist. */
  domains: z
    .object({
      include: z.array(DomainSchema).default([]),
      exclude: z.array(DomainSchema).default([]),
    })
    .default({ include: [], exclude: [] }),
});
export type SentinelConfig = z.infer<typeof SentinelConfigSchema>;
