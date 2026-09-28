import type { Domain } from "../contracts/findings.ts";
import { DomainSchema, SCHEMA_VERSION } from "../contracts/findings.ts";
import type {
  DecidedProposal,
  Proposal,
  ProposalAnswer,
  ProposalSet,
  ScopeDecision,
  ScopeProposalDocument,
} from "../contracts/proposal.ts";
import { ScopeDecisionSchema, ScopeProposalDocumentSchema } from "../contracts/proposal.ts";
import { DEFAULT_DOMAINS, orderDomains } from "./policy.ts";

/** Domains forced on or off independently of any proposal. */
export interface DomainOverrides {
  readonly include?: readonly Domain[];
  readonly exclude?: readonly Domain[];
}

/** Everything that can answer a proposal, from any of the three input paths. */
export interface ScopeOptions {
  /** `--include` selectors: a proposal id, an alias, or a domain name. */
  readonly include?: readonly string[];
  /** `--exclude` selectors. Beats `--include` when both name the same thing. */
  readonly exclude?: readonly string[];
  /** `--yes`: answer every otherwise-unanswered proposal with its default. */
  readonly acceptDefaults?: boolean;
  /** Answers remembered by `sentinel.config.json` from a previous run. */
  readonly previousAnswers?: Readonly<Record<string, ProposalAnswer>>;
  readonly baseDomains?: readonly Domain[];
  readonly domainOverrides?: DomainOverrides;
  /** Tools `doctor` found, used to flag accepted work that cannot run. */
  readonly availableTools?: readonly string[];
}

const DOMAIN_NAMES: ReadonlySet<string> = new Set<string>(DomainSchema.options);

function normalizeSelector(selector: string): string {
  return selector.trim().toLowerCase().replace(/^-+/, "");
}

interface SelectorResolution {
  readonly proposalIds: ReadonlySet<string>;
  readonly domains: ReadonlySet<Domain>;
  readonly unknown: readonly string[];
}

/**
 * Maps `--include`/`--exclude` values onto proposals and domains. A selector
 * that matches nothing is reported rather than dropped, so a typo cannot
 * quietly turn into a skipped check.
 */
export function resolveSelectors(
  selectors: readonly string[],
  proposals: readonly Proposal[],
): SelectorResolution {
  const proposalIds = new Set<string>();
  const domains = new Set<Domain>();
  const unknown: string[] = [];

  for (const raw of selectors) {
    const selector = normalizeSelector(raw);
    if (selector === "") continue;
    let matched = false;

    if (DOMAIN_NAMES.has(selector)) {
      domains.add(selector as Domain);
      matched = true;
    }
    for (const proposal of proposals) {
      const aliases = proposal.aliases.map(normalizeSelector);
      const hit =
        normalizeSelector(proposal.id) === selector ||
        aliases.includes(selector) ||
        (proposal.domain !== "scope" && proposal.domain === selector);
      if (hit) {
        proposalIds.add(proposal.id);
        matched = true;
      }
    }
    if (!matched) unknown.push(raw.trim());
  }

  return { proposalIds, domains, unknown };
}

function decide(
  proposal: Proposal,
  options: ScopeOptions,
  included: ReadonlySet<string>,
  excluded: ReadonlySet<string>,
): DecidedProposal {
  // Flags beat the remembered answer; a remembered answer beats `--yes`.
  if (excluded.has(proposal.id)) return { proposal, outcome: "declined", source: "flag" };
  if (included.has(proposal.id)) return { proposal, outcome: "accepted", source: "flag" };

  const remembered = options.previousAnswers?.[proposal.id];
  if (remembered !== undefined) {
    return {
      proposal,
      outcome: remembered === "on" ? "accepted" : "declined",
      source: "config",
    };
  }

  if (options.acceptDefaults === true) {
    return {
      proposal,
      outcome: proposal.defaultAnswer === "on" ? "accepted" : "declined",
      source: "defaults",
    };
  }

  // Offered and never answered. Off — but the report has to say so.
  return { proposal, outcome: "untouched", source: "unanswered" };
}

/** Resolves proposals plus the three answer channels into the scope of a run. */
export function decideScope(set: ProposalSet, options: ScopeOptions = {}): ScopeDecision {
  const includeResolution = resolveSelectors(options.include ?? [], set.proposals);
  const excludeResolution = resolveSelectors(options.exclude ?? [], set.proposals);

  const decided = set.proposals.map((proposal) =>
    decide(proposal, options, includeResolution.proposalIds, excludeResolution.proposalIds),
  );

  const accepted = decided.filter((entry) => entry.outcome === "accepted");
  const declined = decided.filter((entry) => entry.outcome === "declined");
  const untouched = decided.filter((entry) => entry.outcome === "untouched");

  const enabled = new Set<Domain>(options.baseDomains ?? DEFAULT_DOMAINS);
  for (const entry of accepted) {
    if (entry.proposal.domain !== "scope") enabled.add(entry.proposal.domain);
  }
  for (const domain of includeResolution.domains) enabled.add(domain);
  for (const domain of options.domainOverrides?.include ?? []) enabled.add(domain);
  for (const domain of options.domainOverrides?.exclude ?? []) enabled.delete(domain);
  // Excluding a domain on the command line is the last word on it.
  for (const domain of excludeResolution.domains) enabled.delete(domain);

  const tools = new Set(options.availableTools ?? []);
  for (const entry of accepted) {
    const installs = entry.proposal.attributes.tool;
    if (installs !== undefined) tools.add(installs);
  }
  const blockedOnMissingTool = accepted.flatMap((entry) => {
    const tool = entry.proposal.cost.requiresTool;
    if (tool === undefined || tools.has(tool)) return [];
    return [{ proposalId: entry.proposal.id, tool }];
  });

  const estimatedExtraSeconds = accepted.reduce(
    (total, entry) => total + entry.proposal.cost.estimatedSeconds,
    0,
  );

  return ScopeDecisionSchema.parse({
    enabledDomains: orderDomains(enabled),
    accepted,
    declined,
    untouched,
    notApplicable: set.notApplicable,
    unknownSelectors: [...includeResolution.unknown, ...excludeResolution.unknown],
    blockedOnMissingTool,
    estimatedExtraSeconds,
    usesAi: accepted.some((entry) => entry.proposal.cost.usesAi),
  });
}

/**
 * The answers worth remembering. Untouched proposals are deliberately absent:
 * an unanswered question must be asked again next run.
 */
export function answersFromDecision(decision: ScopeDecision): Record<string, ProposalAnswer> {
  const answers: Record<string, ProposalAnswer> = {};
  for (const entry of decision.accepted) answers[entry.proposal.id] = "on";
  for (const entry of decision.declined) answers[entry.proposal.id] = "off";
  return answers;
}

/** Wraps a decision into the validated `scope-proposal.json` artifact. */
export function buildScopeProposalDocument(input: {
  runId: string;
  target: string;
  decision: ScopeDecision;
}): ScopeProposalDocument {
  return ScopeProposalDocumentSchema.parse({
    schemaVersion: SCHEMA_VERSION,
    runId: input.runId,
    target: input.target,
    decision: input.decision,
  });
}
