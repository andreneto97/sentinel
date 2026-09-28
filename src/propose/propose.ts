import type { Domain } from "../contracts/findings.ts";
import type { Proposal, ProposalSet } from "../contracts/proposal.ts";
import { ProposalSetSchema } from "../contracts/proposal.ts";
import type { ProposalContext, ProposalGenerator } from "./generators.ts";
import { ALL_GENERATORS } from "./generators.ts";
import { DEFAULT_DOMAINS, DOMAIN_ORDER } from "./policy.ts";
import type { ProfileView } from "./stack-profile-adapter.ts";

/** Caller-supplied parts of a proposal context; the rest has sane defaults. */
export interface ProposalContextInput {
  readonly profile: ProfileView;
  readonly baseDomains?: readonly Domain[];
  readonly availableTools?: readonly string[];
  readonly scopedCategories?: readonly string[];
  readonly analysedPath?: string;
}

/** Builds the context the generators read, filling in the default scope. */
export function createProposalContext(input: ProposalContextInput): ProposalContext {
  return {
    profile: input.profile,
    baseDomains: new Set(input.baseDomains ?? DEFAULT_DOMAINS),
    availableTools: new Set(input.availableTools ?? []),
    scopedCategories: new Set(input.scopedCategories ?? []),
    analysedPath: input.analysedPath ?? ".",
  };
}

/** Rank used to order proposals; `scope` sorts last because it is the biggest ask. */
function domainRank(domain: Proposal["domain"]): number {
  if (domain === "scope") return DOMAIN_ORDER.length;
  return DOMAIN_ORDER.indexOf(domain);
}

/**
 * Runs every generator and returns the deduplicated, deterministically ordered
 * gap between what the repo contains and what the current scope will check.
 */
export function proposeScope(
  ctx: ProposalContext,
  generators: readonly ProposalGenerator[] = ALL_GENERATORS,
): ProposalSet {
  const proposals = new Map<string, Proposal>();
  const notApplicable = new Map<string, ProposalSet["notApplicable"][number]>();

  for (const generate of generators) {
    const result = generate(ctx);
    for (const proposal of result.proposals) {
      // First generator to claim an id wins; ALL_GENERATORS is ordered.
      if (!proposals.has(proposal.id)) proposals.set(proposal.id, proposal);
    }
    for (const entry of result.notApplicable) {
      if (!notApplicable.has(entry.id)) notApplicable.set(entry.id, entry);
    }
  }

  const ordered = [...proposals.values()].sort((a, b) => {
    const byDomain = domainRank(a.domain) - domainRank(b.domain);
    return byDomain !== 0 ? byDomain : a.id.localeCompare(b.id);
  });

  // Parsed on the way out: a generator bug should fail here, not in the report.
  return ProposalSetSchema.parse({
    proposals: ordered,
    notApplicable: [...notApplicable.values()].sort((a, b) => a.id.localeCompare(b.id)),
  });
}
