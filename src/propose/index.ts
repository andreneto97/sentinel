/** Phase 0.5: diff what the repo contains against what the scope will check. */
export {
  emptySentinelConfig,
  mergeDecisionIntoConfig,
  parseSentinelConfig,
  SENTINEL_CONFIG_FILENAME,
  serializeSentinelConfig,
} from "./config.ts";
export type { ConfigParseResult } from "./config.ts";
export {
  answersFromDecision,
  buildScopeProposalDocument,
  decideScope,
  resolveSelectors,
} from "./decide.ts";
export type { DomainOverrides, ScopeOptions } from "./decide.ts";
export {
  absenceGenerator,
  ALL_GENERATORS,
  ciGenerator,
  frontendGenerator,
  iacGenerator,
  migrationsGenerator,
  missingToolGenerator,
  monorepoGenerator,
  sastLanguageGenerator,
  serverlessIamGenerator,
} from "./generators.ts";
export type { ProposalContext, ProposalGenerator } from "./generators.ts";
export {
  AI_DEFAULT_ON_BUDGET_SECONDS,
  DEEP_MIGRATION_THRESHOLD,
  DEFAULT_DOMAINS,
  defaultAnswerFor,
} from "./policy.ts";
export { createProposalContext, proposeScope } from "./propose.ts";
export type { ProposalContextInput } from "./propose.ts";
export {
  formatCost,
  formatDuration,
  renderProposalList,
  renderScopeProposalJson,
  renderScopeSection,
  renderScopeSummary,
} from "./render.ts";
export {
  createProfileView,
  evidencePaths,
  factCount,
  PROFILE_TOPICS,
  toProfileView,
  totalCount,
} from "./stack-profile-adapter.ts";
export type { ProfileAbsence, ProfileFact, ProfileView } from "./stack-profile-adapter.ts";
