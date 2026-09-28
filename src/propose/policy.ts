import { DomainSchema } from "../contracts/findings.ts";
import type { Domain } from "../contracts/findings.ts";
import type { ProposalAnswer, ProposalCost } from "../contracts/proposal.ts";

/**
 * Domains a run checks without anyone accepting a proposal: D1-D4 plus dead
 * code, which phase 1 already produces candidates for through knip and
 * dependency-cruiser. Leaving it off silently discarded those, which is the
 * opposite of what scope negotiation is for. D5-D7 stay behind a proposal
 * until their checks exist (PLAN.md, "Build order").
 */
export const DEFAULT_DOMAINS: readonly Domain[] = [
  "dependencies",
  "appsec",
  "data",
  "delivery",
  "deadcode",
];

/** Report order for domains, so two runs never disagree about layout. */
export const DOMAIN_ORDER: readonly Domain[] = DomainSchema.options;

/** An AI proposal cheaper than this is safe to default on; above it, ask. */
export const AI_DEFAULT_ON_BUDGET_SECONDS = 180;

/** Number of migrations above which the directory earns a deep-analysis pass. */
export const DEEP_MIGRATION_THRESHOLD = 20;

/** Languages Sentinel's own SAST rule pack covers as first-class citizens. */
export const SAST_COVERED_LANGUAGES: ReadonlySet<string> = new Set([
  "javascript",
  "js",
  "jsx",
  "typescript",
  "ts",
  "tsx",
]);

/** Languages with no Sentinel rules but a usable opengrep community pack. */
export const OPENGREP_COMMUNITY_LANGUAGES: ReadonlySet<string> = new Set([
  "c",
  "cpp",
  "csharp",
  "elixir",
  "go",
  "java",
  "kotlin",
  "php",
  "python",
  "ruby",
  "rust",
  "scala",
  "swift",
]);

/**
 * What `--yes` answers. Deterministic work defaults on; AI work defaults on
 * only inside the budget; anything blocked on a missing tool defaults off,
 * because accepting it would buy nothing.
 */
export function defaultAnswerFor(cost: ProposalCost, toolAvailable: boolean): ProposalAnswer {
  if (!toolAvailable) return "off";
  if (!cost.usesAi) return "on";
  return cost.estimatedSeconds <= AI_DEFAULT_ON_BUDGET_SECONDS ? "on" : "off";
}

/** Clamps an estimate into a range, so a 900-migration repo does not claim 30 minutes. */
export function clampSeconds(seconds: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, Math.round(seconds)));
}

/** Sorts domains into `DOMAIN_ORDER`, dropping duplicates. */
export function orderDomains(domains: Iterable<Domain>): Domain[] {
  const present = new Set(domains);
  return DOMAIN_ORDER.filter((domain) => present.has(domain));
}

/** True when `child` is the same path as, or nested inside, `parent`. */
export function isWithinPath(child: string, parent: string): boolean {
  const normalize = (value: string): string =>
    value
      .trim()
      .replace(/^\.\/+/, "")
      .replace(/\/+$/, "")
      .replace(/^\/+/, "");
  const parentPath = normalize(parent);
  const childPath = normalize(child);
  if (parentPath === "" || parentPath === ".") return true;
  if (childPath === parentPath) return true;
  return childPath.startsWith(`${parentPath}/`);
}

/** Lower-cased, dash-separated slug usable inside a stable proposal id. */
export function slugify(value: string): string {
  const slug = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return slug === "" ? "unnamed" : slug;
}
