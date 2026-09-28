import type { Domain } from "../contracts/findings.ts";
import type {
  Detection,
  NotApplicable,
  Proposal,
  ProposalAnswer,
  ProposalCost,
  ProposalDomain,
  ProposalSet,
} from "../contracts/proposal.ts";
import {
  DEEP_MIGRATION_THRESHOLD,
  OPENGREP_COMMUNITY_LANGUAGES,
  SAST_COVERED_LANGUAGES,
  clampSeconds,
  defaultAnswerFor,
  isWithinPath,
  slugify,
} from "./policy.ts";
import type { ProfileFact, ProfileView } from "./stack-profile-adapter.ts";
import { PROFILE_TOPICS, evidencePaths, factCount, totalCount } from "./stack-profile-adapter.ts";

/** Everything a generator needs to decide whether a gap exists. */
export interface ProposalContext {
  readonly profile: ProfileView;
  /** Domains the run checks before any proposal is accepted. */
  readonly baseDomains: ReadonlySet<Domain>;
  /** External tools `doctor` reported as present. */
  readonly availableTools: ReadonlySet<string>;
  /** Proposal ids the caller already decided are in scope, so they stay quiet. */
  readonly scopedCategories: ReadonlySet<string>;
  /** Repo-relative path under analysis; packages outside it get proposed. */
  readonly analysedPath: string;
}

/** A pure function from a profiled repo to the gaps it implies. */
export type ProposalGenerator = (ctx: ProposalContext) => ProposalSet;

interface ProposalInput {
  id: string;
  title: string;
  domain: ProposalDomain;
  detected: Detection;
  wouldCheck: string;
  cost: ProposalCost;
  aliases?: readonly string[];
  attributes?: Readonly<Record<string, string>>;
  /** Overrides the cost-derived default where the policy is a judgement call. */
  defaultAnswer?: ProposalAnswer;
  toolAvailable?: boolean;
}

/** Fills in the defaulted fields so generators stay declarative. */
function makeProposal(input: ProposalInput): Proposal {
  return {
    id: input.id,
    title: input.title,
    domain: input.domain,
    detected: input.detected,
    wouldCheck: input.wouldCheck,
    cost: input.cost,
    defaultAnswer: input.defaultAnswer ?? defaultAnswerFor(input.cost, input.toolAvailable ?? true),
    aliases: [...(input.aliases ?? [])],
    attributes: { ...(input.attributes ?? {}) },
  };
}

/** Renders a sample of values as prose: "a, b and 3 more". */
function summarize(values: readonly string[], limit = 3): string {
  if (values.length === 0) return "none";
  const head = values.slice(0, limit).join(", ");
  const rest = values.length - limit;
  return rest > 0 ? `${head} and ${rest} more` : head;
}

/** Fresh empty result; never a shared array, so callers may splice freely. */
function none(): ProposalSet {
  return { proposals: [], notApplicable: [] };
}

/** Facts of the given topics whose value is exactly `value`. */
function factsWithValue(
  profile: ProfileView,
  value: string,
  topics: readonly string[],
): readonly ProfileFact[] {
  return profile.select(...topics).filter((fact) => fact.value.trim() === value);
}

interface IacFlavour {
  readonly label: string;
  readonly seconds: number;
}

const IAC_FLAVOURS: Readonly<Record<string, IacFlavour>> = {
  terraform: { label: "Terraform", seconds: 40 },
  pulumi: { label: "Pulumi", seconds: 40 },
  kubernetes: { label: "Kubernetes manifests", seconds: 30 },
  helm: { label: "Helm charts", seconds: 30 },
};

/** IaC lives in the repo but nothing in the base scope reads it. */
export const iacGenerator: ProposalGenerator = (ctx) => {
  const proposals: Proposal[] = [];
  for (const value of ctx.profile.values(...PROFILE_TOPICS.iac)) {
    const id = `delivery.iac.${slugify(value)}`;
    if (ctx.scopedCategories.has(id)) continue;
    const facts = factsWithValue(ctx.profile, value, PROFILE_TOPICS.iac);
    const flavour = IAC_FLAVOURS[value] ?? { label: value, seconds: 40 };
    const count = totalCount(facts);
    const countText = count === undefined ? "" : ` (${count} file(s))`;
    proposals.push(
      makeProposal({
        id,
        title: `${flavour.label} present but not scanned`,
        domain: "delivery",
        detected: {
          summary: `${flavour.label} detected${countText}`,
          evidence: evidencePaths(facts),
          ...(count === undefined ? {} : { count }),
        },
        wouldCheck: `Run \`trivy config\` over ${flavour.label}: public exposure, missing encryption, over-broad IAM, unpinned modules and insecure defaults.`,
        cost: { estimatedSeconds: flavour.seconds, usesAi: false, requiresTool: "trivy" },
        aliases: [value, `iac.${slugify(value)}`, "iac"],
        attributes: { flavour: value },
        toolAvailable: ctx.availableTools.has("trivy"),
      }),
    );
  }
  return { proposals, notApplicable: [] };
};

/** Serverless workloads exist, so their IAM roles and triggers can be audited. */
export const serverlessIamGenerator: ProposalGenerator = (ctx) => {
  const topics = [...PROFILE_TOPICS.serverlessPlatform, ...PROFILE_TOPICS.serverlessFunction];
  const facts = ctx.profile.select(...topics);
  const id = "serverless.iam-audit";
  if (facts.length === 0 || ctx.scopedCategories.has(id)) return none();
  const platforms = ctx.profile.values(...PROFILE_TOPICS.serverlessPlatform);
  const explicitFunctions = ctx.profile.select(...PROFILE_TOPICS.serverlessFunction);
  const functionCount = explicitFunctions.length > 0 ? explicitFunctions.length : totalCount(facts);
  const manifests = ctx.profile.select(...PROFILE_TOPICS.serverlessManifest);
  const countText = functionCount === undefined ? "" : `${functionCount} function(s) across `;
  return {
    proposals: [
      makeProposal({
        id,
        title: "Serverless IAM and trigger permission audit",
        domain: "serverless",
        detected: {
          summary: `${countText}${platforms.length} serverless platform(s): ${summarize(platforms)}`,
          evidence: evidencePaths([...facts, ...manifests]),
          ...(functionCount === undefined ? {} : { count: functionCount }),
        },
        wouldCheck:
          "For every function: wildcard Action/Resource in its role, a role shared across " +
          "functions, public function URLs and unauthenticated triggers, bucket or queue " +
          "policies wider than the handler needs, and missing DLQ or concurrency limits.",
        cost: {
          estimatedSeconds:
            functionCount === undefined ? 180 : clampSeconds(functionCount * 10, 60, 900),
          usesAi: true,
        },
        aliases: ["iam", "serverless-iam"],
        attributes: { platforms: platforms.join(",") },
      }),
    ],
    notApplicable: [],
  };
};

/**
 * A migrations directory worth reading in full. When the profiler reports a
 * count, a small directory is left to the ordinary data-layer pass; when it
 * reports none, the offer is made rather than guessed away.
 */
export const migrationsGenerator: ProposalGenerator = (ctx) => {
  const facts = ctx.profile.select(...PROFILE_TOPICS.migrationsDir);
  const id = "data.deep-migrations";
  if (facts.length === 0 || ctx.scopedCategories.has(id)) return none();
  const count = totalCount(facts);
  if (count !== undefined && count < DEEP_MIGRATION_THRESHOLD) return none();
  const directories = ctx.profile.values(...PROFILE_TOPICS.migrationsDir);
  const summary =
    count === undefined
      ? `Migrations in ${summarize(directories)}`
      : `${count} migrations in ${summarize(directories)}`;
  return {
    proposals: [
      makeProposal({
        id,
        title: "Deep migration analysis",
        domain: "data",
        detected: {
          summary,
          evidence: evidencePaths(facts),
          ...(count === undefined ? {} : { count }),
        },
        wouldCheck:
          "Locking operations (NOT NULL with a default on a large table, CREATE INDEX without " +
          "CONCURRENTLY, table-rewriting type changes), destructive statements without a guard, " +
          "out-of-order timestamps, drift against the ORM schema, missing rollback paths, and " +
          "seed data carrying real credentials.",
        cost: {
          estimatedSeconds: count === undefined ? 180 : clampSeconds(count * 2, 60, 900),
          usesAi: true,
        },
        aliases: ["migrations", "deep-migrations"],
        attributes: { directories: directories.join(",") },
      }),
    ],
    notApplicable: [],
  };
};

/** CI configuration deserves more than the base delivery pass. */
export const ciGenerator: ProposalGenerator = (ctx) => {
  const facts = ctx.profile.select(...PROFILE_TOPICS.ci);
  const id = "delivery.ci-deep-audit";
  if (facts.length === 0 || ctx.scopedCategories.has(id)) return none();
  const systems = ctx.profile.values(...PROFILE_TOPICS.ci);
  const count = totalCount(facts);
  const countText = count === undefined ? "" : `${count} file(s) across `;
  return {
    proposals: [
      makeProposal({
        id,
        title: "Deep CI/CD audit",
        domain: "delivery",
        detected: {
          summary: `${countText}${systems.length} CI system(s): ${summarize(systems)}`,
          evidence: evidencePaths(facts),
          ...(count === undefined ? {} : { count }),
        },
        wouldCheck:
          "Unpinned third-party actions, `pull_request_target` checking out untrusted code, " +
          "script injection through `${{ github.event.* }}`, over-broad `permissions`, secrets " +
          "reaching logs, missing `concurrency`, and self-hosted runners on a public repo.",
        cost: { estimatedSeconds: 60, usesAi: false, requiresTool: "actionlint" },
        aliases: ["ci", "ci-audit", "actions"],
        attributes: { systems: systems.join(",") },
        toolAvailable: ctx.availableTools.has("actionlint"),
      }),
    ],
    notApplicable: [],
  };
};

/** Monorepo packages sitting outside the analysed path are invisible by default. */
export const monorepoGenerator: ProposalGenerator = (ctx) => {
  const facts = ctx.profile.select(...PROFILE_TOPICS.workspacePackage);
  if (facts.length === 0) return none();
  const proposals: Proposal[] = [];
  for (const packagePath of ctx.profile.values(...PROFILE_TOPICS.workspacePackage)) {
    if (isWithinPath(packagePath, ctx.analysedPath)) continue;
    const id = `scope.package.${slugify(packagePath)}`;
    if (ctx.scopedCategories.has(id)) continue;
    const packageFacts = factsWithValue(ctx.profile, packagePath, PROFILE_TOPICS.workspacePackage);
    const name = packageFacts.find((fact) => fact.detail !== undefined)?.detail;
    const label = name === undefined ? `\`${packagePath}\`` : `\`${name}\` (\`${packagePath}\`)`;
    proposals.push(
      makeProposal({
        id,
        title: `Include the ${label} package`,
        domain: "scope",
        detected: {
          summary: `${label} is part of this monorepo but outside \`${ctx.analysedPath}\``,
          evidence: evidencePaths(packageFacts.length > 0 ? packageFacts : facts),
          count: 1,
        },
        wouldCheck: `Run every enabled domain over \`${packagePath}\` as well, so its routes, queries, dependencies and dead code land in the same dossier.`,
        // Off by default: pulling in a whole package multiplies the run, and
        // the operator may have narrowed the path deliberately.
        defaultAnswer: "off",
        cost: { estimatedSeconds: 240, usesAi: true },
        aliases: [packagePath, slugify(packagePath), ...(name === undefined ? [] : [name])],
        attributes: { path: packagePath, ...(name === undefined ? {} : { name }) },
      }),
    );
  }
  return { proposals, notApplicable: [] };
};

interface ToolRequirement {
  readonly tool: string;
  readonly domain: Domain;
  readonly seconds: number;
  /** What stays unchecked while the tool is missing. */
  readonly buys: string;
  readonly relevant: (ctx: ProposalContext) => boolean;
}

const TOOL_REQUIREMENTS: readonly ToolRequirement[] = [
  {
    tool: "trivy",
    domain: "dependencies",
    seconds: 30,
    buys: "dependency CVEs, the CycloneDX SBOM and licence inventory, and `trivy config`",
    relevant: () => true,
  },
  {
    tool: "gitleaks",
    domain: "appsec",
    seconds: 20,
    buys: "secret detection across the working tree and the full git history",
    relevant: () => true,
  },
  {
    tool: "opengrep",
    domain: "appsec",
    seconds: 25,
    buys: "SAST over Sentinel's own rule pack (injection, XSS sinks, unsafe input)",
    relevant: () => true,
  },
  {
    tool: "hadolint",
    domain: "delivery",
    seconds: 15,
    buys: "Dockerfile linting; without it, findings are limited to Sentinel's own rules",
    relevant: (ctx) => ctx.profile.has(...PROFILE_TOPICS.container),
  },
  {
    tool: "actionlint",
    domain: "delivery",
    seconds: 15,
    buys: "GitHub Actions linting with shellcheck over `run:` blocks",
    relevant: (ctx) => ctx.profile.has(...PROFILE_TOPICS.ci),
  },
];

/** A tool this repo would exercise is not installed; offer to fetch it. */
export const missingToolGenerator: ProposalGenerator = (ctx) => {
  const proposals: Proposal[] = [];
  for (const requirement of TOOL_REQUIREMENTS) {
    if (ctx.availableTools.has(requirement.tool)) continue;
    if (!requirement.relevant(ctx)) continue;
    const id = `tooling.install.${requirement.tool}`;
    if (ctx.scopedCategories.has(id)) continue;
    proposals.push(
      makeProposal({
        id,
        title: `Install \`${requirement.tool}\``,
        domain: requirement.domain,
        detected: {
          summary: `\`${requirement.tool}\` is not installed, and this repo would use it`,
          evidence: [],
        },
        wouldCheck:
          `Download the pinned, hash-verified \`${requirement.tool}\` into the Sentinel cache ` +
          `(no sudo, nothing global) and enable ${requirement.buys}.`,
        // Downloading a binary is a side effect; it waits for an explicit yes.
        defaultAnswer: "off",
        cost: { estimatedSeconds: requirement.seconds, usesAi: false },
        aliases: [requirement.tool, `install-${requirement.tool}`],
        attributes: { tool: requirement.tool },
      }),
    );
  }
  return { proposals, notApplicable: [] };
};

/** Source files Sentinel's SAST rules do not read, one entry per language. */
export const sastLanguageGenerator: ProposalGenerator = (ctx) => {
  const facts = ctx.profile.select(...PROFILE_TOPICS.language);
  if (facts.length === 0) return none();
  const proposals: Proposal[] = [];
  const notApplicable: NotApplicable[] = [];
  const seen = new Set<string>();
  for (const fact of facts) {
    const language = fact.value.trim().toLowerCase().split(":")[0] ?? "";
    if (language === "" || seen.has(language)) continue;
    seen.add(language);
    if (SAST_COVERED_LANGUAGES.has(language)) continue;
    const fileCount = factCount(fact);
    const where = fileCount === undefined ? "Files" : `${fileCount} file(s)`;
    const id = `appsec.sast-language.${slugify(language)}`;
    if (!OPENGREP_COMMUNITY_LANGUAGES.has(language)) {
      notApplicable.push({
        id,
        domain: "appsec",
        category: `SAST for ${language}`,
        reason: `${where} in ${language}; Sentinel ships no rules for it and opengrep has no community pack. These files are counted in the inventory, never analysed.`,
        evidence: evidencePaths([fact]),
      });
      continue;
    }
    if (ctx.scopedCategories.has(id)) continue;
    proposals.push(
      makeProposal({
        id,
        title: `SAST for ${language}`,
        domain: "appsec",
        detected: {
          summary: `${where} in ${language}, a language Sentinel's own rule pack does not cover`,
          evidence: evidencePaths([fact]),
          ...(fileCount === undefined ? {} : { count: fileCount }),
        },
        wouldCheck: `Run opengrep with its community rule pack for ${language}. Declining leaves these files counted in the inventory and reported as unanalysed coverage.`,
        cost: { estimatedSeconds: 90, usesAi: false, requiresTool: "opengrep" },
        aliases: [language, `sast-${slugify(language)}`],
        attributes: { language },
        toolAvailable: ctx.availableTools.has("opengrep"),
      }),
    );
  }
  return { proposals, notApplicable };
};

/**
 * The frontend cuts both ways: present with appsec off is a gap worth offering,
 * absent means the client-side authorization category is declared not
 * applicable instead of quietly producing no findings.
 */
export const frontendGenerator: ProposalGenerator = (ctx) => {
  const facts = ctx.profile.select(...PROFILE_TOPICS.frontend);
  if (facts.length === 0) {
    const absence = ctx.profile.absence("frontend");
    return {
      proposals: [],
      notApplicable: [
        {
          id: "appsec.client-side-authorization",
          domain: "appsec",
          category: "Client-side authorization and role gates",
          reason:
            absence?.note ??
            "No frontend detected in this repository, so there are no role gates to compare " +
              "against server-side checks and no XSS sinks in client code.",
          evidence: [],
        },
      ],
    };
  }
  const id = "appsec.client-surface";
  if (ctx.baseDomains.has("appsec") || ctx.scopedCategories.has(id)) return none();
  const frameworks = ctx.profile.values(...PROFILE_TOPICS.frontend);
  return {
    proposals: [
      makeProposal({
        id,
        title: "Application security over the detected frontend",
        domain: "appsec",
        detected: {
          summary: `Frontend detected (${summarize(frameworks, 2)}) while the appsec domain is off`,
          evidence: evidencePaths(facts),
          count: frameworks.length,
        },
        wouldCheck:
          "Map every frontend role gate to the endpoint behind it and flag the ones the server " +
          "does not re-check, plus XSS sinks (`dangerouslySetInnerHTML`, `innerHTML`, " +
          "`javascript:` URLs) and secrets shipped to the client bundle.",
        cost: { estimatedSeconds: 150, usesAi: true },
        aliases: ["appsec", "frontend"],
        attributes: {},
      }),
    ],
    notApplicable: [],
  };
};

/** Fact kinds whose absence changes what a domain can honestly claim to check. */
const DOMAIN_BY_ABSENT_KIND: Readonly<Record<string, Domain>> = {
  container: "delivery",
  ci: "delivery",
  iac: "delivery",
  "serverless-platform": "serverless",
  "scheduled-job": "serverless",
  queue: "serverless",
  scheduler: "serverless",
  "data-layer": "data",
  "db-schema-file": "data",
  "migrations-dir": "data",
  "database-engine": "data",
  "auth-provider": "appsec",
  "auth-helper": "appsec",
  "config-validation": "appsec",
};

/**
 * Turns the profiler's own absence notes into declarations. The profiler
 * already wrote down what each absence costs; repeating it in the report is
 * cheaper than letting a whole category vanish without a line.
 */
export const absenceGenerator: ProposalGenerator = (ctx) => {
  const notApplicable: NotApplicable[] = [];
  for (const absence of ctx.profile.absences) {
    // The frontend absence is owned by `frontendGenerator`, which words it
    // in terms of the access-control category it disables.
    if (absence.kind === "frontend") continue;
    const domain = DOMAIN_BY_ABSENT_KIND[absence.kind];
    if (domain === undefined || absence.note === undefined) continue;
    notApplicable.push({
      id: `profile.absence.${slugify(absence.kind)}`,
      domain,
      category: absence.kind.replace(/-/g, " "),
      reason: absence.note,
      evidence: [],
    });
  }
  return { proposals: [], notApplicable };
};

/** Every generator phase 0.5 runs, in report order. */
export const ALL_GENERATORS: readonly ProposalGenerator[] = [
  missingToolGenerator,
  iacGenerator,
  ciGenerator,
  migrationsGenerator,
  serverlessIamGenerator,
  sastLanguageGenerator,
  frontendGenerator,
  absenceGenerator,
  monorepoGenerator,
];
