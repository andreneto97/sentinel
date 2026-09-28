/**
 * One classifier for the question two phases keep asking separately: **is this
 * file the code that runs in production?**
 *
 * Phase 1 asks it to grade a finding — a signing secret in `auth.test.ts` is a
 * fixture, not a forgeable production token — and phase 2 asks it to decide
 * whether a unit is worth auditing at all. Both used to answer it by not asking,
 * which is how a scan of a monorepo can open with three `critical` findings that
 * are all `jwt.sign(payload, "test")` inside a unit test.
 *
 * Three rules shape this module:
 *
 * - **The shapes are conventions, not inventions.** Every entry in
 *   {@link FILE_KIND_RULES} is a path shape Node and TypeScript projects use the
 *   same way — `*.test.ts`, `*.spec.ts`, `__snapshots__/`, a `test-helpers/`
 *   library, a Helm chart's `templates/tests/` — and each entry says which
 *   convention it encodes and why that convention means what it means. The table
 *   is exercised in `_file-kind.test.ts` against a corpus of paths drawn from an
 *   invented lending-library service and from this repository itself.
 * - **Non-production is not the same as harmless.** The cap in
 *   {@link FILE_KIND_POLICY} applies to test, fixture and documentation code,
 *   none of which is deployed. Generated and vendored code *is* deployed — it
 *   compiles into the artifact that serves requests — so it is classified and
 *   never downgraded. An `example`/`template` file is classified and also never
 *   downgraded: such a file is tracked and copied by every clone, so a value in
 *   one is exposed exactly as much as a value in source, and a cap keyed on the
 *   filename would hide a real one. Whether a value is real is a question about
 *   the value, and `severity.ts#gradeSecret` is where it is asked.
 * - **A capped finding still carries what it was.** The cap is stated in the
 *   title, the severity it came from is named in the description, and the
 *   analyzer's own grade is untouched in `raw/`. Nothing here deletes a finding.
 *
 * The one case that must survive all of it: a **real** credential committed
 * into a test file. Rotating an AWS key is required whether or not the file it
 * sits in ships, so T3 withholds the cap from a secret gitleaks matched with a
 * provider-specific rule — and only from those, because a `jwt` or
 * `generic-api-key` hit is a shape-and-entropy lead, which is exactly what a
 * fake secret in a test looks like.
 */

import type { Finding, Severity } from "../contracts/findings.ts";
import { SECRET_RULE, SECRET_SCANNER, severityRank } from "./severity.ts";

/** What a path says about whether its contents run in production. */
export type FileKind =
  | "production"
  | "test"
  | "fixture"
  | "documentation"
  | "example"
  | "generated"
  | "vendored";

/**
 * The kinds in the order anything that lists them lists them, so two runs word
 * a sentence about several of them identically.
 */
export const FILE_KIND_ORDER: readonly FileKind[] = [
  "test",
  "fixture",
  "documentation",
  "example",
  "generated",
  "vendored",
  "production",
];

/** One observed path shape and what it means. */
export interface FileKindRule {
  /** `production` is the absence of a rule, so it cannot be declared by one. */
  readonly kind: Exclude<FileKind, "production">;
  /** The shape as a reader writes it; printed in the finding the policy touched. */
  readonly pattern: string;
  /** Tested against the normalised, lower-cased, repo-relative POSIX path. */
  readonly match: RegExp;
}

/**
 * Every shape Sentinel recognises, **in the order it tries them**: first match
 * wins, so the order is part of the policy.
 *
 * Vendored code comes first because "this is not ours" outranks everything else
 * a path could say about it. Build output comes next, so a compiled
 * `dist/handlers.test.js` is reported as build output rather than as a test.
 * Then the basename shapes, which are the sharpest signal a single file can
 * carry — `b2b.generated.spec.ts` is a *test*, and its `.spec.` suffix says so
 * more precisely than its `.generated.` infix does. Directory shapes come last.
 */
export const FILE_KIND_RULES: readonly FileKindRule[] = [
  // Not our code at all. Present whenever dependencies have been installed, and
  // absent from a freshly cloned tree, so a scan may or may not see it.
  { kind: "vendored", pattern: "node_modules/", match: /(^|\/)node_modules\// },

  // Build output. Conventionally git-ignored, so a clone has none of it and a
  // working tree that has been built has all of it.
  { kind: "generated", pattern: ".next/", match: /(^|\/)\.next\// },
  { kind: "generated", pattern: "dist/", match: /(^|\/)dist\// },
  { kind: "generated", pattern: "build/", match: /(^|\/)build\// },

  // Documentation. Tried before the test shapes so `README-TEST.md` is read as
  // the document it is: with no documentation kind at all, a fenced usage line
  // like `npm run test:local -- <token> --account-id=123` is graded as a `high`
  // hardcoded credential in production code.
  { kind: "documentation", pattern: "*.md", match: /\.mdx?$/ },
  { kind: "documentation", pattern: "*.rst", match: /\.(?:rst|adoc|asciidoc)$/ },

  // Placeholder templates: a file whose whole purpose is to be copied and filled
  // in. This kind does **not** cap anything, because a template is tracked and a
  // value in one is as exposed as a value in source. What the value is worth is
  // decided by the value, in `severity.ts#gradeSecret`, not by the name.
  { kind: "example", pattern: "*.example", match: /\.(?:example|sample|template|dist)$/ },

  // Basename shapes. `*.test.*` is the shape this whole module exists for: in a
  // repository of any size it is most of what a careless scan grades as
  // production code.
  { kind: "test", pattern: "*.test.*", match: /\.test\.[cm]?[jt]sx?$/ },
  { kind: "test", pattern: "*.spec.*", match: /\.spec\.[cm]?[jt]sx?$/ },
  // A `test-` prefix rather than a `.test.` infix: a `test-local.ts` next to a
  // service is a hand-run harness behind an npm `test:local` script. The shape
  // is narrow — it matches a basename, not a word inside one — which is what
  // makes it safe to have.
  {
    kind: "test",
    pattern: "test-*",
    match: /(?:^|\/)(?:test-[^/]*|[^/]*-test)\.[cm]?[jt]sx?$/,
  },
  // Declaration files describe types and emit nothing.
  { kind: "generated", pattern: "*.d.ts", match: /\.d\.[cm]?ts$/ },
  // Convention, and the companion of a generated `.spec.` file.
  { kind: "generated", pattern: "*.generated.*", match: /\.generated\.[cm]?[jt]sx?$/ },
  // A `*.mock.ts` under a `mocks/` directory is the canonical hand-written double.
  { kind: "fixture", pattern: "*.mock.*", match: /\.mocks?\.[cm]?[jt]sx?$/ },
  // Convention: a Storybook story is an example of a component, not a caller.
  { kind: "fixture", pattern: "*.stories.*", match: /\.stories\.[cm]?[jt]sx?$/ },

  // Directory shapes. A snapshot directory and a `test-helpers` library are
  // where a large share of a monorepo's non-production files live — including
  // the `jwt.sign(payload, "test")` calls that an unclassified scan reports as
  // `critical` production findings.
  { kind: "fixture", pattern: "__fixtures__/", match: /(^|\/)__fixtures__\// },
  { kind: "fixture", pattern: "__mocks__/", match: /(^|\/)__mocks__\// },
  { kind: "fixture", pattern: "__snapshots__/", match: /(^|\/)__snapshots__\// },
  { kind: "fixture", pattern: "mocks/", match: /(^|\/)mocks\// },
  { kind: "test", pattern: "__tests__/", match: /(^|\/)__tests__\// },
  // A Helm chart keeps its test hook in `templates/tests/`, which is why the
  // bare `test/` and `tests/` segments are here and not only the `__tests__/` one.
  { kind: "test", pattern: "test/", match: /(^|\/)test\// },
  { kind: "test", pattern: "tests/", match: /(^|\/)tests\// },
  { kind: "test", pattern: "test-helpers/", match: /(^|\/)test-helpers\// },
  // The two conventional homes of an end-to-end suite.
  { kind: "test", pattern: "e2e/", match: /(^|\/)e2e\// },
  { kind: "test", pattern: "cypress/", match: /(^|\/)cypress\// },
  // Documentation directories, last so a `.ts` example inside `docs/` is still
  // documentation. The suffix covers a split like `docs/` and `docs-public/`.
  { kind: "documentation", pattern: "docs/", match: /(^|\/)docs?(?:-[a-z-]+)?\// },
];

/**
 * Paths reach this module from six analyzers and five enumerators. Windows
 * separators, a `./` prefix and a stray leading `/` are all normalised away;
 * the comparison is lower-cased because every shape in the table is lower-case
 * ASCII, and a `__TESTS__/` directory is still a test directory.
 */
function normalisePath(path: string): string {
  return path.replace(/\\/g, "/").replace(/^\.\//, "").replace(/^\/+/, "").toLowerCase();
}

/** What a path is, and the shape that decided it. */
export interface FileKindVerdict {
  readonly kind: FileKind;
  /** The matched shape, e.g. `*.test.*`; null when the file is production code. */
  readonly pattern: string | null;
}

/** Classifies one repo-relative path. The only place this question is answered. */
export function classifyFile(path: string): FileKindVerdict {
  const normalised = normalisePath(path);
  for (const rule of FILE_KIND_RULES) {
    if (rule.match.test(normalised)) return { kind: rule.kind, pattern: rule.pattern };
  }
  return { kind: "production", pattern: null };
}

/** True for every kind except `production`. */
export function isNonProduction(kind: FileKind): boolean {
  return kind !== "production";
}

/** What the policy does to a finding in one kind of file. */
export interface FileKindPolicy {
  /** The severity a finding here is capped at; null leaves the finding alone. */
  readonly cap: Severity | null;
  /** Prefixed to the title when the file is not production code; `""` otherwise. */
  readonly titlePrefix: string;
  /** The one-sentence argument for this row, so a reader can disagree with it. */
  readonly because: string;
}

/**
 * **The severity policy for non-production code.** One row per file kind.
 *
 * | kind | severity | title | why |
 * |---|---|---|---|
 * | production | untouched | untouched | it is the code that serves requests |
 * | test | capped at `low` | `In test code: …` | a test is not deployed, so a secret in one is a fixture and a query in one has no tenant to isolate |
 * | fixture | capped at `low` | `In test fixture code: …` | a fixture exists to hold fake data; that is its job, not a defect |
 * | documentation | capped at `low` | `In documentation: …` | prose and fenced examples describe the code; nothing in them executes |
 * | example | untouched | `In an example/template file: …` | a template is *tracked*, so a real value in one is a real leak — only the value decides, and `severity.ts#gradeSecret` reads it |
 * | generated | untouched | untouched | generated code compiles into the artifact that runs, so the risk is real — the *fix* belongs in the generator |
 * | vendored | untouched | untouched | third-party code ships and executes; it is graded by the dependency domain, not downgraded here |
 *
 * And the exception, T3: a secret gitleaks matched with a provider-specific
 * rule keeps its severity in every kind of file, because the credential has to
 * be rotated wherever it was committed. See {@link isRotationRequiredSecret}.
 */
export const FILE_KIND_POLICY: Readonly<Record<FileKind, FileKindPolicy>> = {
  production: {
    cap: null,
    titlePrefix: "",
    because: "it is the code that serves requests",
  },
  test: {
    cap: "low",
    titlePrefix: "In test code: ",
    because:
      "a test is not deployed, so a signing secret in one is a fixture and a query in one has no tenant to isolate",
  },
  fixture: {
    cap: "low",
    titlePrefix: "In test fixture code: ",
    because: "a fixture exists to hold fake data, which is its job rather than a defect",
  },
  documentation: {
    cap: "low",
    titlePrefix: "In documentation: ",
    because:
      "prose and fenced examples describe the code rather than being it, so nothing in them runs, and a value shown in a usage line is there to be read",
  },
  // Deliberately uncapped. A `.env.example` is committed, so a value left in one
  // is readable by everyone who can clone the repository; a cap keyed on the
  // *filename* would hide exactly that. The placeholder case is handled where the
  // evidence is — the value — in `gradeSecret`.
  example: {
    cap: null,
    titlePrefix: "In an example/template file: ",
    because:
      "a template file is tracked and copied by every developer, so a value that is real in one is exposed exactly as much as a value in source; only the value can say which it is",
  },
  generated: {
    cap: null,
    titlePrefix: "",
    because:
      "generated code compiles into the artifact that serves requests, so the risk is real and only the fix moves — into the generator",
  },
  vendored: {
    cap: null,
    titlePrefix: "",
    because:
      "vendored code ships and executes; it is graded by the dependency domain rather than downgraded here",
  },
};

/**
 * Every non-empty prefix {@link FILE_KIND_POLICY} can put in front of a title,
 * longest first so `In test fixture code: ` is tried before any prefix of it.
 *
 * Exported because a title with one of these on the front is no longer the
 * title the rule wrote, and a reader of titles has to be able to get back to
 * it. See {@link withoutFileKindPrefix}.
 */
export const FILE_KIND_TITLE_PREFIXES: readonly string[] = FILE_KIND_ORDER.map(
  (kind) => FILE_KIND_POLICY[kind].titlePrefix,
)
  .filter((prefix) => prefix !== "")
  .sort((left, right) => right.length - left.length);

/**
 * The title as the rule wrote it, with any file-kind prefix taken back off.
 *
 * `_volume.ts` groups a rule's findings under the noun they all share — "Unused
 * file candidate" out of "Unused file candidate: apps/staff-portal/jest.config.ts"
 * — and falls back to the bare rule id when the members disagree. Prefixing some
 * of a group's titles with `In test code: ` makes them disagree, so a group that
 * should read `42 Unused file candidates` prints ``42 `deadcode.unused-file`
 * findings`` instead. The prefix is a fact about the file, not about the rule,
 * so it comes off before the noun is read.
 */
export function withoutFileKindPrefix(title: string): string {
  for (const prefix of FILE_KIND_TITLE_PREFIXES) {
    if (title.startsWith(prefix)) return title.slice(prefix.length);
  }
  return title;
}

/** The policy ids, quoted in the sentence the report prints. */
export const FILE_KIND_RULE_IDS = {
  testCap: "T1",
  fixtureCap: "T2",
  rotationRequired: "T3",
  documentationCap: "T4",
} as const;

/**
 * T3 — the credential that keeps its severity wherever it lives.
 *
 * Decided from **the scanner's own rule id**, not from the path: `gradeSecret`
 * in `severity.ts` issues `confidence: "high"` for a provider-specific match — an
 * AWS key id, a private-key block, a vendor's live token format — and for
 * nothing else, so a `high`-confidence secret finding is one the scanner
 * recognised as a particular provider's credential, and that has to be rotated
 * whether the file ships or not. R1 in `severity.ts` reads the same channel for
 * the same reason.
 *
 * A fake JWT secret in a unit test is not that — `jwt` is a heuristic rule, and
 * the hardcoded-secret findings Sentinel's own opengrep pack raises are not
 * gitleaks findings at all. Both get capped. `_file-kind.test.ts` pins the two
 * `confidenceForRule` answers this rule reads, so a change to that table fails
 * here rather than silently widening the exception.
 */
export function isRotationRequiredSecret(finding: Finding): boolean {
  return (
    finding.rule === SECRET_RULE &&
    finding.source.kind === "tool" &&
    finding.source.name === SECRET_SCANNER &&
    finding.confidence === "high"
  );
}

/** What the policy decided for one finding, and the words to say about it. */
export interface FileKindDecision {
  readonly kind: FileKind;
  /** The shape that decided the kind; null for production code. */
  readonly pattern: string | null;
  /** What the finding should carry. Never above what it came in with. */
  readonly severity: Severity;
  /** True when `severity` is below the severity the finding came in with. */
  readonly capped: boolean;
  /** True when the cap applied to this kind but T3 withheld it. */
  readonly exempt: boolean;
  /** Prefixed to the title; `""` for production code. */
  readonly titlePrefix: string;
  /** One sentence naming the rule that acted; null when nothing did. */
  readonly rationale: string | null;
}

/** The half of T3's sentence that does not vary; kept whole for one template literal. */
const ROTATION_REQUIRED_TAIL =
  "gitleaks matched a provider-specific rule, not one of its entropy heuristics, so this is a real credential and it has to be rotated whether or not this file ships.";

/** `T1`/`T2`/`T4` by kind; only the capped kinds have an id. */
function ruleIdFor(kind: FileKind): string {
  if (kind === "fixture") return FILE_KIND_RULE_IDS.fixtureCap;
  return kind === "documentation"
    ? FILE_KIND_RULE_IDS.documentationCap
    : FILE_KIND_RULE_IDS.testCap;
}

/**
 * Applies {@link FILE_KIND_POLICY} to one finding.
 *
 * Pure, and deliberately returns words rather than writing them: `normalise.ts`
 * composes the title and the description, exactly as it already does with the
 * escalation rationale from `severity.ts`.
 */
export function decideFileKind(finding: Finding): FileKindDecision {
  const verdict = classifyFile(finding.location.file);
  const policy = FILE_KIND_POLICY[verdict.kind];
  const shape = verdict.pattern === null ? "" : ` (\`${verdict.pattern}\`)`;

  const unchanged = {
    kind: verdict.kind,
    pattern: verdict.pattern,
    severity: finding.severity,
    capped: false,
    exempt: false,
    titlePrefix: policy.titlePrefix,
  } as const;

  if (policy.cap === null) return { ...unchanged, rationale: null };

  if (isRotationRequiredSecret(finding)) {
    return {
      ...unchanged,
      exempt: true,
      rationale: `Sentinel kept this at ${finding.severity} although it sits in ${verdict.kind} code${shape} (${FILE_KIND_RULE_IDS.rotationRequired}): ${ROTATION_REQUIRED_TAIL}`,
    };
  }

  // A finding already at or below the cap is in the right place; saying so would
  // be noise, but the title still tells the reader where the code lives.
  if (severityRank(finding.severity) >= severityRank(policy.cap)) {
    return { ...unchanged, rationale: null };
  }

  return {
    kind: verdict.kind,
    pattern: verdict.pattern,
    severity: policy.cap,
    capped: true,
    exempt: false,
    titlePrefix: policy.titlePrefix,
    rationale:
      `Sentinel capped this at ${policy.cap} (${ruleIdFor(verdict.kind)}): it is in ${verdict.kind} code${shape}, and ` +
      `${policy.because}. It was graded ${finding.severity} before the cap, and the analyzer's own grade is in \`raw/\`.`,
  };
}
