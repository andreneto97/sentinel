/**
 * Sentinel's own GitHub Actions rules — the delivery checks actionlint does
 * not make, because actionlint grades a workflow for correctness and these
 * grade it for blast radius.
 *
 * Every rule reads the workflow itself (through `_mini-yaml.ts`) and anchors
 * its finding on the line that proves it, so the citation verifier can extract
 * a snippet a reader can act on.
 *
 * ## Grading is a model, not a mood
 *
 * A severity that leans on the file a match landed in grades the same construct
 * two ways: one `example-org/action-slack-notification@v2.0.0-alpha.4` comes out
 * `high` in the deploy workflow and `medium` in the nightly one, and a reader has
 * no way to tell which number to act on. So severity here is derived only from
 * the construct. Three distinctions carry it, and each one is a table in this
 * file rather than a sentence in a finding:
 *
 * 1. **Whose account has to be compromised** ({@link ActionTrust}). `actions/*`
 *    is the platform, `<this repository's owner>/*` is a colleague who already
 *    has write access here, and anything else is a stranger. The owner is
 *    resolved from the repository's own git remote or the scope of its root
 *    `package.json` — never guessed from the action's name.
 * 2. **How movable the ref is** ({@link RefMutability}): a branch moves on every
 *    push, a floating major tag moves on every release, an exact release tag
 *    moves only if someone force-moves it, and a commit SHA cannot move.
 * 3. **What the step can do with the credential it is handed**
 *    ({@link CredentialClass}): `secrets.GITHUB_TOKEN` is minted per job and is
 *    already readable by every step in that job, a single-channel webhook URL
 *    buys a stranger one Slack message, and a repo-scoped PAT buys the
 *    repository.
 *
 * `secret-echoed` needs the same discipline. The commonest way a workflow hands a
 * secret to `echo` is `echo "…${{ secrets.X }}" >> .npmrc`: stdout is redirected
 * into a file, so nothing reaches the job log the rule is named after. The
 * redirection is therefore read ({@link stdoutDispositionOf}) and only an
 * unredirected write to fd 1/2 is called a leak; the redirected write is still
 * reported, under the rule whose claim is true of it.
 *
 * Nothing here deletes a finding quietly: a rule that declines to fire returns
 * a {@link SuppressionNote}, and the runner prints the count and the reason in
 * the step's own `reason`.
 */

import { join } from "node:path";
import type { Finding, Severity } from "../../contracts/findings.ts";
import { workflowFilesOf } from "../_delivery-files.ts";
import {
  type FindingInput,
  type RunnerContext,
  joinReasons,
  makeFinding,
  outcome,
  skipped,
  verifyStepFindings,
} from "../runners/_runner-support.ts";
import { SEVERITY_ORDER } from "../severity.ts";
import type { StepOutcome } from "../types.ts";
import {
  type YamlEntry,
  type YamlNode,
  asSequence,
  childOf,
  entriesOf,
  entryOf,
  itemsOf,
  linesMatching,
  parseYaml,
  textOf,
} from "./_mini-yaml.ts";

/** Step name for the CI rule pack. */
export const CI_RULES_STEP = "ci-rules";

/** Every finding in this pack belongs to D4, so the domain is fixed here once. */
function buildFinding(input: Omit<FindingInput, "domain">): Finding {
  return makeFinding({ ...input, domain: "delivery" });
}

/** Rule ids are namespaced under the domain and the artifact they read. */
const RULE = {
  unpinnedAction: "delivery.ci.unpinned-action",
  unpinnedPlatformAction: "delivery.ci.unpinned-platform-action",
  targetCheckout: "delivery.ci.pull-request-target-checkout",
  scriptInjection: "delivery.ci.script-injection",
  permissionsWriteAll: "delivery.ci.permissions-write-all",
  permissionsUndeclared: "delivery.ci.permissions-not-declared",
  permissionsWorkflowWide: "delivery.ci.permissions-workflow-wide-write",
  secretEchoed: "delivery.ci.secret-echoed",
  secretInRun: "delivery.ci.secret-in-run-command",
  secretToThirdParty: "delivery.ci.secret-to-third-party-action",
  secretToSameOwner: "delivery.ci.secret-to-same-owner-action",
  missingConcurrency: "delivery.ci.missing-concurrency",
  selfHostedRunner: "delivery.ci.self-hosted-runner",
  untrustedTrigger: "delivery.ci.untrusted-trigger-with-secrets",
} as const;

/**
 * A finding a rule decided not to emit, so that the decision is counted instead
 * of being invisible. The runner folds these into the step's `reason`.
 */
export interface SuppressionNote {
  /** The rule that would have fired. */
  readonly rule: string;
  readonly file: string;
  readonly line: number;
  /** Why it did not, in the words a reader can disagree with. */
  readonly reason: string;
}

/** What analysing one workflow produced: findings, and the decisions not to. */
export interface WorkflowAnalysis {
  readonly findings: Finding[];
  readonly suppressed: SuppressionNote[];
}

/**
 * Events an account with no write access to the repository can fire while the
 * job still runs on the base branch with the repository's secrets. A plain
 * `pull_request` from a fork is deliberately not here: GitHub withholds
 * secrets from it, which is exactly what makes it the safe choice.
 */
const UNTRUSTED_TRIGGERS: readonly string[] = [
  "pull_request_target",
  "issue_comment",
  "issues",
  "discussion",
  "discussion_comment",
  "pull_request_review",
  "pull_request_review_comment",
  "workflow_run",
  "fork",
  "watch",
];

/**
 * Triggers an outsider fires directly, by opening a pull request or leaving a
 * comment. `workflow_run` is not one of them: it fires when another workflow
 * finishes, so reaching it means reaching that workflow first.
 */
const DIRECT_TRIGGERS: readonly string[] = UNTRUSTED_TRIGGERS.filter(
  (name) => name !== "workflow_run",
);

/** Owners whose actions are the platform itself; still mutable, but not a stranger's code. */
const PLATFORM_OWNERS: readonly string[] = ["actions", "github"];

/** Contexts an outside contributor controls the content of. */
const UNTRUSTED_EXPRESSIONS: readonly RegExp[] = [
  /github\.head_ref/,
  /github\.event\.issue\.(title|body)/,
  /github\.event\.pull_request\.(title|body)/,
  /github\.event\.pull_request\.head\.(ref|label)/,
  /github\.event\.pull_request\.head\.repo\./,
  /github\.event\.comment\.body/,
  /github\.event\.review\.body/,
  /github\.event\.review_comment\.body/,
  /github\.event\.discussion\.(title|body)/,
  /github\.event\.(head_commit|commits)\./,
  /github\.event\.workflow_run\.head_(branch|commit)/,
  /github\.event\.pages\./,
  /github\.event\.inputs\./,
];

/** A commit SHA, the only `uses:` reference an attacker cannot repoint. */
const COMMIT_SHA = /^[0-9a-f]{40}$/;

/** `v2.0.0-alpha.4`, `1.0.0`: a tag that names one release. */
const RELEASE_TAG = /^v?\d+\.\d+\.\d+([-+.].*)?$/;

/** `v6`, `v2.3`: a tag upstream moves forward on every release in that line. */
const PARTIAL_TAG = /^v?\d+(\.\d+)?$/;

/** Names that mark a workflow (or a job in it) as a deployment. */
const DEPLOY_NAME = /\b(deploy|release|publish|promote|rollout|cd)\b/i;

/** Shell builtins that put their argument in the job log. */
const LOGGING_COMMAND = /(^|[;&|(\s])(echo|printf|print|cat|tee|console\.log)\b/g;

/** The severities this pack uses; `info` is deliberately not one of them. */
const GRADES: readonly Severity[] = SEVERITY_ORDER.filter((severity) => severity !== "info");

/**
 * Moves a severity `steps` places along {@link GRADES} — positive is harsher —
 * clamped at `critical` and `low` so no adjustment can invent an `info`.
 */
function stepSeverity(severity: Severity, steps: number): Severity {
  const index = GRADES.indexOf(severity);
  if (index === -1) return severity;
  const moved = Math.min(Math.max(index - steps, 0), GRADES.length - 1);
  return GRADES[moved] ?? severity;
}

/** One job of a workflow, with the entry that anchors it. */
interface JobView {
  readonly id: string;
  readonly entry: YamlEntry;
  readonly node: YamlNode;
  /** True when the job hands the called workflow every secret this repo holds. */
  readonly inheritsSecrets: boolean;
}

/** One step of a job, with its position, which is what names it when it has no `name:`. */
interface StepView {
  readonly job: JobView;
  readonly index: number;
  readonly node: YamlNode;
}

/** Everything the rules need to know about one workflow file, read once. */
interface WorkflowView {
  readonly file: string;
  readonly root: YamlNode | null;
  readonly text: string;
  /** Event names the workflow subscribes to. */
  readonly triggers: readonly string[];
  /** The `on:` entry, which is the anchor for anything about the trigger. */
  readonly onEntry: YamlEntry | null;
  /** The trigger entries that an outside contributor can fire, for anchoring. */
  readonly untrustedTriggerEntries: readonly YamlEntry[];
  readonly permissions: YamlEntry | null;
  readonly concurrency: YamlEntry | null;
  readonly jobs: readonly JobView[];
  readonly referencesSecrets: boolean;
  readonly name: string;
  /** Workflow-level `env:`, so `${{ env.ACCOUNT_ID }}` can be resolved to its literal. */
  readonly env: ReadonlyMap<string, string>;
  /** The repository's own owner, lower-cased; null when it could not be resolved. */
  readonly owner: string | null;
}

/** Reads the `on:` section, which GitHub accepts as a scalar, a list or a map. */
function triggersOf(root: YamlNode | null): { names: string[]; entries: YamlEntry[] } {
  const entry = entryOf(root, "on");
  if (entry === null) return { names: [], entries: [] };
  const value = entry.value;
  if (value.kind === "mapping") {
    return { names: value.entries.map((item) => item.key), entries: [...value.entries] };
  }
  const names: string[] = [];
  for (const item of itemsOf(value)) {
    const text = textOf(item);
    if (text !== null) names.push(text.trim());
  }
  return { names, entries: [] };
}

/** Reads the jobs map into a list that keeps each job's anchor line. */
function jobsOf(root: YamlNode | null): JobView[] {
  return entriesOf(childOf(root, "jobs")).map((entry) => ({
    id: entry.key,
    entry,
    node: entry.value,
    inheritsSecrets: (textOf(childOf(entry.value, "secrets")) ?? "").trim() === "inherit",
  }));
}

/** Every step of every job, in file order. */
function stepsOf(jobs: readonly JobView[]): StepView[] {
  const steps: StepView[] = [];
  for (const job of jobs) {
    const list = asSequence(childOf(job.node, "steps"));
    if (list === null) continue;
    list.items.forEach((node, index) => steps.push({ job, index, node }));
  }
  return steps;
}

/** A step's display name, for the finding title and the stable id. */
function stepLabel(step: StepView): string {
  const name = textOf(childOf(step.node, "name"));
  if (name !== null && name.trim() !== "") return name.trim();
  const uses = textOf(childOf(step.node, "uses"));
  if (uses !== null) return uses.trim();
  return `step ${step.index + 1}`;
}

/** The workflow-level `env:` map, which is how a role ARN is spelled in these files. */
function envOf(root: YamlNode | null): Map<string, string> {
  const env = new Map<string, string>();
  for (const entry of entriesOf(childOf(root, "env"))) {
    const value = textOf(entry.value);
    if (value !== null) env.set(entry.key, value.trim());
  }
  return env;
}

/** Substitutes `${{ env.NAME }}` with the workflow-level literal, when there is one. */
export function resolveEnvExpressions(text: string, env: ReadonlyMap<string, string>): string {
  return text.replace(/\$\{\{\s*env\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}/g, (match, name: string) => {
    return env.get(name) ?? match;
  });
}

/** Builds the once-per-file view every rule reads from. */
function viewOf(file: string, text: string, owner: string | null): WorkflowView {
  const document = parseYaml(text);
  const root = document.root;
  const { names, entries } = triggersOf(root);
  const jobs = jobsOf(root);
  return {
    file,
    root,
    text,
    triggers: names,
    onEntry: entryOf(root, "on"),
    untrustedTriggerEntries: entries.filter((entry) => UNTRUSTED_TRIGGERS.includes(entry.key)),
    permissions: entryOf(root, "permissions"),
    concurrency: entryOf(root, "concurrency"),
    jobs,
    referencesSecrets: /\$\{\{\s*secrets\./.test(text) || jobs.some((job) => job.inheritsSecrets),
    name: textOf(childOf(root, "name")) ?? file,
    env: envOf(root),
    owner,
  };
}

/** True when an outside contributor can fire this workflow with secrets in scope. */
function hasUntrustedTrigger(view: WorkflowView): boolean {
  return view.triggers.some((name) => UNTRUSTED_TRIGGERS.includes(name));
}

/** The line that best proves the trigger, falling back to the `on:` key. */
function triggerLine(view: WorkflowView): number {
  return view.untrustedTriggerEntries[0]?.line ?? view.onEntry?.line ?? 1;
}

// ---------------------------------------------------------------------------
// The `uses:` reference: whose code it is, and how movable the ref is
// ---------------------------------------------------------------------------

/** Whose account has to be compromised for a `uses:` reference to change meaning. */
export type ActionTrust = "platform" | "same-owner" | "third-party";

/** How easily the thing a `uses:` ref points at can be replaced. */
export type RefMutability = "sha" | "release-tag" | "floating-tag" | "branch";

/** Parses a `uses:` reference into owner, name, git ref and the two risk axes. */
export interface ActionReference {
  readonly owner: string;
  readonly repository: string;
  readonly ref: string;
  /** `mutability === "sha"`: the only reference nobody can repoint. */
  readonly pinned: boolean;
  /** `trust === "platform"`: an `actions/*` or `github/*` action. */
  readonly firstParty: boolean;
  readonly trust: ActionTrust;
  readonly mutability: RefMutability;
  /** True for `owner/repo/.github/workflows/file.yml@ref`, a reusable workflow. */
  readonly reusableWorkflow: boolean;
}

/** Classifies a git ref by how easily the code behind it can be swapped. */
export function classifyRef(ref: string): RefMutability {
  const value = ref.trim();
  if (COMMIT_SHA.test(value)) return "sha";
  if (RELEASE_TAG.test(value)) return "release-tag";
  if (PARTIAL_TAG.test(value)) return "floating-tag";
  return "branch";
}

/** Platform, this repository's own organisation, or a stranger. */
function trustOf(owner: string, repositoryOwner: string | null): ActionTrust {
  const lower = owner.toLowerCase();
  if (PLATFORM_OWNERS.includes(lower)) return "platform";
  if (repositoryOwner !== null && lower === repositoryOwner.toLowerCase()) return "same-owner";
  return "third-party";
}

/**
 * Reads `owner/repo@ref`, or null for a local (`./`) or unparseable reference.
 *
 * `repositoryOwner` is the owner of the repository under analysis: passing it is
 * what stops `<this org>/some-action` being reported as third-party code.
 */
export function parseActionReference(
  uses: string,
  repositoryOwner: string | null = null,
): ActionReference | null {
  const value = uses.trim();
  if (value === "" || value.startsWith("./") || value.startsWith(".\\")) return null;
  if (value.startsWith("docker://")) {
    const image = value.slice("docker://".length);
    const digest = image.includes("@sha256:");
    const tag = image.split(":")[1] ?? "latest";
    return {
      owner: "docker",
      repository: image.split(":")[0] ?? image,
      ref: digest ? "sha256" : tag,
      pinned: digest,
      firstParty: false,
      trust: "third-party",
      mutability: digest ? "sha" : classifyRef(tag),
      reusableWorkflow: false,
    };
  }
  const at = value.lastIndexOf("@");
  if (at === -1) return null;
  const path = value.slice(0, at);
  const ref = value.slice(at + 1);
  const owner = path.split("/")[0] ?? "";
  if (owner === "" || !path.includes("/")) return null;
  const trust = trustOf(owner, repositoryOwner);
  const mutability = classifyRef(ref);
  return {
    owner,
    repository: path,
    ref,
    pinned: mutability === "sha",
    firstParty: trust === "platform",
    trust,
    mutability,
    reusableWorkflow: /\/\.github\/workflows\//.test(path),
  };
}

/** How a reference reads in a title: the distinction the severity model is built on. */
function trustWord(trust: ActionTrust): string {
  if (trust === "platform") return "Platform";
  return trust === "same-owner" ? "Same-organisation" : "Third-party";
}

/** How a ref reads in a sentence. */
const MUTABILITY_WORD: Readonly<Record<RefMutability, string>> = {
  sha: "a commit SHA",
  "release-tag": "an exact release tag",
  "floating-tag": "a floating major/minor tag",
  branch: "a branch",
};

/** Who has to act for the code behind the ref to change. */
function mutabilitySentence(reference: ActionReference, subject: string): string {
  switch (reference.mutability) {
    case "branch":
      return `\`${reference.ref}\` is a branch: every push to it changes what ${subject}, with no release and no review here.`;
    case "floating-tag":
      return `\`${reference.ref}\` is a floating tag: ${reference.owner} moves it forward on every release in that line.`;
    case "release-tag":
      return `\`${reference.ref}\` names one release, so it changes only if ${reference.owner} force-moves the tag.`;
    default:
      return `\`${reference.ref}\` is a commit SHA and cannot be repointed.`;
  }
}

// ---------------------------------------------------------------------------
// The credential a step is handed
// ---------------------------------------------------------------------------

/** What a credential buys whoever gets hold of it. */
export type CredentialClass = "auto-token" | "narrow" | "broad";

/**
 * Secrets whose name says they are one notification channel. A webhook URL buys
 * a stranger the ability to post in one Slack channel; it is not the repository.
 */
const NARROW_CREDENTIAL = /(^|_)(slack|discord|teams|mattermost|webhook|notification)(_|$)/i;

/**
 * Grades the credential behind a `${{ secrets.NAME }}` reference.
 *
 * `GITHUB_TOKEN` is the installation token GitHub mints for the job, scoped by
 * the workflow's `permissions:` block and revoked when the job ends. Every step
 * in the job can already read it — `actions/checkout` even persists it into
 * `.git/config` — so "handed to a step" is not a disclosure, and grading it like a
 * long-lived PAT turns every ordinary `with: token: ${{ secrets.GITHUB_TOKEN }}`
 * into a finding a reader can do nothing about.
 */
export function credentialClass(name: string): CredentialClass {
  const upper = name.trim().toUpperCase();
  if (upper === "GITHUB_TOKEN") return "auto-token";
  if (NARROW_CREDENTIAL.test(name)) return "narrow";
  return "broad";
}

/** Every `${{ ... }}` expression in a string. */
function expressionsIn(text: string): string[] {
  return [...text.matchAll(/\$\{\{([^}]*)\}\}/g)].map((match) => (match[1] ?? "").trim());
}

/** True when the expression resolves to something an outside contributor writes. */
export function isUntrustedExpression(expression: string): boolean {
  return UNTRUSTED_EXPRESSIONS.some((pattern) => pattern.test(expression));
}

/** Collects the untrusted expressions on one line of a script. */
function untrustedOn(text: string): string[] {
  return expressionsIn(text).filter(isUntrustedExpression);
}

/** The first `secrets.NAME` on a line, or null. */
function secretNameOn(text: string): { name: string; index: number } | null {
  const match = /\$\{\{\s*secrets\.([A-Za-z0-9_]+)/.exec(text);
  if (match === null || match[1] === undefined) return null;
  return { name: match[1], index: match.index };
}

/** Recursively collects every scalar under a node, with its line. */
function scalarsUnder(node: YamlNode | null, out: Array<{ line: number; text: string }>): void {
  if (node === null) return;
  if (node.kind === "scalar") {
    if (node.style !== "empty") out.push({ line: node.line, text: node.value });
    return;
  }
  if (node.kind === "sequence") {
    for (const item of node.items) scalarsUnder(item, out);
    return;
  }
  for (const entry of node.entries) scalarsUnder(entry.value, out);
}

/** The value of the first `key:` found anywhere under a node, with its line. */
function deepEntry(
  node: YamlNode | null,
  key: string,
): { line: number; value: YamlNode; text: string | null } | null {
  if (node === null) return null;
  if (node.kind === "sequence") {
    for (const item of node.items) {
      const hit = deepEntry(item, key);
      if (hit !== null) return hit;
    }
    return null;
  }
  if (node.kind !== "mapping") return null;
  for (const entry of node.entries) {
    if (entry.key === key)
      return { line: entry.line, value: entry.value, text: textOf(entry.value) };
  }
  for (const entry of node.entries) {
    const hit = deepEntry(entry.value, key);
    if (hit !== null) return hit;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Shell structure: does the value actually reach the job log?
// ---------------------------------------------------------------------------

/** Where the stdout of one command in a `run:` script goes. */
export interface StdoutDisposition {
  /** `log` is the only one a reader of the workflow run can see. */
  readonly target: "log" | "file" | "pipe";
  /** The redirection target, or the command the output is piped into. */
  readonly sink: string | null;
}

/** Targets that are rendered on the run page, so writing to them is still a leak. */
const LOGGED_SINKS: readonly string[] = ["$GITHUB_STEP_SUMMARY", "${GITHUB_STEP_SUMMARY}"];

/**
 * Reads the shell structure of one line of a `run:` script and says where the
 * stdout of the command containing `from` goes.
 *
 * Only an unredirected write to fd 1 or fd 2 reaches the job log. `>>
 * .npmrc` writes a file, `| base64` hands the bytes to another process, and
 * `> /dev/null` discards them — none of those is a log line. Redirecting to
 * `$GITHUB_STEP_SUMMARY` is a log line, because GitHub renders it on the run
 * page, and `>&2` is one too.
 */
export function stdoutDispositionOf(line: string, from = 0): StdoutDisposition {
  let quote: string | null = null;
  for (let index = from; index < line.length; index += 1) {
    const char = line[index];
    if (quote !== null) {
      if (char === "\\" && quote === '"') {
        index += 1;
        continue;
      }
      if (char === quote) quote = null;
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }
    // A new command starts here, so the one that held the secret has ended.
    if (char === ";") break;
    if (char === "&" && line[index + 1] === "&") break;
    if (char === "|" && line[index + 1] === "|") break;
    if (char === "|") {
      const consumer =
        line
          .slice(index + 1)
          .trim()
          .split(/\s+/)[0] ?? "";
      // `tee` prints what it writes, so a pipe into it still lands in the log.
      if (/^tee$/.test(consumer)) return { target: "log", sink: consumer };
      return { target: "pipe", sink: consumer === "" ? null : consumer };
    }
    if (char === ">") {
      const rest = line.slice(index).replace(/^>+/, "").trim();
      // `>&2`, `1>&2`: still a file descriptor the log collects.
      if (rest.startsWith("&")) return { target: "log", sink: `>${rest.split(/\s+/)[0] ?? ""}` };
      const sink = rest.split(/\s+/)[0] ?? "";
      if (LOGGED_SINKS.includes(sink)) return { target: "log", sink };
      return { target: "file", sink: sink === "" ? null : sink };
    }
  }
  return { target: "log", sink: null };
}

/** The logging command that most closely precedes `index`, or null. */
function loggingCommandBefore(line: string, index: number): { command: string; at: number } | null {
  LOGGING_COMMAND.lastIndex = 0;
  let found: { command: string; at: number } | null = null;
  for (;;) {
    const match = LOGGING_COMMAND.exec(line);
    if (match === null) break;
    const at = match.index + (match[1]?.length ?? 0);
    if (at > index) break;
    found = { command: match[2] ?? "echo", at };
  }
  LOGGING_COMMAND.lastIndex = 0;
  return found;
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

/**
 * **The severity model for a mutable `uses:` ref.** Two axes and nothing else,
 * so the same reference gets the same grade in every file of the repository.
 *
 * | ref | third-party | same organisation |
 * |---|---|---|
 * | branch (`@main`) | high | medium |
 * | floating tag (`@v6`) | medium | low |
 * | exact release tag (`@v2.0.0`) | low | low |
 *
 * A commit SHA is not a finding at all, and a platform (`actions/*`) reference
 * is rolled up once per file by {@link platformActions} rather than graded here.
 * One step harsher when the step is *also* handed a broad credential, because
 * then repointing the ref is worth doing.
 */
const UNPINNED_SEVERITY: Readonly<
  Record<
    "third-party" | "same-owner",
    Readonly<Record<"branch" | "floating-tag" | "release-tag", Severity>>
  >
> = {
  "third-party": { branch: "high", "floating-tag": "medium", "release-tag": "low" },
  "same-owner": { branch: "medium", "floating-tag": "low", "release-tag": "low" },
};

/** The broadest credential this step (or its job) hands to the action, if any. */
function credentialOf(step: StepView): { name: string; class: CredentialClass } | null {
  if (step.job.inheritsSecrets) return { name: "inherit", class: "broad" };
  const inputs: Array<{ line: number; text: string }> = [];
  scalarsUnder(childOf(step.node, "with"), inputs);
  scalarsUnder(childOf(step.node, "env"), inputs);
  let best: { name: string; class: CredentialClass } | null = null;
  for (const input of inputs) {
    const secret = secretNameOn(input.text);
    if (secret === null) continue;
    const grade = credentialClass(secret.name);
    if (best === null || grade === "broad") best = { name: secret.name, class: grade };
  }
  return best;
}

/** Every `uses:` in the file: step-level actions and job-level reusable workflows. */
interface UsesSite {
  readonly entry: YamlEntry;
  readonly uses: string;
  readonly reference: ActionReference;
  /** The step, when the `uses:` is a step's; null for a job-level reusable workflow. */
  readonly step: StepView | null;
  readonly job: JobView;
  readonly credential: { name: string; class: CredentialClass } | null;
}

/**
 * Collects every `uses:` reference in the workflow.
 *
 * Job-level `uses:` is included, which it was not before: a reusable workflow
 * called as `owner/repo/.github/workflows/x.yml@main` with `secrets: inherit`
 * is the most movable reference a repository can hold, so a collector that walks
 * only step-level `uses:` misses the worst case in the file while escalating
 * every exact-tagged webhook action it does see.
 */
function usesSites(view: WorkflowView, steps: readonly StepView[]): UsesSite[] {
  const sites: UsesSite[] = [];
  for (const job of view.jobs) {
    const entry = entryOf(job.node, "uses");
    const uses = entry === null ? null : textOf(entry.value);
    if (entry === null || uses === null || uses.includes("${{")) continue;
    const reference = parseActionReference(uses, view.owner);
    if (reference === null) continue;
    sites.push({
      entry,
      uses,
      reference,
      step: null,
      job,
      credential: job.inheritsSecrets ? { name: "inherit", class: "broad" } : null,
    });
  }
  for (const step of steps) {
    const entry = entryOf(step.node, "uses");
    const uses = entry === null ? null : textOf(entry.value);
    if (entry === null || uses === null || uses.includes("${{")) continue;
    const reference = parseActionReference(uses, view.owner);
    if (reference === null) continue;
    sites.push({
      entry,
      uses,
      reference,
      step,
      job: step.job,
      credential: credentialOf(step),
    });
  }
  return sites;
}

/** How a site reads in a finding: a named step, or the job that calls a workflow. */
function siteLabel(site: UsesSite): string {
  return site.step === null
    ? `Job "${site.job.id}"`
    : `Step "${stepLabel(site.step)}" in job "${site.job.id}"`;
}

/** The noun for what the reference runs, so a job-level `uses:` is not called a step. */
function siteNoun(site: UsesSite): string {
  return site.step === null ? "this job calls" : "this step runs";
}

/** The symbol that identifies a site across runs. */
function siteSymbol(site: UsesSite): string {
  return site.step === null
    ? `${site.job.id}:uses:${site.reference.repository}`
    : `${site.job.id}:${site.step.index}:${site.reference.repository}`;
}

/** Actions and reusable workflows referenced by a movable ref instead of a SHA. */
function unpinnedActions(view: WorkflowView, sites: readonly UsesSite[]): Finding[] {
  const findings: Finding[] = [];
  for (const site of sites) {
    const reference = site.reference;
    if (reference.mutability === "sha" || reference.trust === "platform") continue;
    const base = UNPINNED_SEVERITY[reference.trust][reference.mutability];
    const broad = site.credential?.class === "broad";
    const severity = broad ? stepSeverity(base, 1) : base;
    const kind = reference.reusableWorkflow ? "reusable workflow" : "action";
    findings.push(
      buildFinding({
        rule: RULE.unpinnedAction,
        severity,
        confidence: "high",
        title: `${trustWord(reference.trust)} ${kind} ${reference.repository} is pinned to ${MUTABILITY_WORD[reference.mutability]}, not a commit SHA`,
        description: `${siteLabel(site)} runs ${site.uses}. ${mutabilitySentence(reference, siteNoun(site))} ${
          reference.trust === "same-owner"
            ? `\`${reference.owner}\` is this repository's own organisation, so moving the ref needs org write access — which already implies access here; that is why this is graded below the same shape from a stranger.`
            : `\`${reference.owner}\` is outside this repository's organisation, so nobody here has to act for the code to change.`
        }${
          broad
            ? ` Graded one step higher because the ${site.credential?.name === "inherit" ? "job passes `secrets: inherit`" : `step also hands it \`secrets.${site.credential?.name}\``}, which makes repointing the ref worth doing.`
            : ""
        }`,
        file: view.file,
        line: site.entry.line,
        symbol: siteSymbol(site),
        exploitability: `Requires whoever controls \`${reference.owner}\` — or anyone who takes over an account there — to move \`${reference.ref}\`. ${
          hasUntrustedTrigger(view)
            ? "This workflow is reachable by an event an outside contributor can influence, so the compromised code runs without any maintainer action."
            : "The workflow runs on repository events only, so the change lands on the next internal run."
        }`,
        impact:
          "A silent upstream change executes in CI with the job's token and every secret it is handed, which is enough to publish artifacts or to exfiltrate those secrets.",
        recommendation: `Pin to a full commit SHA — \`uses: ${reference.repository}@<40-char sha> # ${reference.ref}\` — and let Dependabot propose the bumps.`,
        acceptanceCriteria: [
          `\`${reference.repository}\` in ${view.file} references a 40-character commit SHA`,
          "The previous tag is kept as a trailing comment so the version stays readable",
        ],
        cwe: ["CWE-494", "CWE-1357"],
        source: { kind: "rule", name: CI_RULES_STEP },
      }),
    );
  }
  return findings;
}

/**
 * Platform (`actions/*`, `github/*`) references on a movable tag, rolled up into
 * one finding for the file.
 *
 * They used to be skipped outright. They are a real, if small, supply-chain
 * fact — `actions/checkout@v7` is a tag GitHub can move — but one per step would
 * bury the rule that matters, so the file gets a single `low` with every
 * occurrence in `evidence`.
 */
function platformActions(view: WorkflowView, sites: readonly UsesSite[]): Finding[] {
  const movable = sites.filter(
    (site) => site.reference.trust === "platform" && site.reference.mutability !== "sha",
  );
  if (movable.length === 0) return [];
  const refs = [...new Set(movable.map((site) => site.uses))].sort();
  return [
    buildFinding({
      rule: RULE.unpinnedPlatformAction,
      severity: "low",
      confidence: "high",
      title: `${movable.length} platform action reference(s) are pinned to a tag rather than a commit SHA`,
      description: `${view.file} uses ${refs.map((ref) => `\`${ref}\``).join(", ")}. These are GitHub's own actions, so the account that would have to be compromised is the platform's rather than a third party's — which is why this is one \`low\` finding for the file instead of one per step — but the tags are still mutable references.`,
      file: view.file,
      line: movable[0]?.entry.line ?? 1,
      symbol: "platform-actions",
      evidence: movable.slice(0, 20).map((site) => ({
        file: view.file,
        line: site.entry.line,
        note: site.uses,
      })),
      exploitability:
        "Requires a compromise of the `actions`/`github` organisation, or of the release process behind one of its tags.",
      impact:
        "A moved tag would run new code in every job that uses it, with that job's token; the blast radius is the same as any other action, only the publisher is harder to compromise.",
      recommendation:
        "If the repository's threat model calls for reproducible CI, pin these to commit SHAs as well; otherwise record the decision to trust the platform's tags so the gap is deliberate.",
      acceptanceCriteria: [
        `The decision about platform-action pinning in ${view.file} is deliberate and written down`,
      ],
      cwe: ["CWE-1357"],
      source: { kind: "rule", name: CI_RULES_STEP },
    }),
  ];
}

/** `pull_request_target` (or `workflow_run`) combined with a checkout of the PR head. */
function targetCheckout(view: WorkflowView, steps: readonly StepView[]): Finding[] {
  const dangerous = view.triggers.filter(
    (name) => name === "pull_request_target" || name === "workflow_run",
  );
  if (dangerous.length === 0) return [];

  const findings: Finding[] = [];
  for (const step of steps) {
    const uses = textOf(childOf(step.node, "uses")) ?? "";
    const isCheckout = /(^|\/)checkout(@|$)/.test(uses);
    const withNode = childOf(step.node, "with");
    const candidates: Array<{ line: number; text: string }> = [];
    if (isCheckout) scalarsUnder(withNode, candidates);
    const run = childOf(step.node, "run");
    for (const hit of linesMatching(
      run,
      /github\.event\.(pull_request\.head|workflow_run\.head)/,
    )) {
      candidates.push(hit);
    }

    const hit = candidates.find((candidate) =>
      /github\.(event\.(pull_request\.head|workflow_run\.head)|head_ref)/.test(candidate.text),
    );
    if (hit === undefined) continue;

    findings.push(
      buildFinding({
        rule: RULE.targetCheckout,
        severity: "critical",
        confidence: "high",
        title: `${dangerous[0] ?? "pull_request_target"} workflow checks out the untrusted pull-request head`,
        description: `Job "${step.job.id}" runs on the \`${dangerous.join("/")}\` trigger — which executes on the base branch with the repository's secrets — and step "${stepLabel(step)}" checks out code from the pull request itself.`,
        file: view.file,
        line: hit.line,
        symbol: `${step.job.id}:${step.index}`,
        exploitability:
          "Any outside contributor opening a pull request. No approval is required for the workflow to run, and nothing in the diff has to look malicious — a build script or a test helper is enough.",
        impact:
          "Attacker-supplied code executes in a job that holds every repository secret and a write-capable GITHUB_TOKEN. This is a full repository compromise, including the ability to publish releases.",
        recommendation:
          "Split the workflow: run untrusted code under `pull_request` (no secrets), and do the privileged part in a separate `workflow_run` job that checks out the base branch only and consumes the first job's artifacts.",
        acceptanceCriteria: [
          `No \`pull_request_target\` job in ${view.file} checks out \`github.event.pull_request.head\``,
          "Any job that does build pull-request code runs without repository secrets",
        ],
        cwe: ["CWE-94", "CWE-829"],
        owasp: ["A08:2021-Software and Data Integrity Failures"],
        source: { kind: "rule", name: CI_RULES_STEP },
      }),
    );
  }
  return findings;
}

/** Untrusted context values interpolated straight into a `run:` script. */
function scriptInjection(view: WorkflowView, steps: readonly StepView[]): Finding[] {
  const findings: Finding[] = [];
  for (const step of steps) {
    const run = childOf(step.node, "run");
    for (const hit of linesMatching(run, /\$\{\{/)) {
      const expressions = untrustedOn(hit.text);
      const expression = expressions[0];
      if (expression === undefined) continue;
      findings.push(
        buildFinding({
          rule: RULE.scriptInjection,
          severity: "high",
          confidence: "high",
          title: `Untrusted \`${expression}\` is interpolated into a run: script`,
          description: `Step "${stepLabel(step)}" in job "${step.job.id}" builds its shell script by substituting \`${expression}\` into the command text before the shell parses it. GitHub performs that substitution textually, so the value is code, not data.`,
          file: view.file,
          line: hit.line,
          symbol: `${step.job.id}:${step.index}:${expression}`,
          exploitability:
            "No credentials needed: whoever can set that field — a pull-request title, an issue body, a branch name — chooses what the runner executes.",
          impact:
            "Arbitrary command execution on the runner with the job's secrets and GITHUB_TOKEN in the environment, and on a self-hosted runner, on the host itself.",
          recommendation: `Bind the value to an environment variable on the step (\`env: { VALUE: \${{ ${expression} }} }\`) and reference it as \`"$VALUE"\` in the script, so the shell receives it as data.`,
          acceptanceCriteria: [
            `No \`run:\` block in ${view.file} contains a \`\${{ github.event.* }}\` or \`\${{ github.head_ref }}\` interpolation`,
            "Values that the script needs are passed through `env:` and quoted at the point of use",
          ],
          cwe: ["CWE-94", "CWE-78"],
          owasp: ["A03:2021-Injection"],
          source: { kind: "rule", name: CI_RULES_STEP },
        }),
      );
    }
  }
  return findings;
}

/** Collects the `scope: write` grants of a `permissions:` mapping. */
function writeScopes(node: YamlNode | null): string[] {
  return entriesOf(node)
    .filter((entry) => (textOf(entry.value) ?? "").trim() === "write")
    .map((entry) => entry.key);
}

/**
 * Write scopes that let the token change the repository. `id-token: write` is
 * not one of them: it mints an OIDC assertion for a cloud role, which is a
 * different prize and is named as such in {@link prizeOf}.
 */
const REPOSITORY_WRITE_SCOPES: readonly string[] = [
  "contents",
  "packages",
  "pull-requests",
  "issues",
  "actions",
  "deployments",
  "pages",
  "statuses",
  "checks",
  "security-events",
  "discussions",
];

/** Over-broad, or entirely undeclared, token permissions. */
function permissions(view: WorkflowView): Finding[] {
  const findings: Finding[] = [];
  const untrusted = hasUntrustedTrigger(view);
  const entry = view.permissions;

  if (entry === null) {
    const jobsWithout = view.jobs.filter((job) => entryOf(job.node, "permissions") === null);
    if (view.jobs.length > 0 && jobsWithout.length > 0) {
      findings.push(
        buildFinding({
          rule: RULE.permissionsUndeclared,
          severity: untrusted ? "high" : "medium",
          confidence: "high",
          title:
            "Workflow declares no `permissions:`, so GITHUB_TOKEN inherits the repository default",
          description: `${view.file} sets no \`permissions:\` at workflow level, and ${jobsWithout.length} of ${view.jobs.length} job(s) set none either. The token those jobs receive is whatever the repository or organisation default is — historically read-write on every scope.`,
          file: view.file,
          line: view.onEntry?.line ?? 1,
          symbol: "workflow",
          impact:
            "Every step, including third-party actions, runs with a token that can push commits, publish packages and edit issues, so one compromised dependency inherits write access to the repository.",
          recommendation:
            "Add `permissions: contents: read` at the top of the workflow and grant the extra scopes only on the individual jobs that need them.",
          acceptanceCriteria: [
            `${view.file} declares an explicit \`permissions:\` block`,
            "Any write scope is granted on a single job rather than workflow-wide",
          ],
          cwe: ["CWE-250", "CWE-732"],
          source: { kind: "rule", name: CI_RULES_STEP },
        }),
      );
    }
    return findings;
  }

  const literal = (textOf(entry.value) ?? "").trim();
  if (literal === "write-all") {
    findings.push(
      buildFinding({
        rule: RULE.permissionsWriteAll,
        severity: "high",
        confidence: "high",
        title: "Workflow grants `permissions: write-all`",
        description: `${view.file} hands every job a GITHUB_TOKEN with write access to every scope, which is the widest token GitHub will issue.`,
        file: view.file,
        line: entry.line,
        symbol: "write-all",
        exploitability: untrusted
          ? "The workflow is reachable by an outside contributor, so any injection or compromised action in it starts with full write access."
          : "Requires a compromised step or action inside the workflow.",
        impact:
          "A single compromised step can push to protected-branch-adjacent refs, publish packages, rewrite issues and pull requests, and alter workflow files.",
        recommendation:
          "Replace `write-all` with the smallest set of scopes each job needs, starting from `contents: read`.",
        acceptanceCriteria: [`${view.file} no longer grants \`write-all\``],
        cwe: ["CWE-250", "CWE-732"],
        source: { kind: "rule", name: CI_RULES_STEP },
      }),
    );
    return findings;
  }

  const scopes = writeScopes(entry.value);
  if (scopes.length > 0) {
    findings.push(
      buildFinding({
        rule: RULE.permissionsWorkflowWide,
        severity: untrusted ? "medium" : "low",
        confidence: "high",
        title: `Write scope(s) ${scopes.join(", ")} are granted workflow-wide`,
        description: `${view.file} grants \`${scopes.join("`, `")}: write\` at workflow level, so every job — including ones that only run tests — receives the write-capable token.`,
        file: view.file,
        line: entry.line,
        symbol: scopes.join(","),
        impact:
          "Least privilege is lost across the whole workflow: a compromised step in any job can use a token it never needed.",
        recommendation:
          "Keep the workflow-level block read-only and move each write scope onto the one job that needs it.",
        acceptanceCriteria: [
          `Workflow-level \`permissions:\` in ${view.file} grants no write scope`,
          "Jobs that publish or push declare their own `permissions:`",
        ],
        cwe: ["CWE-732"],
        source: { kind: "rule", name: CI_RULES_STEP },
      }),
    );
  }
  return findings;
}

/** Secrets interpolated into a `run:` script: a log leak, or a command line. */
function secretsInScripts(view: WorkflowView, steps: readonly StepView[]): Finding[] {
  const findings: Finding[] = [];
  for (const step of steps) {
    const run = childOf(step.node, "run");
    for (const hit of linesMatching(run, /\$\{\{\s*secrets\./)) {
      const secret = secretNameOn(hit.text);
      const name = secret?.name ?? "a repository secret";
      const logger = secret === null ? null : loggingCommandBefore(hit.text, secret.index);
      const disposition =
        logger === null ? null : stdoutDispositionOf(hit.text, logger.at + logger.command.length);
      const logged = disposition !== null && disposition.target === "log";
      const sink = disposition?.sink ?? null;
      findings.push(
        buildFinding({
          rule: logged ? RULE.secretEchoed : RULE.secretInRun,
          severity: logged ? "high" : "medium",
          confidence: logged ? "high" : "medium",
          title: logged
            ? `Secret \`${name}\` is written to the job log`
            : `Secret \`${name}\` is interpolated into a shell command line`,
          description: logged
            ? `Step "${stepLabel(step)}" in job "${step.job.id}" passes \`secrets.${name}\` to \`${logger?.command ?? "echo"}\`, whose stdout is not redirected${sink === null ? "" : ` (it goes to \`${sink}\`, which GitHub renders on the run page)`}, so the value lands in the job log. GitHub masks exact matches, but any transformation — base64, a substring, a URL-encode — defeats the mask.`
            : `Step "${stepLabel(step)}" in job "${step.job.id}" splices \`secrets.${name}\` into the script text, so the value appears in the command line, in \`set -x\` traces and in any process listing on the runner.${
                logger === null
                  ? ""
                  : ` It is *not* written to the job log: the \`${logger.command}\` on this line has its stdout ${disposition?.target === "file" ? `redirected into ${sink === null ? "a file" : `\`${sink}\``}` : `piped into \`${sink ?? "another command"}\``}, which is why this is reported here rather than as \`${RULE.secretEchoed}\`.`
              }`,
          file: view.file,
          line: hit.line,
          symbol: `${step.job.id}:${step.index}:${name}`,
          exploitability: logged
            ? "Anyone who can read the workflow run; on a public repository that is everyone, and the log outlives the run."
            : `Requires something that can observe the runner while the step runs — a \`set -x\` trace, the process table, another step in the same job — or read access to ${sink === null ? "what the command writes" : `\`${sink}\``}.`,
          impact: logged
            ? `${name} leaks to anyone who can read the workflow run, which on a public repository is everyone; the credential then has to be rotated.`
            : `${name} is exposed to anything that can read the runner's process table or a shell trace for the length of the step, and to whatever the command writes it into; the blast radius is the runner, not the run page.`,
          recommendation:
            logged || sink === null
              ? 'Pass the secret through `env:` on the step and reference it as `"$NAME"`, and never pipe it into a command that echoes its arguments.'
              : `Pass the secret through \`env:\` on the step and write \`${sink}\` with a \`\${VAR}\` reference instead of the value — npm, docker and most consumers expand the variable when they read the file — so the secret is never part of a command line.`,
          acceptanceCriteria: [
            `No \`run:\` block in ${view.file} interpolates \`\${{ secrets.* }}\` directly`,
            "Secrets reach the script through `env:` only",
          ],
          cwe: logged ? ["CWE-532", "CWE-522"] : ["CWE-214", "CWE-522"],
          source: { kind: "rule", name: CI_RULES_STEP },
        }),
      );
    }
  }
  return findings;
}

/** Severity for a secret handed to an action, by whose code it is and what the secret buys. */
const SECRET_TO_ACTION_SEVERITY: Readonly<
  Record<"third-party" | "same-owner", Readonly<Record<"broad" | "narrow", Severity>>>
> = {
  "third-party": { broad: "high", narrow: "medium" },
  "same-owner": { broad: "medium", narrow: "low" },
};

/** Secrets handed to code Sentinel cannot see. */
function secretToAction(
  view: WorkflowView,
  sites: readonly UsesSite[],
  suppressed: SuppressionNote[],
): Finding[] {
  const findings: Finding[] = [];
  for (const site of sites) {
    const reference = site.reference;
    if (reference.trust === "platform") continue;
    if (site.step === null) continue;
    const inputs: Array<{ line: number; text: string }> = [];
    scalarsUnder(childOf(site.step.node, "with"), inputs);
    scalarsUnder(childOf(site.step.node, "env"), inputs);
    const hit = inputs.find((input) => /\$\{\{\s*secrets\./.test(input.text));
    if (hit === undefined) continue;
    const secret = secretNameOn(hit.text);
    const name = secret?.name ?? "a repository secret";
    const grade = secret === null ? "broad" : credentialClass(secret.name);

    if (grade === "auto-token") {
      suppressed.push({
        rule: RULE.secretToThirdParty,
        file: view.file,
        line: hit.line,
        reason: `\`secrets.GITHUB_TOKEN\` is the installation token GitHub mints for this job, scoped by the workflow's \`permissions:\` block and revoked at job end; every step in the job can already read it, so handing it to \`${reference.repository}\` discloses nothing new. The token's scope is graded by the \`permissions:\` rules instead.`,
      });
      continue;
    }

    const base = SECRET_TO_ACTION_SEVERITY[reference.trust][grade];
    const severity = reference.mutability === "sha" ? stepSeverity(base, -1) : base;
    const sameOwner = reference.trust === "same-owner";
    findings.push(
      buildFinding({
        rule: sameOwner ? RULE.secretToSameOwner : RULE.secretToThirdParty,
        severity,
        confidence: "high",
        title: `Secret \`${name}\` is handed to ${sameOwner ? "same-organisation" : "third-party"} action ${reference.repository}`,
        description: `${siteLabel(site)} passes \`secrets.${name}\` to \`${site.uses}\`, code Sentinel cannot see and that is pinned to ${MUTABILITY_WORD[reference.mutability]}. ${
          sameOwner
            ? `\`${reference.owner}\` is this repository's own organisation, so the secret does not cross an organisational trust boundary; what remains is that the ref can be repointed by anyone with org write access.`
            : `\`${reference.owner}\` is outside this repository's organisation, so the secret crosses a trust boundary the repository does not control.`
        } ${
          grade === "narrow"
            ? `\`${name}\` reads as a single-channel notification credential, which buys an attacker messages in one channel rather than access to this repository — that is what separates it from a repository-scoped token.`
            : `\`${name}\` is not a single-channel credential, so it has to be assumed to buy whatever it authenticates.`
        }`,
        file: view.file,
        line: hit.line,
        symbol: `${site.job.id}:${site.step.index}:${name}`,
        exploitability:
          reference.mutability === "sha"
            ? "Requires the pinned commit itself to be malicious."
            : `Requires whoever controls \`${reference.owner}\` to move \`${reference.ref}\`, after which the secret is readable on the next run.`,
        impact: `${name} is readable by that code for the duration of the step, with outbound network access available to send it anywhere.${
          grade === "narrow"
            ? " For a notification webhook the loss is the channel, not the repository."
            : ""
        }`,
        recommendation: `Pin ${reference.repository} to a commit SHA, and keep ${name} the narrowest credential that works${grade === "broad" ? " — a fine-grained token scoped to exactly what this step needs" : ""}.`,
        acceptanceCriteria: [
          `${reference.repository} is pinned to a commit SHA`,
          `The credential behind ${name} is scoped to only what this step needs`,
        ],
        cwe: ["CWE-522", "CWE-1357"],
        source: { kind: "rule", name: CI_RULES_STEP },
      }),
    );
  }
  return findings;
}

/** Deploy workflows without a concurrency group, which lets two releases race. */
function missingConcurrency(view: WorkflowView): Finding[] {
  if (view.concurrency !== null) return [];
  const findings: Finding[] = [];
  for (const job of view.jobs) {
    if (entryOf(job.node, "concurrency") !== null) continue;
    const jobName = textOf(childOf(job.node, "name")) ?? job.id;
    const environment = entryOf(job.node, "environment");
    const looksLikeDeploy =
      environment !== null ||
      DEPLOY_NAME.test(job.id) ||
      DEPLOY_NAME.test(jobName) ||
      DEPLOY_NAME.test(view.name) ||
      DEPLOY_NAME.test(view.file);
    if (!looksLikeDeploy) continue;
    findings.push(
      buildFinding({
        rule: RULE.missingConcurrency,
        severity: "medium",
        confidence: environment !== null ? "high" : "medium",
        title: `Deployment job "${job.id}" declares no \`concurrency:\` group`,
        description: `Job "${job.id}" in ${view.file} deploys${environment === null ? "" : ` to the \`${textOf(environment.value) ?? "declared"}\` environment`} and neither it nor the workflow declares a concurrency group, so two pushes in quick succession deploy in parallel.`,
        file: view.file,
        line: job.entry.line,
        symbol: job.id,
        impact:
          "Two runs can write the same environment at once; the slower one finishes last and the environment ends up on the older commit, with no error anywhere.",
        recommendation:
          "Add `concurrency: { group: <workflow>-<environment or ref>, cancel-in-progress: false }` so deployments queue instead of racing.",
        acceptanceCriteria: [
          `Job "${job.id}" runs under a concurrency group keyed by its target environment`,
          "A second run queues behind the first rather than starting alongside it",
        ],
        cwe: ["CWE-362"],
        source: { kind: "rule", name: CI_RULES_STEP },
      }),
    );
  }
  return findings;
}

/** Self-hosted runners, which do not get a fresh machine between jobs. */
function selfHostedRunners(view: WorkflowView): Finding[] {
  const findings: Finding[] = [];
  const untrusted = hasUntrustedTrigger(view);
  for (const job of view.jobs) {
    const entry = entryOf(job.node, "runs-on");
    if (entry === null) continue;
    const labels: string[] = [];
    const direct = textOf(entry.value);
    if (direct !== null) labels.push(direct);
    for (const item of itemsOf(childOf(entry.value, "labels") ?? entry.value)) {
      const text = textOf(item);
      if (text !== null) labels.push(text);
    }
    if (!labels.some((label) => label.trim().toLowerCase() === "self-hosted")) continue;
    findings.push(
      buildFinding({
        rule: RULE.selfHostedRunner,
        severity: untrusted ? "high" : "medium",
        confidence: "high",
        title: `Job "${job.id}" runs on a self-hosted runner`,
        description: `Job "${job.id}" in ${view.file} targets \`self-hosted\`. Unlike a GitHub-hosted runner, a self-hosted machine is not destroyed after the job, so anything a job writes to disk, to the tool cache or to the environment is visible to the next job that lands on it.`,
        file: view.file,
        line: entry.line,
        symbol: job.id,
        exploitability: untrusted
          ? "This workflow can be fired by an outside contributor, so untrusted code reaches your own hardware."
          : "Requires code to reach the runner through a branch or a dependency.",
        impact:
          "Persistence on infrastructure you own: credentials cached by an earlier job, network reachability into your private ranges, and a foothold that outlives the workflow run.",
        recommendation:
          "Use ephemeral (just-in-time) runners in an isolated network, keep them off any workflow an outside contributor can trigger, and never run fork code on them.",
        acceptanceCriteria: [
          `The runner behind job "${job.id}" is ephemeral and is destroyed after each job`,
          "No workflow reachable by an outside contributor targets a self-hosted label",
        ],
        cwe: ["CWE-1188"],
        source: { kind: "rule", name: CI_RULES_STEP },
      }),
    );
  }
  return findings;
}

/** What the token this workflow issues is actually worth, read from `permissions:`. */
function prizeOf(view: WorkflowView): string {
  const entry = view.permissions;
  const literal = (textOf(entry?.value ?? null) ?? "").trim();
  if (entry === null || literal === "write-all") {
    return "every repository secret and a GITHUB_TOKEN whose scopes are the repository default (historically write on every scope), which is enough to push commits and publish releases";
  }
  const scopes = writeScopes(entry.value);
  const repositoryWrites = scopes.filter((scope) => REPOSITORY_WRITE_SCOPES.includes(scope));
  const role = deepEntry(childOf(view.root, "jobs"), "role-to-assume");
  const arn =
    role?.text === null || role?.text === undefined
      ? null
      : resolveEnvExpressions(role.text, view.env);
  const oidc = scopes.includes("id-token");
  const parts: string[] = [];
  if (repositoryWrites.length > 0) {
    parts.push(
      `a GITHUB_TOKEN with \`${repositoryWrites.join("`, `")}: write\`, which can change the repository`,
    );
  }
  if (oidc) {
    parts.push(
      arn === null
        ? "an OIDC assertion (`id-token: write`) that a cloud provider will exchange for a role"
        : `an OIDC assertion (\`id-token: write\`) that is exchanged for \`${arn}\``,
    );
  }
  if (view.referencesSecrets) parts.push("the repository secrets the jobs read");
  if (parts.length === 0) return "the repository secrets this workflow reads";
  return parts.join(", plus ");
}

/** True when the `workflow_run` filter admits only runs whose head branch is named. */
function namedBranchFilter(view: WorkflowView): string[] {
  const entry = view.untrustedTriggerEntries.find((candidate) => candidate.key === "workflow_run");
  if (entry === undefined) return [];
  const branches: string[] = [];
  for (const item of itemsOf(childOf(entry.value, "branches"))) {
    const text = textOf(item);
    if (text === null) return [];
    const value = text.trim();
    if (value === "" || /[*?\[]/.test(value)) return [];
    branches.push(value);
  }
  return branches;
}

/**
 * A workflow an outside contributor can reach that also holds repository secrets.
 *
 * Graded from two facts, not one. The trigger alone is `medium`: `workflow_run`
 * with secrets is the shape GitHub itself recommends for privileged post-PR work,
 * and a `branches:` filter on it means the upstream run has to have happened on a
 * branch with that name. It reaches `high` only when the token the workflow hands
 * out can change the repository. And when a stricter rule in this same file
 * already reports the exploitable second fact — a checkout of the event's head, or
 * an event value interpolated into a script — this finding names it instead of
 * repeating the claim at its own severity.
 */
function untrustedTriggerWithSecrets(view: WorkflowView, reported: readonly Finding[]): Finding[] {
  if (!hasUntrustedTrigger(view)) return [];
  const writeAll = (textOf(view.permissions?.value ?? null) ?? "").trim() === "write-all";
  if (!view.referencesSecrets && !writeAll) return [];
  const events = view.triggers.filter((name) => UNTRUSTED_TRIGGERS.includes(name));
  const direct = events.filter((name) => DIRECT_TRIGGERS.includes(name));
  const second = reported.find(
    (finding) => finding.rule === RULE.targetCheckout || finding.rule === RULE.scriptInjection,
  );
  const branches = namedBranchFilter(view);
  const repositoryWrite =
    writeAll ||
    view.permissions === null ||
    writeScopes(view.permissions.value).some((scope) => REPOSITORY_WRITE_SCOPES.includes(scope));

  return [
    buildFinding({
      rule: RULE.untrustedTrigger,
      severity: repositoryWrite ? "high" : "medium",
      confidence: direct.length > 0 ? "high" : "medium",
      title: "Workflow is triggerable by an outside contributor and holds repository secrets",
      description: `${view.file} subscribes to \`${events.join("`, `")}\`, and ${view.referencesSecrets ? "the workflow reads `${{ secrets.* }}`" : "it grants a write-all token"}. ${
        direct.length > 0
          ? `\`${direct.join("`, `")}\` runs on the base branch with the real secrets, not the redacted fork-PR set, and any GitHub account can fire it.`
          : `\`workflow_run\` is one step removed: it fires when another workflow finishes${branches.length === 0 ? "" : `, and only when that run's head branch is \`${branches.join("` or `")}\``}, so reaching it means getting the upstream workflow to run first — which a fork pull request does${branches.length === 0 ? "" : `, though its head branch would have to be named \`${branches.join("` or `")}\``}.`
      } ${
        second === undefined
          ? "Nothing else in this file turns that reachability into execution, so this finding is about the entry point only."
          : `The exploitable second fact is reported separately as \`${second.rule}\` at ${view.file}:${second.location.line}, which is where the exposure actually is; this finding is the entry-point context for it and is deliberately graded below it.`
      }`,
      file: view.file,
      line: triggerLine(view),
      symbol: events.join(","),
      evidence:
        second === undefined
          ? []
          : [{ file: second.location.file, line: second.location.line, note: second.rule }],
      exploitability:
        direct.length > 0
          ? "Any GitHub account: opening a pull request, filing an issue or leaving a comment is enough to start the run."
          : `Requires the upstream workflow to run${branches.length === 0 ? "" : ` with a head branch named \`${branches.join("` or `")}\``}; an outside contributor gets there through a fork pull request that the upstream workflow builds.`,
      impact: `What a weakness inside this workflow reaches is ${prizeOf(view)}.`,
      recommendation:
        "Gate the job behind an explicit check (`if: github.event.pull_request.author_association == 'MEMBER'` or an environment with required reviewers), or move the secret-using part into a separate workflow that untrusted events cannot reach.",
      acceptanceCriteria: [
        `Jobs in ${view.file} that read secrets are gated on an author or environment check`,
        "The untrusted-event entry point performs no privileged action of its own",
      ],
      cwe: ["CWE-863"],
      owasp: ["A01:2021-Broken Access Control"],
      source: { kind: "rule", name: CI_RULES_STEP },
    }),
  ];
}

/** What `analyseWorkflow` needs to know about the repository around the file. */
export interface WorkflowOptions {
  /**
   * The owner of the repository under analysis, as `<owner>/<repo>` spells it.
   * Without it every `uses:` looks third-party, which is how a repository's own
   * actions came to be reported as a stranger's code.
   */
  readonly repositoryOwner?: string | null | undefined;
}

/** Runs every CI rule over one already-parsed workflow. */
export function analyseWorkflow(
  file: string,
  text: string,
  options: WorkflowOptions = {},
): WorkflowAnalysis {
  const view = viewOf(file, text, options.repositoryOwner ?? null);
  if (view.root === null) return { findings: [], suppressed: [] };
  const steps = stepsOf(view.jobs);
  const sites = usesSites(view, steps);
  const suppressed: SuppressionNote[] = [];

  // The two rules that report an exploitable fact run first, so the
  // entry-point finding can point at them instead of restating the claim.
  const reachable = [...targetCheckout(view, steps), ...scriptInjection(view, steps)];
  const findings = [
    ...untrustedTriggerWithSecrets(view, reachable),
    ...reachable,
    ...secretsInScripts(view, steps),
    ...secretToAction(view, sites, suppressed),
    ...permissions(view),
    ...unpinnedActions(view, sites),
    ...platformActions(view, sites),
    ...selfHostedRunners(view),
    ...missingConcurrency(view),
  ];
  return { findings, suppressed };
}

// ---------------------------------------------------------------------------
// Resolving the repository's own owner
// ---------------------------------------------------------------------------

/** `https://github.com/example-org/example-api.git` → `example-org`. */
export function ownerFromRemoteUrl(url: string): string | null {
  const cleaned = url
    .trim()
    .replace(/\.git$/i, "")
    .replace(/\/+$/, "");
  const parts = cleaned.split(/[/:]/).filter((part) => part !== "");
  if (parts.length < 2) return null;
  const owner = parts[parts.length - 2];
  // A GitHub owner is alphanumeric with hyphens; a dot or an `@` means we are
  // looking at the host segment, so the URL carried no owner at all.
  if (owner === undefined || !/^[A-Za-z0-9-]+$/.test(owner)) return null;
  return owner.toLowerCase();
}

/** The `url =` of `[remote "origin"]`, or of the first remote, out of a git config. */
export function ownerFromGitConfig(text: string): string | null {
  const lines = text.split("\n").map((line) => line.trim());
  let inOrigin = false;
  let fallback: string | null = null;
  for (const line of lines) {
    if (line.startsWith("[")) {
      inOrigin = /^\[remote\s+"origin"\]$/.test(line);
      continue;
    }
    const match = /^url\s*=\s*(.+)$/.exec(line);
    if (match?.[1] === undefined) continue;
    const owner = ownerFromRemoteUrl(match[1]);
    if (owner === null) continue;
    if (inOrigin) return owner;
    fallback ??= owner;
  }
  return fallback;
}

/** `@example-org/example-api` → `example-org`. */
export function ownerFromPackageName(name: string): string | null {
  const match = /^@([A-Za-z0-9-]+)\//.exec(name.trim());
  return match?.[1]?.toLowerCase() ?? null;
}

/** Where the owner came from, so the report can say which signal it used. */
export interface OwnerResolution {
  readonly owner: string | null;
  readonly source: string;
}

/**
 * Resolves the repository's own owner from the repository itself: the `origin`
 * remote first, then the scope of the root `package.json` name.
 *
 * Reading happens through the filesystem port the runner was handed, so this
 * stays inside the port discipline and works against a stub in tests.
 */
export async function resolveRepositoryOwner(ctx: RunnerContext): Promise<OwnerResolution> {
  try {
    const config = await ctx.fs.readFile(join(ctx.targetDir, ".git", "config"));
    const owner = ownerFromGitConfig(config);
    if (owner !== null) return { owner, source: "the `origin` remote in .git/config" };
  } catch {
    // No git directory (a tarball, a worktree export): fall through.
  }
  try {
    const manifest = await ctx.fs.readFile(join(ctx.targetDir, "package.json"));
    const parsed: unknown = JSON.parse(manifest);
    const name =
      typeof parsed === "object" && parsed !== null && "name" in parsed
        ? (parsed as { name?: unknown }).name
        : undefined;
    if (typeof name === "string") {
      const owner = ownerFromPackageName(name);
      if (owner !== null) return { owner, source: "the scope of the root package.json name" };
    }
  } catch {
    // Unreadable or unparseable manifest: the owner stays unknown.
  }
  return { owner: null, source: "no owner signal in the repository" };
}

/** Lets the orchestrator hand in the file list it discovered. */
export interface CiRulesOptions {
  /** Repo-relative workflow files; defaults to the ones phase 0 proved. */
  readonly files?: readonly string[] | undefined;
  /** Overrides owner resolution; the runner reads it from the repository otherwise. */
  readonly repositoryOwner?: string | null | undefined;
}

/** How much of a withheld finding's reason the step's one-line summary carries. */
const REASON_BUDGET = 150;

/**
 * The accounting line for findings a rule declined to emit: one entry per rule,
 * with the count and the reasons, so a suppression is a number a reader can see
 * rather than an absence they cannot.
 *
 * The notes themselves carry the file and the line; this is the pointer to them,
 * so each reason is trimmed and at most two per rule are printed.
 */
export function summariseSuppressions(notes: readonly SuppressionNote[]): string | null {
  if (notes.length === 0) return null;
  const groups = new Map<string, { count: number; reasons: string[] }>();
  for (const note of notes) {
    const group = groups.get(note.rule) ?? { count: 0, reasons: [] };
    group.count += 1;
    const reason =
      note.reason.length > REASON_BUDGET
        ? `${note.reason.slice(0, REASON_BUDGET - 1)}…`
        : note.reason;
    if (!group.reasons.includes(reason)) group.reasons.push(reason);
    groups.set(note.rule, group);
  }
  const parts = [...groups.entries()].map(([rule, group]) => {
    const shown = group.reasons.slice(0, 2);
    const rest = group.reasons.length - shown.length;
    return `${group.count}× ${rule} (${shown.join("; ")}${rest > 0 ? `; +${rest} more reason(s)` : ""})`;
  });
  return `${notes.length} finding(s) withheld by a rule's own gate: ${parts.join(". ")}`;
}

/**
 * Runs Sentinel's GitHub Actions rules over the target's workflows. A workflow
 * that cannot be read or parsed degrades the step, it never throws.
 */
export async function runCiRules(
  ctx: RunnerContext,
  options: CiRulesOptions = {},
): Promise<StepOutcome> {
  const startedAt = performance.now();
  const files = [...new Set(options.files ?? workflowFilesOf(ctx.profile))].sort();
  if (files.length === 0) {
    return skipped(CI_RULES_STEP, startedAt, "the target has no GitHub Actions workflow");
  }

  const resolved =
    options.repositoryOwner === undefined
      ? await resolveRepositoryOwner(ctx)
      : { owner: options.repositoryOwner, source: "the caller" };

  const findings: Finding[] = [];
  const suppressed: SuppressionNote[] = [];
  const notes: Array<string | null> = [];
  const unreadable: string[] = [];
  let scanned = 0;

  for (const file of files) {
    let text: string;
    try {
      text = await ctx.fs.readFile(join(ctx.targetDir, file));
    } catch (cause) {
      unreadable.push(`${file} (${cause instanceof Error ? cause.message : String(cause)})`);
      continue;
    }
    for (const error of parseYaml(text).errors) notes.push(`${file}: ${error}`);
    scanned += 1;
    const analysis = analyseWorkflow(file, text, { repositoryOwner: resolved.owner });
    findings.push(...analysis.findings);
    suppressed.push(...analysis.suppressed);
  }

  if (unreadable.length > 0) {
    notes.push(`could not read ${unreadable.join(", ")}`);
  }

  const verified = await verifyStepFindings(findings, ctx);
  if (verified.droppedFindings > 0) {
    notes.push(
      `${verified.droppedFindings} finding(s) cited a line Sentinel could not resolve on disk and were dropped`,
    );
  }

  // Suppression notes are an accounting line, never a degradation, so the
  // status is decided before they join the reason.
  const status = notes.length === 0 ? "ok" : "degraded";
  return outcome(
    CI_RULES_STEP,
    status,
    joinReasons([
      `${scanned} of ${files.length} workflow(s) analysed`,
      resolved.owner === null
        ? `repository owner unresolved (${resolved.source}), so every \`uses:\` is graded as third-party`
        : `repository owner \`${resolved.owner}\` (from ${resolved.source})`,
      ...notes,
      summariseSuppressions(suppressed),
    ]),
    verified.kept,
    [],
    startedAt,
  );
}

/** Every rule id this pack can emit, for the report's rule index. */
export const CI_RULE_IDS: readonly string[] = Object.values(RULE);
