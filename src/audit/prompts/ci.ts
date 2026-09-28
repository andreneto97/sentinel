/**
 * The CI workflow-job prompt (D4).
 *
 * This is the kind that was enumerated and never audited. Phase 2 lists every
 * job of every workflow, `src/scan/rules/ci.ts` grades the *syntax* of those
 * workflows — an unpinned action, an undeclared `permissions`, a secret on a
 * `run:` line — and until this prompt existed no model ever read one. The delivery
 * domain therefore counted its analyzer steps as the only checks that ran, while
 * every enumerated job sat in the denominator as a check nobody looked at.
 *
 * What a model adds over the rule pack is one judgement the pack cannot make:
 * **is the untrusted code executed, or only checked out?** Two `workflow_run` jobs
 * can check out `github.event.workflow_run.head_sha` on identical lines and not be
 * equally dangerous. One that then runs a composite action *out of that checkout*
 * is arbitrary code execution, and in a job holding `id-token: write` and a cloud
 * role it hands a contributor the credential. One that runs `git diff` and a `jq`
 * over a committed manifest is attacker-controlled *data* reaching a parser. A
 * pattern matcher sees the same `ref:` line in both. Only a reader of the steps
 * can tell them apart, so every check here demands that distinction in writing,
 * and the two outcomes are separate rules with separate ceilings.
 *
 * The prompt is deliberately told what the deterministic pack has already
 * reported, so the model does not spend its answer restating an unpinned action.
 */

import { type AuditCheck, type PromptSpec, createPromptBuilder } from "./_shared.ts";

/**
 * The D4 questions asked of every CI job, in report order.
 *
 * The first two are one question split in two answers on purpose. A job that
 * executes contributor-controlled code with secrets is a repository compromise;
 * a job that only reads it is a parser exposure and a landmine for the next
 * person who adds a build step. Filing them under one rule would average the two
 * into a severity that is wrong for both.
 */
export const WORKFLOW_JOB_CHECKS: readonly AuditCheck[] = [
  {
    name: "untrusted-code-execution",
    statement: "code an outside contributor controls is never executed in a job that holds secrets",
    rule: "delivery.ci.untrusted-code-executed",
    question:
      "does this job run on an event an outside contributor can fire while the repository's secrets and token are in scope — `pull_request_target`, `workflow_run`, `issue_comment`, `issues`, `discussion`, `discussion_comment` — check out the code that contributor controls, and then EXECUTE something from that checkout?",
    fails:
      "the job checks out a ref derived from the event (`github.event.workflow_run.head_sha`, `github.event.pull_request.head.sha`, a pull-request merge ref, `github.head_ref`) and a later step runs code from it: an `npm install`/`npm ci`/`yarn`/`pnpm` with lifecycle scripts, a build, lint or test script, a local `uses: ./…` action, a `make`, or any interpreter invoked on a file from the tree — while the job can read `secrets.*`, inherits secrets, or holds a write-scoped or `id-token` token",
    ceiling: "critical",
    notApplicable:
      "the job runs only on events whose payload an outside contributor cannot influence (`push`, `workflow_dispatch`, `schedule`, `release`), or it checks out nothing: name the trigger you relied on",
  },
  {
    name: "untrusted-checkout",
    statement: "an untrusted ref that is checked out is read as data and never run",
    subject: "jobs that check out a contributor-controlled ref",
    rule: "delivery.ci.untrusted-code-checked-out",
    question:
      "when the job checks out a contributor-controlled ref and you can see no step that executes code from it, is everything it does with that checkout confined to reading data — a `git diff`, a `jq` over a committed file, a path listing?",
    fails:
      "the checkout's contents reach a step that could run them or honour configuration from them — a shell that sources a file from the tree, a tool that loads a plugin or config file it finds there, a step whose `uses:` path points inside the checkout — even though no explicit install or build step is present",
    ceiling: "high",
    notApplicable:
      "the job checks out nothing an outside contributor can influence, or the untrusted code is executed and the finding belongs to `delivery.ci.untrusted-code-executed` instead",
  },
  {
    name: "expression-injection",
    statement: "event data reaches a shell only through an environment variable",
    rule: "delivery.ci.expression-injection",
    question:
      'is every `${{ … }}` expression carrying contributor-controlled text — `github.event.*` titles, bodies, labels, branch and ref names, `github.head_ref`, `inputs.*`, a step output derived from any of them — passed through `env:` and read as `"$VAR"`, rather than interpolated straight into a `run:` block?',
    fails:
      "a `run:` block contains a `${{ … }}` expression whose value an outside contributor can choose, so their text is pasted into the shell before it is parsed",
    ceiling: "critical",
    notApplicable:
      "the job has no `run:` block, or every expression inside one resolves to a value the platform or the repository controls (`github.sha`, `github.event_name`, `github.ref`, `env.*`, `vars.*`, `needs.*` outputs that are not derived from event text)",
  },
  {
    name: "job-permissions",
    statement: "the job's token carries only the scopes its own steps use",
    rule: "delivery.ci.excessive-permissions",
    question:
      "read the `permissions` this job runs with against what its steps actually do: is every write scope it holds used by a step you were shown?",
    fails:
      "the job holds `contents: write`, `packages: write`, `id-token: write`, `write-all`, or inherits a workflow-wide write block, and no step in the job needs that scope",
    ceiling: "medium",
    notApplicable:
      "the facts record no `permissions` for this job and the workflow's own block is not in the context you were given",
  },
  {
    name: "secret-handling",
    statement: "secrets reach only the steps that need them, and leave no copy behind",
    subject: "jobs that read a secret",
    rule: "delivery.ci.secret-exposure",
    question:
      "for every `secrets.*` this job reads: is it consumed by a step that must have it, kept out of the job log, and out of anything that outlives the step?",
    fails:
      "a secret is written to standard output or standard error without redirection, handed to an action outside `actions/*` and this repository's own owner, left in a file that a later step uploads or caches, passed to a step that runs untrusted code, or forwarded wholesale with `secrets: inherit` to a workflow in another repository",
    ceiling: "high",
    notApplicable: "the facts record `usesSecrets: none` for this job",
  },
  {
    name: "runner-exposure",
    statement: "self-hosted runners are reachable only from trusted events",
    subject: "jobs on a self-hosted runner",
    rule: "delivery.ci.fork-reachable-self-hosted-runner",
    question:
      "if `runs-on` names a self-hosted runner, can an event an outside contributor fires schedule work on it?",
    fails:
      "the job runs on a self-hosted runner and is reachable from a contributor-controlled event, or it runs untrusted code there — a runner is a persistent machine, so what a job leaves behind is available to the next one",
    ceiling: "high",
    notApplicable: "the facts record `selfHosted: no`: the job runs on a GitHub-hosted runner",
  },
  {
    name: "cross-job-integrity",
    statement: "artifacts, caches and images a job consumes were produced by a trusted job",
    subject: "jobs that consume another job's output",
    rule: "delivery.ci.poisoned-artifact",
    question:
      "does this job consume something produced elsewhere — a downloaded artifact, a restored cache, a registry tag, a `needs.*.outputs` value — and could a less-trusted run have written what it gets?",
    fails:
      "the job downloads an artifact, restores a cache or pulls an image or tag whose key can be produced by a run of a contributor-controlled event, and then executes, publishes or deploys what it received",
    ceiling: "medium",
    notApplicable:
      "the job consumes no artifact, cache, image or output from another job or another run",
  },
];

/** How to read the facts the workflow-job enumerator attaches to a unit. */
const WORKFLOW_JOB_ATTRIBUTES: Readonly<Record<string, string>> = {
  job: "the job's key under `jobs:`, which is what `needs:` in other jobs refers to",
  workflow: "the workflow's `name:`, or its file name when it has none",
  triggers:
    "every event the WORKFLOW subscribes to, comma-separated, with the filters stripped — the filters (`branches`, `types`, `workflows`) are in the workflow header quoted in the shared context",
  permissions:
    "the job's own `permissions`, or the workflow-wide block when the job declares none, or `not declared`",
  usesSecrets: "the `secrets.*` names read anywhere in this job's lines, or `none`",
  runsOn: "the `runs-on` value, as written",
  selfHosted: "`yes` when `runs-on` mentions a self-hosted label",
  environment: "the deployment environment the job requests, which may carry required reviewers",
  usesWorkflow: "the reusable workflow this job calls instead of running steps, when it does",
  concurrency: "`yes` when the workflow declares a `concurrency` group",
  condition: "the job's `if:` expression, as written",
};

/** The CI workflow-job prompt spec. */
export const WORKFLOW_JOB_PROMPT: PromptSpec = {
  kind: "workflow-job",
  noun: "CI workflow job",
  mission:
    "You decide what an outside contributor can make each CI job do: whether it executes code they control while it holds the repository's secrets, whether their text reaches a shell, and how far the credentials the job is handed can reach.",
  checks: WORKFLOW_JOB_CHECKS,
  attributes: WORKFLOW_JOB_ATTRIBUTES,
  guidance: [
    "Say, in every note and every finding about untrusted code, whether that code is EXECUTED or only CHECKED OUT, and name the step that decides it. `uses: ./…`, an install with lifecycle scripts, a build or test script and any interpreter run on a file from the tree are execution; `git diff`, a path listing and a `jq` over a committed file are not. This distinction is the whole reason a model is reading these jobs.",
    "A plain `pull_request` from a fork receives no secrets and a read-only token: it is not an untrusted-trigger-with-secrets. `pull_request_target`, `workflow_run`, `issue_comment`, `issues` and the discussion events run on the base branch with full access, and that is what makes them dangerous.",
    "`workflow_run` is one step removed: it fires when another workflow finishes. Read the header's filters — `workflows:` names which workflow, `branches:` constrains that run's head branch — and state in `exploitability` what a contributor has to do to reach it, rather than asserting it is unreachable.",
    "`${{ github.sha }}`, `${{ github.ref }}`, `${{ github.event_name }}`, `${{ job.status }}` and `env`/`vars` values are platform- or repository-controlled: they are not injection. `github.event.*` titles, bodies, labels and branch names, and `inputs.*` on a `workflow_dispatch`, are contributor text.",
    "The workflow header is quoted in the shared context: the `on:` block with its filters, the workflow-level `env:` and `permissions:`, and `concurrency`. It is where the blast radius is usually written down — an account id, an IAM role name, a cluster — so read it before describing impact, and cite its lines like any other slice.",
    "`permissions` on a unit may be the workflow-wide block rather than the job's own; the facts do not distinguish them, the header does. A job that only posts to Slack while holding `id-token: write` and `packages: write` is the common case of this check failing.",
    "A job whose facts carry `usesWorkflow` calls a reusable workflow: it has no steps here. Judge what it hands over — the `with:` inputs, and `secrets: inherit` — and say that the called workflow was not shown.",
    "`needs:` does not gate a trigger. If the workflow runs, this job runs once its dependencies succeed, with whatever they produced; an `if:` on the job is the only gate, and an `if:` that tests `github.event.workflow_run.conclusion` filters failures, not authors.",
    "Sentinel's deterministic pack already reports unpinned actions, undeclared or workflow-wide `permissions`, secrets on `run:` lines, missing `concurrency` and self-hosted runners as syntax, with the trust of each action's owner and the mutability of its ref. Do not restate those facts. Report what needs the steps read in order: what the job executes, what the secret reaches, what the contributor controls.",
    "An OIDC exchange (`aws-actions/configure-aws-credentials`, `azure/login`, `google-github-actions/auth`) is what `id-token: write` is for. When a job performs one, the blast radius of anything else wrong in that job is the cloud role it assumes: name the role in `impact`.",
  ],
};

/** The CI workflow-job prompt builder. */
export const workflowJobPromptBuilder = createPromptBuilder(WORKFLOW_JOB_PROMPT);
