import { describe, expect, test } from "bun:test";
import type { AuditUnit } from "../../contracts/findings.ts";
import { type PromptContext, type PromptUnit, UNKNOWN_STACK, checkIdOf } from "./_shared.ts";
import { WORKFLOW_JOB_CHECKS, WORKFLOW_JOB_PROMPT, workflowJobPromptBuilder } from "./ci.ts";
import { checkIdsFor, promptFor, renderChecks, rulesFor } from "./index.ts";

/**
 * Three CI jobs shaped as `inventory.json` carries them, over an invented
 * lending-library repository: the workflows are invented, and the shape they are
 * written in is the one the workflow enumerator emits.
 *
 * Every id is `unitId("workflow-job", file, "job:<key>")` — the construction
 * `src/inventory/inventory.ts` assigns — every attribute is a key that
 * enumerator emits, and every quoted line is rendered the way
 * `src/inventory/slice.ts` renders one, elision markers included. So what the
 * prompt is asked to reason about here has the shape of what it will be handed.
 *
 * They are the three answers the execution distinction has to produce:
 * `select-suites` checks out the head of the run that triggered it and then runs
 * a composite action *out of that checkout*; `prepare` in
 * `publish-catalog-feed.yaml` runs on `workflow_dispatch` alone and can be
 * reached by nobody outside; `build` in `verify.yaml` builds a fork's pull
 * request, but under `pull_request`, where GitHub withholds the secrets it reads.
 */
const SELECT_SUITES: AuditUnit = {
  id: "241927d374dd7653",
  kind: "workflow-job",
  label: "shelf-checks.yaml#select-suites",
  location: { file: ".github/workflows/shelf-checks.yaml", line: 173, endLine: 190 },
  attributes: {
    concurrency: "yes",
    condition: "${{ !inputs.skip-tests }}",
    job: "select-suites",
    permissions: "contents:read,id-token:write",
    runsOn: "ubuntu-latest",
    selfHosted: "no",
    triggers: "workflow_dispatch,workflow_run",
    usesSecrets: "none",
    workflow: "Shelf Checks",
  },
};

const FEED_PREPARE: AuditUnit = {
  id: "0983d0520938248a",
  kind: "workflow-job",
  label: "publish-catalog-feed.yaml#prepare",
  location: { file: ".github/workflows/publish-catalog-feed.yaml", line: 33, endLine: 67 },
  attributes: {
    concurrency: "no",
    condition: "${{ github.event_name == 'workflow_dispatch' }}",
    job: "prepare",
    permissions: "contents:read,id-token:write",
    runsOn: "ubuntu-latest",
    selfHosted: "no",
    triggers: "workflow_dispatch",
    usesSecrets: "none",
    workflow: "Publish Catalog Feed",
  },
};

const VERIFY_BUILD: AuditUnit = {
  id: "dbdfd13ef6149d59",
  kind: "workflow-job",
  label: "verify.yaml#build",
  location: { file: ".github/workflows/verify.yaml", line: 56, endLine: 153 },
  attributes: {
    concurrency: "yes",
    job: "build",
    permissions: "contents:read,id-token:write,packages:write",
    runsOn: "ubuntu-latest",
    selfHosted: "no",
    triggers: "pull_request,push,workflow_dispatch",
    usesSecrets: "GITHUB_TOKEN,PACKAGES_READ_TOKEN",
    workflow: "Verify",
  },
};

/** Lines 173-190 of that workflow, as `src/inventory/slice.ts` renders them. */
const SELECT_SUITES_SLICE = `// .github/workflows/shelf-checks.yaml:173-190
173 | select-suites:
174 |   needs: deploy
175 |   if: \${{ !inputs.skip-tests }}
176 |   name: Select test suites
177 |   runs-on: ubuntu-latest
178 |   outputs:
179 |     suites: \${{ steps.select.outputs.suites }}
180 |   steps:
181 |     - uses: actions/checkout@v4
182 |       with:
183 |         ref: \${{ github.event.workflow_run.head_sha || github.sha }}
184 |         fetch-depth: 2
185 |     - name: Select
186 |       id: select
187 |       uses: ./.github/actions/select-suites
188 |       with:
189 |         event_name: \${{ github.event_name }}
// … 1 line elided …`;

/** The head of the same workflow, which is what the batch quotes once. */
const SHELF_CHECKS_HEADER = `// .github/workflows/shelf-checks.yaml:1-37
 1 | name: Shelf Checks
 2 |
 3 | on:
 4 |   # Runs after Verify finishes on the staging branch
 5 |   workflow_run:
 6 |     workflows: ['Verify']
 7 |     types: ['completed']
 8 |     branches: ['staging']
// … 11 lines elided …
20 | env:
21 |   AWS_REGION: eu-west-1
22 |   ACCOUNT_ID: "210987654321"
23 |   AWS_ROLE: "shelf-checks-deploy"
// … 10 lines elided …
34 | permissions:
35 |   id-token: write
36 |   contents: read
// … 1 line elided …`;

/** One job as the prompt renders it, with the workflow header as shared context. */
function entry(unit: AuditUnit, sliceText: string): PromptUnit {
  return { unit, sliceText, related: [] };
}

const CONTEXT: PromptContext = {
  stack: UNKNOWN_STACK,
  shared: [
    {
      label:
        "workflow header (.github/workflows/shelf-checks.yaml): its triggers, workflow-level env and permissions",
      text: SHELF_CHECKS_HEADER,
    },
  ],
  batchId: "workflow-job-1a2b3c4d5e6f",
};

describe("the CI job prompt", () => {
  test("is registered for the kind phase 1 could only lint", () => {
    expect(workflowJobPromptBuilder.kind).toBe("workflow-job");
    expect(promptFor("workflow-job", "delivery")).toBe(workflowJobPromptBuilder);
    // Nothing is projected away: no earlier row of this kind asks any of it.
    expect(checkIdsFor("workflow-job", "delivery")).toEqual(
      WORKFLOW_JOB_CHECKS.map((check) => checkIdOf(check)),
    );
  });

  test("every check is a delivery question with a ceiling and a positive statement", () => {
    expect(WORKFLOW_JOB_CHECKS).toHaveLength(7);
    for (const check of WORKFLOW_JOB_CHECKS) {
      expect(check.rule.startsWith("delivery.ci.")).toBe(true);
      expect(checkIdOf(check).startsWith("delivery.")).toBe(true);
      expect(check.question.length).toBeGreaterThan(40);
      expect(check.fails.length).toBeGreaterThan(40);
      expect(check.statement).not.toContain("missing");
      expect(check.notApplicable?.length ?? 0).toBeGreaterThan(20);
    }
  });

  test("executed and merely checked out are two rules, graded apart", () => {
    // The distinction two findings on the same repository turn on: one job runs a
    // composite action out of an untrusted checkout, another only reads a
    // manifest out of one. One rule for both would average a repository
    // compromise and a parser exposure into a severity that is wrong for both.
    const executed = WORKFLOW_JOB_CHECKS.find((check) => check.name === "untrusted-code-execution");
    const checkedOut = WORKFLOW_JOB_CHECKS.find((check) => check.name === "untrusted-checkout");
    expect(executed?.rule).toBe("delivery.ci.untrusted-code-executed");
    expect(executed?.ceiling).toBe("critical");
    expect(checkedOut?.rule).toBe("delivery.ci.untrusted-code-checked-out");
    expect(checkedOut?.ceiling).toBe("high");
    expect(executed?.fails).toContain("uses: ./");
    expect(checkedOut?.notApplicable).toContain("delivery.ci.untrusted-code-executed");
    // And the instruction that makes the model say which of the two it saw.
    const guidance = WORKFLOW_JOB_PROMPT.guidance.join("\n");
    expect(guidance).toContain("EXECUTED or only CHECKED OUT");
    expect(guidance).toContain("name the step");
  });

  test("the rubric names the triggers that carry secrets and the one that does not", () => {
    const rendered = [renderChecks(WORKFLOW_JOB_PROMPT), ...WORKFLOW_JOB_PROMPT.guidance].join(
      "\n",
    );
    for (const trigger of ["pull_request_target", "workflow_run", "issue_comment"]) {
      expect(rendered).toContain(trigger);
    }
    // `verify.yaml#build` builds a fork's pull request and reads two secrets. It
    // is not the untrusted-with-secrets case, and a prompt that did not say so
    // would report every job of a repository like this one as critical.
    expect(rendered).toContain("A plain `pull_request` from a fork receives no secrets");
    // The same trap in the other direction: a job that interpolates
    // `github.event_name` into a `run:` block is not injectable.
    expect(rendered).toContain("`${{ github.event_name }}`");
    expect(rendered).toContain("platform- or repository-controlled");
  });

  test("it does not ask for what the deterministic pack already reported", () => {
    const system = workflowJobPromptBuilder.systemPrompt();
    const guidance = WORKFLOW_JOB_PROMPT.guidance.join("\n");
    expect(guidance).toContain("Do not restate those facts");
    // The rule ids offered are this prompt's own: the pack's ids stay the
    // pack's, so a model cannot file a finding phase 1 already filed.
    for (const rule of rulesFor("workflow-job", "delivery")) expect(system).toContain(rule);
    for (const taken of [
      "delivery.ci.unpinned-action",
      "delivery.ci.pull-request-target-checkout",
      "delivery.ci.untrusted-trigger-with-secrets",
      "delivery.ci.secret-in-run-command",
      "delivery.ci.missing-concurrency",
      "delivery.ci.self-hosted-runner",
    ]) {
      expect(system).not.toContain(taken);
    }
  });

  test("the header states every check key, the fact legend and the batch id", () => {
    const header = workflowJobPromptBuilder.header(CONTEXT, [
      entry(SELECT_SUITES, SELECT_SUITES_SLICE),
      entry(VERIFY_BUILD, "// .github/workflows/verify.yaml:56-153\n 56 | build:"),
    ]);
    expect(header).toContain("BATCH workflow-job-1a2b3c4d5e6f — 2 CI workflow jobs to audit");
    for (const id of checkIdsFor("workflow-job", "delivery")) expect(header).toContain(`"${id}"`);
    // How to read a fact that is not the job's own, and where the rest of it is.
    expect(header).toContain("or the workflow-wide block when the job declares none");
    expect(header).toContain("with the filters stripped");
    // The header slice is quoted once for the batch, and named.
    expect(header).toContain("workflow header (.github/workflows/shelf-checks.yaml)");
    expect(header).toContain("branches: ['staging']");
  });

  test("a job section carries its facts and its YAML with the real line numbers", () => {
    const section = workflowJobPromptBuilder.section(entry(SELECT_SUITES, SELECT_SUITES_SLICE));
    expect(section).toContain("UNIT 241927d374dd7653");
    expect(section).toContain("at: .github/workflows/shelf-checks.yaml:173-190");
    expect(section).toContain("triggers: workflow_dispatch,workflow_run");
    expect(section).toContain("permissions: contents:read,id-token:write");
    expect(section).toContain("usesSecrets: none");
    // Both halves of the judgement are on the page: the checkout of the
    // contributor's ref, and the step that runs code out of it.
    expect(section).toContain("183 |         ref: ${{ github.event.workflow_run.head_sha");
    expect(section).toContain("187 |       uses: ./.github/actions/select-suites");
    // And the marker that says the job does not end where the quote does, so a
    // control below line 189 cannot be reported missing.
    expect(section).toContain("// … 1 line elided …");
  });

  test("a job nobody outside can trigger is answerable as not applicable", () => {
    // `publish-catalog-feed.yaml#prepare` runs on `workflow_dispatch` only. The
    // prompt has to make "nobody outside can fire this" a legitimate answer with
    // a named reason, or a model under pressure to find something invents one.
    const executed = WORKFLOW_JOB_CHECKS[0];
    expect(executed?.notApplicable).toContain("workflow_dispatch");
    expect(executed?.notApplicable).toContain("name the trigger you relied on");
    const section = workflowJobPromptBuilder.section(
      entry(FEED_PREPARE, "// .github/workflows/publish-catalog-feed.yaml:33-67\n33 | prepare:"),
    );
    expect(section).toContain("triggers: workflow_dispatch");
  });

  test("the footer demands a verdict for every job id in the batch", () => {
    const units = [
      entry(SELECT_SUITES, SELECT_SUITES_SLICE),
      entry(FEED_PREPARE, "// .github/workflows/publish-catalog-feed.yaml:33-67\n33 | prepare:"),
      entry(VERIFY_BUILD, "// .github/workflows/verify.yaml:56-153\n 56 | build:"),
    ];
    const footer = workflowJobPromptBuilder.footer(units);
    expect(footer).toContain("A VERDICT IS REQUIRED FOR ALL 3 OF THESE UNIT IDS");
    for (const one of units) expect(footer).toContain(one.unit.id);
    expect(footer).toContain(`${WORKFLOW_JOB_CHECKS.length} checks`);
  });
});
