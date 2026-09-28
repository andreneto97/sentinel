import { describe, expect, test } from "bun:test";
import type { Finding } from "../../contracts/findings.ts";
import type { DetectedFact, StackProfile } from "../../contracts/profile.ts";
import { createFileSystem } from "../../ports/file-system.ts";
import { createStubProcessExecutor } from "../../ports/process-executor.ts";
import type { RunnerContext, RunnerFileSystem } from "../runners/_runner-support.ts";
import {
  CI_RULES_STEP,
  analyseWorkflow,
  classifyRef,
  credentialClass,
  isUntrustedExpression,
  ownerFromGitConfig,
  ownerFromPackageName,
  ownerFromRemoteUrl,
  parseActionReference,
  resolveRepositoryOwner,
  runCiRules,
  stdoutDispositionOf,
  summariseSuppressions,
} from "./ci.ts";

/** A real repository fixture: one deliberately dangerous workflow and one careful one. */
const TARGET_DIR = `${import.meta.dir}/__fixtures__/repo`;
const RISKY = ".github/workflows/risky.yml";
const SAFE = ".github/workflows/safe.yml";
/** A pipeline whose risky steps are all the repository owner's own code. */
const ORG = ".github/workflows/org-pipeline.yml";
const RUN_DIR = "/tmp/sentinel-run";

const risky = await Bun.file(`${TARGET_DIR}/${RISKY}`).text();
const safe = await Bun.file(`${TARGET_DIR}/${SAFE}`).text();
const org = await Bun.file(`${TARGET_DIR}/${ORG}`).text();

/** Reads through the real port; the rules never write anything. */
function readOnlyFileSystem(): RunnerFileSystem {
  const real = createFileSystem();
  return {
    readFile: (path) => real.readFile(path),
    readFileBytes: (path) => real.readFileBytes(path),
    realpath: (path) => real.realpath(path),
    exists: (path) => real.exists(path),
    mkdirp: async () => undefined,
    writeFile: async () => undefined,
  };
}

function context(overrides: Partial<RunnerContext> = {}): RunnerContext {
  return {
    fs: readOnlyFileSystem(),
    exec: createStubProcessExecutor(() => ({})),
    tools: { resolve: async () => null },
    targetDir: TARGET_DIR,
    runDir: RUN_DIR,
    ...overrides,
  };
}

/** A profile that proves exactly the given facts. */
function profileWith(facts: ReadonlyArray<[DetectedFact["kind"], string, string]>): StackProfile {
  return {
    schemaVersion: "1.0",
    target: TARGET_DIR,
    facts: facts.map(([kind, value, file]) => ({
      kind,
      value,
      confidence: "high",
      evidence: [{ file, line: 1 }],
    })),
    absences: [],
    warnings: [],
    scan: { filesSeen: 2, filesRead: 2, truncated: false },
  };
}

/** The findings of one workflow, which is all most of these tests look at. */
function findingsOf(file: string, text: string, owner: string | null = null): Finding[] {
  return analyseWorkflow(file, text, { repositoryOwner: owner }).findings;
}

/** The finding for one rule, or undefined when the rule did not fire. */
function ruleHit(findings: readonly Finding[], leaf: string): Finding | undefined {
  return findings.find((finding) => finding.rule === `delivery.ci.${leaf}`);
}

/** Every finding for one rule. */
function ruleHits(findings: readonly Finding[], leaf: string): Finding[] {
  return findings.filter((finding) => finding.rule === `delivery.ci.${leaf}`);
}

describe("parseActionReference", () => {
  test("recognises a commit-pinned reference", () => {
    const reference = parseActionReference(
      "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
    );
    expect(reference?.pinned).toBe(true);
    expect(reference?.firstParty).toBe(true);
    expect(reference?.trust).toBe("platform");
    expect(reference?.mutability).toBe("sha");
  });

  test("recognises a tag as unpinned", () => {
    const reference = parseActionReference("some-org/deploy-action@v1");
    expect(reference?.pinned).toBe(false);
    expect(reference?.firstParty).toBe(false);
    expect(reference?.repository).toBe("some-org/deploy-action");
    expect(reference?.trust).toBe("third-party");
  });

  test("calls an action from the repository's own organisation same-owner, not third-party", () => {
    // Without the owner, every `example-org/*` step reads as a stranger's code
    // in a repository whose own remote is `github.com/example-org/example-api`.
    const reference = parseActionReference(
      "example-org/action-slack-notification@v2.0.0-alpha.4",
      "example-org",
    );
    expect(reference?.trust).toBe("same-owner");
    expect(reference?.mutability).toBe("release-tag");
  });

  test("reads a job-level reusable workflow reference", () => {
    const reference = parseActionReference(
      "example-org/example-qa-regression/.github/workflows/regression.yml@main",
      "example-org",
    );
    expect(reference?.reusableWorkflow).toBe(true);
    expect(reference?.mutability).toBe("branch");
  });

  test("ignores a local action, which is this repository's own code", () => {
    expect(parseActionReference("./.github/actions/build")).toBeNull();
  });

  test("treats a docker image without a digest as unpinned", () => {
    expect(parseActionReference("docker://alpine:3.19")?.pinned).toBe(false);
    expect(parseActionReference("docker://alpine@sha256:abc")?.pinned).toBe(true);
    expect(parseActionReference("docker://alpine@sha256:abc")?.mutability).toBe("sha");
  });
});

describe("classifyRef", () => {
  test("separates a SHA, an exact release tag, a floating tag and a branch", () => {
    expect(classifyRef("11bd71901bbe5b1630ceea73d27597364c9af683")).toBe("sha");
    expect(classifyRef("v2.0.0-alpha.4")).toBe("release-tag");
    expect(classifyRef("1.0.0")).toBe("release-tag");
    expect(classifyRef("v6")).toBe("floating-tag");
    expect(classifyRef("v2.3")).toBe("floating-tag");
    expect(classifyRef("main")).toBe("branch");
    expect(classifyRef("latest")).toBe("branch");
  });
});

describe("credentialClass", () => {
  test("separates the per-job token, a notification webhook and a real credential", () => {
    expect(credentialClass("GITHUB_TOKEN")).toBe("auto-token");
    expect(credentialClass("SLACK_URL")).toBe("narrow");
    expect(credentialClass("REGISTRY_PAT")).toBe("broad");
    // A connection string ends in `_URL` and is not a notification channel.
    expect(credentialClass("DATABASE_URL")).toBe("broad");
  });
});

describe("stdoutDispositionOf", () => {
  test("a redirected echo writes a file, so nothing reaches the job log", () => {
    const line = 'echo "//npm.pkg.github.com/:_authToken=${{ secrets.REGISTRY_PAT }}" >> .npmrc';
    expect(stdoutDispositionOf(line)).toEqual({ target: "file", sink: ".npmrc" });
  });

  test("an unredirected echo reaches the job log", () => {
    expect(stdoutDispositionOf('echo "token is ${{ secrets.NPM_TOKEN }}"').target).toBe("log");
  });

  test("`>&2` and the step summary are still the log; a pipe and /dev/null are not", () => {
    expect(stdoutDispositionOf("echo x >&2").target).toBe("log");
    expect(stdoutDispositionOf("echo x >> $GITHUB_STEP_SUMMARY").target).toBe("log");
    expect(stdoutDispositionOf("echo x | base64")).toEqual({ target: "pipe", sink: "base64" });
    expect(stdoutDispositionOf("echo x | tee log.txt").target).toBe("log");
    expect(stdoutDispositionOf("echo x > /dev/null")).toEqual({
      target: "file",
      sink: "/dev/null",
    });
  });

  test("a `>` inside quotes is text, and a following command is not this command", () => {
    expect(stdoutDispositionOf('echo "a > b"').target).toBe("log");
    expect(stdoutDispositionOf("echo x ; cat y > z").target).toBe("log");
  });
});

describe("resolving the repository's own owner", () => {
  test("reads the owner out of either git remote spelling", () => {
    expect(ownerFromRemoteUrl("https://github.com/example-org/example-api.git")).toBe(
      "example-org",
    );
    expect(ownerFromRemoteUrl("git@github.com:example-org/example-api.git")).toBe("example-org");
    expect(ownerFromRemoteUrl("https://github.com/no-owner")).toBeNull();
  });

  test("prefers the `origin` remote of a real git config", () => {
    const config = [
      "[core]",
      "\trepositoryformatversion = 0",
      '[remote "upstream"]',
      "\turl = https://github.com/someone-else/example-api.git",
      '[remote "origin"]',
      "\turl = https://github.com/example-org/example-api.git",
      "\tfetch = +refs/heads/*:refs/remotes/origin/*",
    ].join("\n");
    expect(ownerFromGitConfig(config)).toBe("example-org");
  });

  test("falls back to the scope of the root package name", () => {
    expect(ownerFromPackageName("@example-org/example-api")).toBe("example-org");
    expect(ownerFromPackageName("example-api")).toBeNull();
  });

  test("resolves through the filesystem port, git config first", async () => {
    const fs = readOnlyFileSystem();
    const resolved = await resolveRepositoryOwner(
      context({
        fs: {
          ...fs,
          readFile: async (path: string) => {
            if (path.endsWith("/.git/config")) {
              return '[remote "origin"]\n\turl = https://github.com/example-org/example-api.git\n';
            }
            throw new Error(`unexpected read of ${path}`);
          },
        },
      }),
    );
    expect(resolved.owner).toBe("example-org");
    expect(resolved.source).toContain("origin");
  });

  test("falls back to package.json, and says so when there is no signal at all", async () => {
    const fs = readOnlyFileSystem();
    const fromManifest = await resolveRepositoryOwner(
      context({
        fs: {
          ...fs,
          readFile: async (path: string) => {
            if (path.endsWith("package.json")) return '{ "name": "@example-org/example-api" }';
            throw new Error("no git config");
          },
        },
      }),
    );
    expect(fromManifest.owner).toBe("example-org");
    expect(fromManifest.source).toContain("package.json");

    const nothing = await resolveRepositoryOwner(
      context({
        fs: {
          ...fs,
          readFile: async () => {
            throw new Error("missing");
          },
        },
      }),
    );
    expect(nothing.owner).toBeNull();
  });
});

describe("isUntrustedExpression", () => {
  test("accepts the contexts an outside contributor writes", () => {
    expect(isUntrustedExpression("github.event.pull_request.title")).toBe(true);
    expect(isUntrustedExpression("github.event.issue.body")).toBe(true);
    expect(isUntrustedExpression("github.head_ref")).toBe(true);
    expect(isUntrustedExpression("github.event.comment.body")).toBe(true);
  });

  test("leaves the contexts GitHub controls alone", () => {
    expect(isUntrustedExpression("github.sha")).toBe(false);
    expect(isUntrustedExpression("github.ref")).toBe(false);
    expect(isUntrustedExpression("github.event.pull_request.number")).toBe(false);
    expect(isUntrustedExpression("secrets.NPM_TOKEN")).toBe(false);
  });
});

describe("analyseWorkflow on the risky fixture", () => {
  const findings = findingsOf(RISKY, risky);

  test("flags the pull_request_target checkout of the PR head as critical", () => {
    const finding = ruleHit(findings, "pull-request-target-checkout");
    expect(finding?.severity).toBe("critical");
    // The anchor is the `ref:` line, which is what proves the claim.
    expect(finding?.location.line).toBe(13);
    expect(finding?.cwe).toContain("CWE-94");
  });

  test("anchors script injection on the line inside the run block, not on `run:`", () => {
    const finding = ruleHit(findings, "script-injection");
    expect(finding?.severity).toBe("high");
    expect(finding?.location.line).toBe(18);
    expect(finding?.title).toContain("github.event.pull_request.title");
  });

  test("finds the echoed secret on its own line of the literal block", () => {
    const finding = ruleHit(findings, "secret-echoed");
    expect(finding?.severity).toBe("high");
    expect(finding?.location.line).toBe(21);
    // Nothing redirects this one, which is the whole difference from `>> .npmrc`.
    expect(finding?.description).toContain("not redirected");
  });

  test("flags the secret handed to an unpinned third-party action", () => {
    const finding = ruleHit(findings, "secret-to-third-party-action");
    expect(finding?.severity).toBe("high");
    expect(finding?.location.line).toBe(16);
  });

  test("flags the unpinned third-party action, and only that one", () => {
    const finding = ruleHit(findings, "unpinned-action");
    expect(finding?.location.line).toBe(14);
    // Floating tag from a stranger, plus a broad secret on the step.
    expect(finding?.severity).toBe("high");
    expect(ruleHits(findings, "unpinned-action")).toHaveLength(1);
  });

  test("reports the platform action once for the file rather than per step", () => {
    const platform = ruleHits(findings, "unpinned-platform-action");
    expect(platform).toHaveLength(1);
    expect(platform[0]?.severity).toBe("low");
    expect(platform[0]?.description).toContain("actions/checkout@v4");
  });

  test("flags the undeclared permissions, anchored on a line that exists", () => {
    const finding = ruleHit(findings, "permissions-not-declared");
    expect(finding?.severity).toBe("high");
    expect(finding?.location.line).toBe(2);
  });

  test("flags the self-hosted runner and the missing concurrency group", () => {
    expect(ruleHit(findings, "self-hosted-runner")?.location.line).toBe(9);
    expect(ruleHit(findings, "missing-concurrency")?.location.line).toBe(8);
  });

  test("flags the untrusted trigger on the trigger's own line", () => {
    const finding = ruleHit(findings, "untrusted-trigger-with-secrets");
    // No `permissions:` block at all, so the token can change the repository.
    expect(finding?.severity).toBe("high");
    expect(finding?.location.line).toBe(3);
  });

  test("gives every finding a distinct id", () => {
    expect(new Set(findings.map((finding) => finding.id)).size).toBe(findings.length);
  });
});

describe("analyseWorkflow on the careful fixture", () => {
  test("reports nothing: pinned SHAs, read-only token, concurrency, env-bound input", () => {
    expect(analyseWorkflow(SAFE, safe)).toEqual({ findings: [], suppressed: [] });
  });

  test("does not flag an untrusted value that is bound through env:", () => {
    expect(safe).toContain("TITLE: ${{ github.event.pull_request.title }}");
    expect(findingsOf(SAFE, safe).some((f) => f.rule.endsWith("script-injection"))).toBe(false);
  });
});

describe("analyseWorkflow on a same-owner pipeline", () => {
  const findings = findingsOf(ORG, org, "example-org");

  test("grades the organisation's own exact-tagged webhook action at the bottom of both tables", () => {
    const secret = ruleHit(findings, "secret-to-same-owner-action");
    expect(secret?.severity).toBe("low");
    expect(secret?.title).toContain("SLACK_URL");
    expect(secret?.description).toContain("does not cross an organisational trust boundary");
    const unpinned = ruleHits(findings, "unpinned-action").find(
      (finding) => finding.location.line === 36,
    );
    expect(unpinned?.severity).toBe("low");
    // The rule id for a stranger's code is not used for the organisation's own.
    expect(ruleHit(findings, "secret-to-third-party-action")).toBeUndefined();
  });

  test("a broad credential lifts the organisation's own action one step, to medium", () => {
    const secret = ruleHits(findings, "secret-to-same-owner-action").find((finding) =>
      finding.title.includes("REGISTRY_PAT"),
    );
    expect(secret?.severity).toBe("medium");
    const unpinned = ruleHits(findings, "unpinned-action").find((finding) =>
      finding.title.includes("example-api-tests"),
    );
    expect(unpinned?.severity).toBe("medium");
  });

  test("withholds the auto-provisioned GITHUB_TOKEN and counts the decision", () => {
    const analysis = analyseWorkflow(ORG, org, { repositoryOwner: "example-org" });
    expect(analysis.suppressed).toHaveLength(1);
    expect(analysis.suppressed[0]?.rule).toBe("delivery.ci.secret-to-third-party-action");
    expect(analysis.suppressed[0]?.reason).toContain("installation token");
    expect(summariseSuppressions(analysis.suppressed)).toContain("1× delivery.ci.secret-to");
    // docker/login-action is genuinely third-party and still reported as unpinned.
    expect(
      ruleHits(findings, "unpinned-action").find((f) => f.title.includes("docker/login-action"))
        ?.severity,
    ).toBe("medium");
  });

  test("a reusable workflow on a branch with `secrets: inherit` is the worst ref in the file", () => {
    const worst = ruleHits(findings, "unpinned-action").filter((f) => f.severity === "high");
    expect(worst).toHaveLength(1);
    expect(worst[0]?.title).toContain("reusable workflow");
    expect(worst[0]?.location.line).toBe(69);
    expect(worst[0]?.description).toContain("secrets: inherit");
  });

  test("a vendor action on a floating major tag is a medium, wherever it sits", () => {
    const aws = ruleHits(findings, "unpinned-action").find((f) =>
      f.title.includes("configure-aws-credentials"),
    );
    expect(aws?.severity).toBe("medium");
  });

  test("the redirected `>> .npmrc` write is a command-line exposure, not a log leak", () => {
    expect(ruleHit(findings, "secret-echoed")).toBeUndefined();
    const finding = ruleHit(findings, "secret-in-run-command");
    expect(finding?.severity).toBe("medium");
    expect(finding?.location.line).toBe(50);
    expect(finding?.description).toContain("*not* written to the job log");
    expect(finding?.description).toContain(".npmrc");
  });

  test("the entry-point finding is a medium that names the critical it belongs to", () => {
    const finding = ruleHit(findings, "untrusted-trigger-with-secrets");
    expect(finding?.severity).toBe("medium");
    expect(finding?.description).toContain("head branch is `develop`");
    // `id-token: write` is not repository write, and the prize is named.
    expect(finding?.impact).toContain("arn:aws:iam::123456789012:role/ExampleDeployRole");
  });

  test("the entry-point finding points at the checkout when there is one", () => {
    const withCheckout = findingsOf(
      "qa.yml",
      [
        "on:",
        "  workflow_run:",
        "    workflows: ['Tests']",
        "permissions:",
        "  id-token: write",
        "  contents: read",
        "jobs:",
        "  deploy:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - uses: actions/checkout@v7",
        "        with:",
        "          ref: ${{ github.event.workflow_run.head_sha }}",
        "      - run: ./deploy.sh ${{ secrets.DEPLOY_KEY }}",
        "",
      ].join("\n"),
      "example-org",
    );
    const entry = ruleHit(withCheckout, "untrusted-trigger-with-secrets");
    expect(entry?.severity).toBe("medium");
    expect(entry?.description).toContain("delivery.ci.pull-request-target-checkout");
    expect(entry?.evidence[0]?.line).toBe(13);
    // The critical itself is untouched: it is the finding that carries the risk.
    expect(ruleHit(withCheckout, "pull-request-target-checkout")?.severity).toBe("critical");
  });
});

describe("the severity model does not depend on which file the match landed in", () => {
  const step = [
    "jobs:",
    "  notify:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: example-org/action-slack-notification@v2.0.0-alpha.4",
    "        with:",
    "          slack-endpoint: ${{ secrets.SLACK_URL }}",
    "",
  ].join("\n");
  const quiet = `on: workflow_dispatch\npermissions:\n  contents: read\n${step}`;
  const exposed = `on:\n  workflow_run:\n    workflows: ['Tests']\npermissions:\n  contents: read\n${step}`;

  test("the same reference gets the same grade in a quiet and in a reachable workflow", () => {
    const left = findingsOf("quiet.yml", quiet, "example-org");
    const right = findingsOf("exposed.yml", exposed, "example-org");
    const grade = (findings: readonly Finding[], leaf: string): string | undefined =>
      ruleHit(findings, leaf)?.severity;
    expect(grade(left, "unpinned-action")).toBe("low");
    expect(grade(right, "unpinned-action")).toBe(grade(left, "unpinned-action"));
    expect(grade(right, "secret-to-same-owner-action")).toBe(
      grade(left, "secret-to-same-owner-action"),
    );
  });

  test("without an owner signal the same reference is graded as a stranger's code", () => {
    const unknown = findingsOf("quiet.yml", quiet, null);
    expect(ruleHit(unknown, "unpinned-action")?.severity).toBe("low");
    expect(ruleHit(unknown, "secret-to-third-party-action")?.severity).toBe("medium");
  });
});

describe("analyseWorkflow edge cases", () => {
  test("write-all is a finding in its own right", () => {
    const findings = findingsOf(
      "w.yml",
      "on: push\npermissions: write-all\njobs:\n  a:\n    runs-on: ubuntu-latest\n",
    );
    expect(ruleHit(findings, "permissions-write-all")?.severity).toBe("high");
  });

  test("a workflow-wide write scope is a low finding, not a missing-permissions one", () => {
    const findings = findingsOf(
      "w.yml",
      "on: push\npermissions:\n  contents: write\njobs:\n  a:\n    runs-on: ubuntu-latest\n",
    );
    expect(ruleHit(findings, "permissions-workflow-wide-write")?.severity).toBe("low");
    expect(ruleHit(findings, "permissions-not-declared")).toBeUndefined();
  });

  test("a plain pull_request trigger is not an untrusted-trigger finding", () => {
    // GitHub withholds secrets from fork pull requests, which is what makes
    // `pull_request` the safe trigger and `pull_request_target` the dangerous one.
    const findings = findingsOf(
      "w.yml",
      'on: pull_request\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "${{ secrets.X }}"\n',
    );
    expect(ruleHit(findings, "untrusted-trigger-with-secrets")).toBeUndefined();
  });

  test("a self-hosted label inside a runs-on list is still self-hosted", () => {
    const findings = findingsOf(
      "w.yml",
      "on: push\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: [self-hosted, linux]\n",
    );
    expect(ruleHit(findings, "self-hosted-runner")?.location.line).toBe(6);
  });

  test("a non-deploy workflow without concurrency is left alone", () => {
    const findings = findingsOf(
      "test.yml",
      "name: test\non: push\npermissions:\n  contents: read\njobs:\n  unit:\n    runs-on: ubuntu-latest\n",
    );
    expect(ruleHit(findings, "missing-concurrency")).toBeUndefined();
  });

  test("a job with an environment is treated as a deployment", () => {
    const findings = findingsOf(
      "w.yml",
      "name: ship\non: push\npermissions:\n  contents: read\njobs:\n  go:\n    environment: production\n    runs-on: ubuntu-latest\n",
    );
    expect(ruleHit(findings, "missing-concurrency")?.confidence).toBe("high");
  });

  test("an unreadable workflow yields nothing rather than throwing", () => {
    expect(findingsOf("empty.yml", "")).toEqual([]);
    expect(findingsOf("comment.yml", "# nothing\n")).toEqual([]);
  });
});

describe("runCiRules", () => {
  test("verifies every citation and puts a disk-read snippet on it", async () => {
    const result = await runCiRules(context(), { files: [RISKY, SAFE] });
    expect(result.status).toBe("ok");
    expect(result.step).toBe(CI_RULES_STEP);
    expect(result.findings.length).toBe(10);
    for (const finding of result.findings) {
      expect(finding.location.snippet).toBeDefined();
      expect(finding.location.file).toBe(RISKY);
    }
    const injection = ruleHit(result.findings, "script-injection");
    expect(injection?.location.snippet).toContain("github.event.pull_request.title");
  });

  test("names the owner signal it used in the step's reason", async () => {
    const result = await runCiRules(context(), { files: [ORG], repositoryOwner: "example-org" });
    expect(result.reason).toContain("repository owner `example-org`");
    // The withheld GITHUB_TOKEN finding is counted where a reader will see it.
    expect(result.reason).toContain("withheld by a rule's own gate");
    expect(result.status).toBe("ok");
  });

  test("says so when the repository carries no owner signal", async () => {
    const result = await runCiRules(context(), { files: [SAFE] });
    expect(result.reason).toContain("repository owner unresolved");
  });

  test("takes the workflow list from the profile when none is given", async () => {
    const ctx = context({
      profile: profileWith([
        ["ci", "github-actions", RISKY],
        ["ci", "github-actions", SAFE],
      ]),
    });
    const result = await runCiRules(ctx);
    expect(result.status).toBe("ok");
    expect(result.findings.length).toBe(10);
  });

  test("skips when the repository has no workflow", async () => {
    const result = await runCiRules(context(), { files: [] });
    expect(result.status).toBe("skipped");
    expect(result.reason).toContain("no GitHub Actions workflow");
  });

  test("degrades, and names the file, when a workflow cannot be read", async () => {
    const result = await runCiRules(context(), { files: [RISKY, "missing.yml"] });
    expect(result.status).toBe("degraded");
    expect(result.reason).toContain("missing.yml");
    // The workflow that could be read is still analysed.
    expect(result.findings.length).toBe(10);
  });

  test("surfaces a YAML problem as a reason instead of throwing", async () => {
    const fs = readOnlyFileSystem();
    const ctx = context({
      fs: { ...fs, readFile: async () => "a:\n\tb: 1\n" },
    });
    const result = await runCiRules(ctx, { files: ["broken.yml"] });
    expect(result.status).toBe("degraded");
    expect(result.reason).toContain("tab used for indentation");
  });
});
