import { describe, expect, test } from "bun:test";
import type { SarifLocation } from "../parsers/sarif.ts";
import {
  GITLEAKS_RULE,
  type GitleaksContext,
  confidenceForRule,
  gitleaksArgs,
  maskSpan,
  runGitleaks,
  severityForRule,
  spanFits,
} from "./gitleaks.ts";

/** The real gitleaks SARIF captured from a repository with a planted secret. */
const REPORT = await Bun.file(
  `${import.meta.dir}/../parsers/__fixtures__/gitleaks-report.sarif`,
).text();

/**
 * The `.env` the fixture's second hit points at. The value is built rather than
 * written out so this test file carries no string that looks like a real token,
 * while keeping the exact length gitleaks reported (columns 14..53).
 *
 * It is also the case that proves the value gate does not swallow a real
 * credential: 36 repeated characters have almost no entropy, and `github-pat` is
 * still graded a credential, because a provider's own format outranks the shape
 * of what it matched.
 */
const ENV_LINE = `GITHUB_TOKEN=ghp_${"x".repeat(36)}`;

/** The commit the fixture's `.env` hit cites, for the blob the harness serves. */
const ENV_COMMIT = "5555eeee4444dddd3333cccc2222bbbb1111aaaa";

/** Minimal in-memory filesystem covering the slice both runners take. */
class MemoryFs {
  readonly files = new Map<string, string>();
  readonly dirs = new Set<string>();

  constructor(files: Record<string, string> = {}) {
    for (const [path, body] of Object.entries(files)) this.files.set(path, body);
  }

  async readFile(path: string): Promise<string> {
    const body = this.files.get(path);
    if (body === undefined) throw new Error(`ENOENT: ${path}`);
    return body;
  }

  async readFileBytes(path: string): Promise<Uint8Array> {
    return new TextEncoder().encode(await this.readFile(path));
  }

  async writeFile(path: string, data: string | Uint8Array): Promise<void> {
    this.files.set(path, typeof data === "string" ? data : new TextDecoder().decode(data));
  }

  async mkdirp(path: string): Promise<void> {
    this.dirs.add(path);
  }

  async exists(path: string): Promise<boolean> {
    if (this.files.has(path) || this.dirs.has(path)) return true;
    const prefix = `${path}/`;
    for (const known of this.files.keys()) if (known.startsWith(prefix)) return true;
    return false;
  }

  async realpath(path: string): Promise<string> {
    if (!(await this.exists(path))) throw new Error(`ENOENT: ${path}`);
    return path;
  }

  async readLines(path: string, from: number, to: number): Promise<string[]> {
    const lines = (await this.readFile(path)).split("\n");
    return lines.slice(from - 1, to === Number.POSITIVE_INFINITY ? undefined : to);
  }
}

/** What the stubbed gitleaks process did, so a test can assert on the call. */
interface Call {
  command: string;
  args: readonly string[];
  env: Readonly<Record<string, string | undefined>> | undefined;
  cwd: string | undefined;
}

interface HarnessOptions {
  /** Files in the fake target, keyed by absolute path. */
  readonly files?: Record<string, string>;
  /** The report gitleaks "writes"; omit to have it write nothing. */
  readonly report?: string | null;
  readonly exitCode?: number;
  readonly stderr?: string;
  readonly timedOut?: boolean;
  readonly notFound?: boolean;
  readonly truncated?: boolean;
  /** Null makes the resolver report gitleaks as not installed. */
  readonly binary?: string | null;
  readonly isGitRepo?: boolean;
  /**
   * What `git show <sha>:./<path>` returns, keyed `"<sha>:<path>"`. This is how
   * the runner learns what gitleaks matched: the report is `--redact`ed, so the
   * only place the matched text exists is the blob of the commit it cites.
   */
  readonly blobs?: Record<string, string>;
  /** False makes `git` unavailable, so a shifted line is graded as unresolved. */
  readonly git?: boolean;
}

const TARGET = "/repo";
const RUN_DIR = "/runs/r1";
const REPORT_PATH = `${RUN_DIR}/raw/gitleaks/report.sarif`;

/** Builds a context whose gitleaks is a stub that writes a chosen report. */
function harness(options: HarnessOptions = {}): { ctx: GitleaksContext; calls: Call[] } {
  const fs = new MemoryFs(options.files ?? {});
  if (options.isGitRepo !== false) fs.dirs.add(`${TARGET}/.git`);
  const calls: Call[] = [];

  const ctx: GitleaksContext = {
    fs,
    exec: {
      async run(command, args = [], runOptions = {}) {
        calls.push({
          command,
          args,
          env: runOptions.env,
          cwd: runOptions.cwd,
        });
        const clean = {
          exitCode: 0,
          stdout: "",
          stderr: "",
          timedOut: false,
          truncated: false,
          notFound: false,
        };
        if (command === "git") {
          if (options.git === false) return { ...clean, notFound: true };
          // `git show <sha>:./<path>` — the runner's only use of git.
          const key = (args[1] ?? "").replace(":./", ":");
          const blob = options.blobs?.[key];
          return blob === undefined
            ? { ...clean, exitCode: 128, stderr: `fatal: path does not exist: ${key}` }
            : { ...clean, stdout: blob };
        }
        const report = options.report === undefined ? REPORT : options.report;
        if (report !== null) await fs.writeFile(REPORT_PATH, report);
        return {
          ...clean,
          exitCode: options.exitCode ?? 0,
          stderr: options.stderr ?? "",
          timedOut: options.timedOut ?? false,
          truncated: options.truncated ?? false,
          notFound: options.notFound ?? false,
        };
      },
    },
    tools: {
      async resolve() {
        return options.binary === undefined ? "/tools/gitleaks" : options.binary;
      },
    },
    targetDir: TARGET,
    runDir: RUN_DIR,
  };
  return { ctx, calls };
}

describe("gitleaksArgs", () => {
  test("scans history: --no-git is never passed", () => {
    const args = gitleaksArgs(TARGET, REPORT_PATH);
    expect(args).not.toContain("--no-git");
    expect(args[0]).toBe("detect");
  });

  test("redacts, so the raw report is shareable", () => {
    expect(gitleaksArgs(TARGET, REPORT_PATH)).toContain("--redact");
  });

  test("makes leaks a normal outcome rather than a failing exit code", () => {
    const args = gitleaksArgs(TARGET, REPORT_PATH);
    expect(args.slice(args.indexOf("--exit-code"), args.indexOf("--exit-code") + 2)).toEqual([
      "--exit-code",
      "0",
    ]);
  });

  test("writes SARIF where the run directory expects it", () => {
    const args = gitleaksArgs(TARGET, REPORT_PATH);
    expect(args).toContain("sarif");
    expect(args).toContain(REPORT_PATH);
  });
});

describe("severity and confidence classification", () => {
  test("key material is critical", () => {
    expect(severityForRule("private-key")).toBe("critical");
    expect(severityForRule("pkcs12-file")).toBe("critical");
    expect(severityForRule("cloudflare-origin-ca-key")).toBe("critical");
  });

  test("a cloud provider credential is critical", () => {
    expect(severityForRule("aws-access-token")).toBe("critical");
    expect(severityForRule("gcp-api-key")).toBe("critical");
    expect(severityForRule("azure-ad-client-secret")).toBe("critical");
    expect(severityForRule("hashicorp-tf-api-token")).toBe("critical");
  });

  test("every other provider token is high", () => {
    expect(severityForRule("github-pat")).toBe("high");
    expect(severityForRule("slack-bot-token")).toBe("high");
    expect(severityForRule("stripe-access-token")).toBe("high");
  });

  test("shape-and-entropy rules are a lead, not proof", () => {
    expect(confidenceForRule("generic-api-key")).toBe("medium");
    expect(confidenceForRule("jwt")).toBe("medium");
    expect(confidenceForRule("github-pat")).toBe("high");
  });
});

describe("maskSpan", () => {
  const at = (partial: Partial<SarifLocation>): SarifLocation => ({
    file: "f",
    startLine: 1,
    startColumn: null,
    endLine: null,
    endColumn: null,
    snippet: null,
    ...partial,
  });

  test("masks exactly the reported columns", () => {
    const masked = maskSpan([ENV_LINE], 1, at({ startLine: 1, startColumn: 14, endColumn: 53 }));
    expect(masked[0]).toBe("GITHUB_TOKEN=[REDACTED]");
  });

  test("keeps the surrounding text on the line", () => {
    const masked = maskSpan(['const k = "abcdef";'], 1, at({ startColumn: 12, endColumn: 17 }));
    expect(masked[0]).toBe('const k = "[REDACTED]";');
  });

  test("masks whole lines in the middle of a multi-line match", () => {
    // A PEM block's shape — a header and two 19-character body lines — with a body
    // built out of one repeated character, so nothing key-shaped is written here.
    const key = [
      "-----BEGIN RSA PRIVATE KEY-----",
      `MIIE${"o".repeat(15)}`,
      `AAKC${"a".repeat(15)}`,
    ];
    const masked = maskSpan(
      key,
      1,
      at({ startLine: 1, startColumn: 1, endLine: 3, endColumn: 19 }),
    );
    expect(masked).toEqual(["[REDACTED]", "[REDACTED]", "[REDACTED]"]);
  });

  test("leaves context lines outside the span untouched", () => {
    const masked = maskSpan(["before", "secret", "after"], 4, at({ startLine: 5, startColumn: 1 }));
    expect(masked[0]).toBe("before");
    expect(masked[2]).toBe("after");
  });
});

describe("spanFits", () => {
  const at = (partial: Partial<SarifLocation>): SarifLocation => ({
    file: "f",
    startLine: 5,
    startColumn: null,
    endLine: null,
    endColumn: null,
    snippet: null,
    ...partial,
  });

  test("accepts a line that still holds the reported span", () => {
    expect(spanFits([ENV_LINE], 5, at({ startColumn: 14, endColumn: 53 }))).toBe(true);
  });

  test("rejects a line that has been shortened since the commit", () => {
    expect(spanFits(["GITHUB_TOKEN="], 5, at({ startColumn: 14, endColumn: 53 }))).toBe(false);
  });

  test("rejects a window that does not reach the cited line", () => {
    expect(spanFits([], 5, at({ startColumn: 1, endColumn: 4 }))).toBe(false);
  });
});

describe("runGitleaks on real captured output", () => {
  const files = { [`${TARGET}/.env`]: `${ENV_LINE}\n` };

  test("emits one appsec.hardcoded-secret finding per hit", async () => {
    const { ctx } = harness({ files });
    const step = await runGitleaks(ctx);

    expect(step.step).toBe("gitleaks");
    expect(step.status).toBe("ok");
    expect(step.findings).toHaveLength(2);
    for (const finding of step.findings) {
      expect(finding.rule).toBe(GITLEAKS_RULE);
      expect(finding.domain).toBe("appsec");
      expect(finding.source).toEqual({ kind: "tool", name: "gitleaks" });
    }
  });

  test("masks the secret in the snippet it extracts from disk", async () => {
    const { ctx } = harness({ files });
    const step = await runGitleaks(ctx);

    const hit = step.findings.find((finding) => finding.location.file === ".env");
    expect(hit?.location.snippet).toContain("GITHUB_TOKEN=[REDACTED]");
    expect(hit?.location.snippet).not.toContain("ghp_");
    expect(hit?.location.note).toBe("secret value masked by Sentinel");
  });

  test("nothing in the finding repeats the secret", async () => {
    const { ctx } = harness({ files });
    const step = await runGitleaks(ctx);
    const serialised = JSON.stringify(step.findings);
    expect(serialised).not.toContain("ghp_");
    expect(serialised).not.toContain("x".repeat(36));
  });

  test("a value deleted from a file that stays is reported against the commit", async () => {
    // The token was replaced by a shorter placeholder. The blob says what was
    // matched, the current file does not contain it, so this is history-only --
    // and it is *proved*, not inferred from the line having got shorter.
    const { ctx } = harness({
      files: { [`${TARGET}/.env`]: "GITHUB_TOKEN=\n" },
      blobs: { [`${ENV_COMMIT}:.env`]: `${ENV_LINE}\n` },
    });
    const step = await runGitleaks(ctx);

    const hit = step.findings.find((finding) => finding.location.file === ".env");
    expect(hit?.location.snippet).toBeUndefined();
    expect(hit?.location.note).toContain("the value is no longer in this file");
    expect(hit?.description).toContain("no longer in the working tree");
    // Still a credential: `github-pat` is a provider-specific rule.
    expect(hit?.severity).toBe("high");
    expect(hit?.confidence).toBe("high");
  });

  /**
   * The bug a line-length comparison produces. gitleaks reports the columns of
   * the blob *in the commit it matched*, so a file that has grown at the top no
   * longer holds that span at that line — the span test fails, the hit is reported
   * as "no longer in the working tree", and the acceptance criteria tell the
   * remediator to purge git history for a value that is sitting in HEAD a few
   * lines further down the same tracked file.
   */
  test("a value that moved down the file is re-anchored to where it is now", async () => {
    const moved = ["# header", "", "", `${ENV_LINE}`, "TRAILING=1", ""].join("\n");
    const { ctx } = harness({
      files: { [`${TARGET}/.env`]: moved },
      blobs: { [`${ENV_COMMIT}:.env`]: `${ENV_LINE}\n` },
    });
    const step = await runGitleaks(ctx);

    const hit = step.findings.find((finding) => finding.location.file === ".env");
    expect(hit?.location.line).toBe(4);
    expect(hit?.location.snippet).toContain("GITHUB_TOKEN=[REDACTED]");
    expect(hit?.location.snippet).not.toContain("ghp_");
    expect(hit?.location.note).toContain("re-anchored from line 1");
    expect(hit?.description).toContain("still in the working tree");
    // The acceptance criteria must ask for the line to go, not only for history.
    expect(
      hit?.acceptanceCriteria.some((line) => line.includes("gone from the working tree")),
    ).toBe(true);
  });

  test("a line that changed with no blob to read is unresolved, not declared gone", async () => {
    const { ctx } = harness({
      files: { [`${TARGET}/.env`]: "GITHUB_TOKEN=\n" },
      git: false,
    });
    const step = await runGitleaks(ctx);

    const hit = step.findings.find((finding) => finding.location.file === ".env");
    expect(hit?.location.note).toContain("unknown");
    expect(hit?.description).toContain("treat it as present until that is checked");
    expect(step.reason).toContain("git is not on PATH");
  });

  test("a secret whose file is gone is still reported, with the commit", async () => {
    const { ctx } = harness({ files });
    const step = await runGitleaks(ctx);

    const historic = step.findings.find((finding) => finding.location.file === "src/key.pem");
    expect(historic).toBeDefined();
    expect(historic?.severity).toBe("critical");
    expect(historic?.location.snippet).toBeUndefined();
    expect(historic?.location.note).toContain("not in the working tree");
    expect(historic?.location.note).toContain("aaaa1111bb");
    expect(historic?.description).toContain("no longer in the working tree");
    expect(historic?.description).toContain("Dev Example");
    expect(historic?.exploitability).toContain("git log -p");
  });

  test("the worktree hit is classified by its rule, not by its presence", async () => {
    const { ctx } = harness({ files });
    const step = await runGitleaks(ctx);

    const hit = step.findings.find((finding) => finding.location.file === ".env");
    expect(hit?.severity).toBe("high");
    expect(hit?.confidence).toBe("high");
    expect(hit?.title).toContain("github-pat");
    expect(hit?.cwe).toEqual(["CWE-798: Use of Hard-coded Credentials"]);
    expect(hit?.owasp).toEqual(["A07:2021 - Identification and Authentication Failures"]);
  });

  test("a private key also cites the hardcoded-key weakness", async () => {
    const { ctx } = harness({ files });
    const step = await runGitleaks(ctx);
    const historic = step.findings.find((finding) => finding.location.file === "src/key.pem");
    expect(historic?.cwe).toContain("CWE-321: Use of Hard-coded Cryptographic Key");
  });

  test("rotation comes before deletion in the recommendation", async () => {
    const { ctx } = harness({ files });
    const step = await runGitleaks(ctx);
    for (const finding of step.findings) {
      expect(finding.recommendation).toContain("Rotate the credential first");
      expect(finding.acceptanceCriteria[0]).toContain("revoked or rotated");
      expect(finding.acceptanceCriteria.some((line) => line.includes("filter-repo"))).toBe(true);
    }
  });

  test("ids are stable across runs and distinct per hit", async () => {
    const first = await runGitleaks(harness({ files }).ctx);
    const second = await runGitleaks(harness({ files }).ctx);
    const ids = first.findings.map((finding) => finding.id);
    expect(second.findings.map((finding) => finding.id)).toEqual(ids);
    expect(new Set(ids).size).toBe(2);
  });

  test("discloses that uncommitted changes are outside the scan", async () => {
    const { ctx } = harness({ files });
    const step = await runGitleaks(ctx);
    expect(step.reason).toContain("uncommitted working-tree changes");
  });

  test("runs in the target and does not inherit an ambient gitleaks config", async () => {
    const { ctx, calls } = harness({ files });
    await runGitleaks(ctx);
    expect(calls[0]?.cwd).toBe(TARGET);
    expect(calls[0]?.env).toEqual({ GITLEAKS_CONFIG: undefined, GITLEAKS_CONFIG_TOML: undefined });
  });
});

describe("runGitleaks degrades instead of crashing", () => {
  test("skips when gitleaks is not installed, and says what that costs", async () => {
    const step = await runGitleaks(harness({ binary: null }).ctx);
    expect(step.status).toBe("skipped");
    expect(step.reason).toContain("committed credentials go unreported");
    expect(step.findings).toEqual([]);
  });

  test("skips a target with no git history rather than scanning the worktree only", async () => {
    const step = await runGitleaks(harness({ isGitRepo: false }).ctx);
    expect(step.status).toBe("skipped");
    expect(step.reason).toContain("not a git repository");
  });

  test("fails on a non-zero exit, quoting the tool", async () => {
    const step = await runGitleaks(
      harness({ exitCode: 3, stderr: "fatal: not a valid object name" }).ctx,
    );
    expect(step.status).toBe("failed");
    expect(step.reason).toContain("exited with code 3");
    expect(step.reason).toContain("not a valid object name");
  });

  test("fails on a timeout, naming the cause", async () => {
    const step = await runGitleaks(harness({ timedOut: true }).ctx);
    expect(step.status).toBe("failed");
    expect(step.reason).toContain("time budget");
  });

  test("fails when the tool succeeds but writes no report", async () => {
    const step = await runGitleaks(harness({ report: null }).ctx);
    expect(step.status).toBe("failed");
    expect(step.reason).toContain("wrote no report");
  });

  test("fails on a truncated report instead of reading it as clean", async () => {
    const step = await runGitleaks(harness({ report: '{"runs":[{"resu' }).ctx);
    expect(step.status).toBe("failed");
    expect(step.reason).toContain("not valid JSON");
    expect(step.findings).toEqual([]);
  });

  test("fails on a report that is not SARIF", async () => {
    const step = await runGitleaks(harness({ report: '{"leaks":[]}' }).ctx);
    expect(step.status).toBe("failed");
    expect(step.reason).toContain("no `runs` array");
  });

  test("a clean repository is ok with no findings", async () => {
    const step = await runGitleaks(
      harness({ report: '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks"}}}]}' })
        .ctx,
    );
    expect(step.status).toBe("ok");
    expect(step.findings).toEqual([]);
    expect(step.artifacts).toEqual([REPORT_PATH]);
  });

  test("truncated output is reported as degraded, not as a full scan", async () => {
    const step = await runGitleaks(harness({ truncated: true }).ctx);
    expect(step.status).toBe("degraded");
    expect(step.reason).toContain("truncated");
  });

  test("a hit pointing outside the target is dropped and counted", async () => {
    const escaping = JSON.stringify({
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { name: "gitleaks" } },
          results: [
            {
              ruleId: "aws-access-token",
              message: { text: "leak" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "../../../etc/shadow" },
                    region: { startLine: 1 },
                  },
                },
              ],
            },
          ],
        },
      ],
    });
    const step = await runGitleaks(harness({ report: escaping }).ctx);
    expect(step.findings).toEqual([]);
    expect(step.reason).toContain("outside the target directory");
  });
});

// ---------------------------------------------------------------------------
// The three positions a generic rule matches in, replayed end to end
// ---------------------------------------------------------------------------

/**
 * Almost everything a secret scanner matches in a repository that keeps its
 * credentials out of source is `generic-api-key`, and the three fixtures below
 * are the positions it matches in: a gateway chart that *names* secrets held in
 * Kubernetes, an env template that holds an id and a credential-shaped value, and
 * a README whose "credential" is a command-line argument.
 *
 * They are built in an invented lending-library service, and every
 * credential-shaped value in them is generated by {@link syntheticValue} — a tool
 * that exists to stop credentials being committed does not commit one into its
 * own fixtures, and does not leave a literal for a scanner to match either.
 */

/**
 * A credential-shaped stand-in, generated rather than written out: the label says
 * what it stands for and every character after it is a function of its position.
 */
function syntheticValue(label: string, length: number): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let value = `synthetic-${label}-`;
  for (let index = 0; value.length < length; index += 1) {
    value += alphabet.charAt((index * 29 + 7) % alphabet.length);
  }
  return value;
}

/** The consumer id the chart addresses a rate-limiting consumer by. */
const CONSUMER_ID = syntheticValue("consumer-id", 24);

/**
 * The gateway chart: a `key:` under `secretKeyRef:` that names an entry in a
 * Kubernetes Secret, and a `credentialKey:` further down whose value the chart
 * itself uses to build that name.
 */
const CHART_VALUES_BLOB = [
  "gateway:",
  "  plugins:",
  "    - name: rate-limiting-branch-portal",
  "      config:",
  "        window_seconds: 60",
  "      configPatches:",
  "        - path: /second",
  "          valueFrom:",
  "            secretKeyRef:",
  "              name: lending-api-secrets",
  `              key: LOAN_RATE_POINTS_${CONSUMER_ID}`,
  "  consumers:",
  "    anonymous:",
  "      username: anonymous",
  "    branch-portal:",
  "      username: branch-portal",
  `      credentialKey: ${CONSUMER_ID}`,
  "      plugins:",
  "        - rate-limiting-branch-portal",
  "",
].join("\n");

/** The env template's SSO block: the public half on one line, the secret half on the next. */
const ENV_EXAMPLE_BLOB = [
  "LENDING_SSO_DOMAIN=sso.lending.example.com",
  `LENDING_SSO_CLIENT_ID=${syntheticValue("client-id", 32)}`,
  `LENDING_SSO_CLIENT_SECRET=${syntheticValue("client-secret", 64)}`,
  "LENDING_BASE_URL=http://localhost:3010",
  "",
].join("\n");

/** The README usage line whose "credential" is the integer 123. */
const README_BLOB = [
  "# Running Tests",
  "",
  "```bash",
  "npm run test:local -- <token> --account-id=123 --member-id=123 --access-token=abc456",
  "```",
  "",
].join("\n");

/** Builds a `generic-api-key` result with the span gitleaks reports: end exclusive. */
function genericHit(file: string, line: number, text: string, sha: string): unknown {
  return {
    message: { text: `generic-api-key has detected secret for file ${file} at commit ${sha}.` },
    ruleId: "generic-api-key",
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: file },
          region: {
            startLine: line,
            // gitleaks' generic rules start the span one character into the name
            // and end it one past the last character of the match.
            startColumn: 2,
            endLine: line,
            endColumn: text.length + 1,
            snippet: { text: "REDACTED" },
          },
        },
      },
    ],
    partialFingerprints: {
      commitSha: sha,
      email: "dev@example.com",
      author: "Dev Example",
      date: "2026-05-14T09:12:44Z",
      commitMessage: "chore: drop the branch-portal consumer",
    },
  };
}

/** A SARIF log carrying the given results, shaped like gitleaks' own. */
function sarifOf(results: readonly unknown[]): string {
  return JSON.stringify({
    version: "2.1.0",
    runs: [{ tool: { driver: { name: "gitleaks", semanticVersion: "v8.28.0" } }, results }],
  });
}

const CHART = "ops/kubernetes/charts/lending-api/values.prod.yaml";
const CHART_SHA = "1111111122222222333333334444444455555555";
const ENV_SHA = "6666666677777777888888889999999900000000";
const README = "services/hold-reminder/README-TEST.md";
const README_SHA_A = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeee";
const README_SHA_B = "ffffffff00000000111111112222222233333333";

describe("the gateway chart hits: a pointer and an identifier, not two secrets", () => {
  const chartLines = CHART_VALUES_BLOB.split("\n");
  const keyLine = 11;
  const credentialLine = 17;

  async function run(): Promise<Awaited<ReturnType<typeof runGitleaks>>> {
    const { ctx } = harness({
      // The consumer block was deleted from the chart since those commits, so
      // neither value is in the current file.
      files: { [`${TARGET}/${CHART}`]: "gateway:\n  plugins: []\n" },
      report: sarifOf([
        genericHit(CHART, keyLine, chartLines[keyLine - 1] ?? "", CHART_SHA),
        genericHit(CHART, credentialLine, chartLines[credentialLine - 1] ?? "", CHART_SHA),
      ]),
      blobs: { [`${CHART_SHA}:${CHART}`]: CHART_VALUES_BLOB },
    });
    return runGitleaks(ctx);
  }

  test("a secretKeyRef key name is not a secret value", async () => {
    const step = await run();
    const reference = step.findings.find((finding) => finding.location.line === keyLine);
    expect(reference?.severity).toBe("info");
    expect(reference?.confidence).toBe("low");
    expect(reference?.title).toContain("Secret key name, not a secret value");
    expect(reference?.description).toContain("held outside the repository");
    expect(reference?.impact).toContain("lives in the secret store");
    // Nothing to rotate, so the checklist does not ask for a rotation.
    expect(reference?.acceptanceCriteria[0]).toContain("confirmed Sentinel's reading");
  });

  test("an access id the same chart uses as a key name is the public half", async () => {
    const step = await run();
    const identifier = step.findings.find((finding) => finding.location.line === credentialLine);
    expect(identifier?.severity).toBe("low");
    expect(identifier?.title).toContain("Public half of a credential pair");
    expect(identifier?.description).toContain("*name* a secret stored elsewhere");
    expect(identifier?.recommendation).toContain("Check the paired secret");
  });

  test("the step says how many matches it graded below credential severity", async () => {
    const step = await run();
    expect(step.status).toBe("ok");
    expect(step.reason).toContain(
      "2 of 2 matches were graded as something other than a credential",
    );
  });
});

describe("the env template block: one public identifier, one credential-shaped value", () => {
  const envLines = ENV_EXAMPLE_BLOB.split("\n");

  async function run(current: string): Promise<Awaited<ReturnType<typeof runGitleaks>>> {
    const { ctx } = harness({
      files: { [`${TARGET}/.env.example`]: current },
      report: sarifOf([
        genericHit(".env.example", 2, envLines[1] ?? "", ENV_SHA),
        genericHit(".env.example", 3, envLines[2] ?? "", ENV_SHA),
      ]),
      blobs: { [`${ENV_SHA}:.env.example`]: ENV_EXAMPLE_BLOB },
    });
    return runGitleaks(ctx);
  }

  test("the client_id is demoted and the client_secret is not", async () => {
    const step = await run(ENV_EXAMPLE_BLOB);
    const [identifier, secret] = [
      step.findings.find((finding) => finding.title.includes("Public half")),
      step.findings.find((finding) => finding.title.includes("Hardcoded credential")),
    ];
    expect(identifier?.severity).toBe("low");
    expect(secret?.severity).toBe("high");
    expect(secret?.confidence).toBe("medium");
    expect(secret?.description).toContain("length and the entropy of a real credential");
    expect(secret?.recommendation).toContain("Rotate the credential first");
    // The finding is in a template file, and says so rather than being capped for it.
    expect(secret?.location.file).toBe(".env.example");
  });

  test("a secret that moved down the file is still reported as present", async () => {
    // The failure this guards: a template that has grown at the top no longer
    // holds the reported span at the reported line, and a line-length comparison
    // calls a value that is in HEAD today "no longer in the working tree".
    const shifted = ["# added later", "", "", ...envLines].join("\n");
    const step = await run(shifted);
    const secret = step.findings.find((finding) => finding.title.includes("Hardcoded credential"));
    expect(secret?.location.line).toBe(6);
    expect(secret?.location.note).toContain("re-anchored from line 3");
    expect(secret?.description).toContain("still in the working tree");
    expect(secret?.location.snippet).toContain("LENDING_SSO_CLIENT_SECRET=[REDACTED]");
  });

  /**
   * A finding's own span is masked by position; its *context* lines are the lines
   * around it, and in an env template those hold the neighbouring matches.
   * Re-anchoring is what makes this reachable: a block reported as history-only
   * has no snippet at all, and the first snippet rendered for a re-anchored one
   * printed the value on the next line in the clear.
   */
  test("the context lines of one secret do not print the next one", async () => {
    const step = await run(ENV_EXAMPLE_BLOB);
    const serialised = JSON.stringify(step.findings);
    // The two values gitleaks matched, neither of which may appear anywhere.
    for (const line of [envLines[1], envLines[2]]) {
      const value = (line ?? "").split("=")[1];
      expect(value).toBeDefined();
      expect(serialised).not.toContain(value ?? "@@");
    }
    const secret = step.findings.find((finding) => finding.title.includes("Hardcoded credential"));
    // The neighbouring client_id is in the window, and it is masked there too.
    expect(secret?.location.snippet).toContain("LENDING_SSO_CLIENT_ID=[REDACTED]");
    // Context that was never matched still reads normally.
    expect(secret?.location.snippet).toContain("LENDING_SSO_DOMAIN=sso.lending.example.com");
  });

  test("a placeholder in the same position is not a credential at all", async () => {
    const slot = "LENDING_SSO_CLIENT_SECRET=<your-client-secret>";
    const { ctx } = harness({
      files: { [`${TARGET}/.env.example`]: `${slot}\n` },
      report: sarifOf([genericHit(".env.example", 1, slot, ENV_SHA)]),
      blobs: { [`${ENV_SHA}:.env.example`]: `${slot}\n` },
    });
    const step = await runGitleaks(ctx);
    expect(step.findings[0]?.severity).toBe("info");
    expect(step.findings[0]?.title).toContain("Placeholder matched as a credential");
    expect(step.findings[0]?.impact).toContain("nothing here to authenticate with");
  });
});

describe("one value in one file is one finding", () => {
  test("the same README line under two commits collapses, and says so", async () => {
    const readmeLine = README_BLOB.split("\n")[3] ?? "";
    const { ctx } = harness({
      files: { [`${TARGET}/${README}`]: README_BLOB },
      report: sarifOf([
        genericHit(README, 4, readmeLine, README_SHA_A),
        genericHit(README, 4, readmeLine, README_SHA_B),
      ]),
      blobs: {
        [`${README_SHA_A}:${README}`]: README_BLOB,
        [`${README_SHA_B}:${README}`]: README_BLOB,
      },
    });
    const step = await runGitleaks(ctx);

    expect(step.findings).toHaveLength(1);
    const [finding] = step.findings;
    // The "credential" is the integer 123, in a fenced usage block.
    expect(finding?.severity).toBe("info");
    expect(finding?.title).toContain("Placeholder matched as a credential");
    expect(finding?.description).toContain("matched 1 further time in this file");
    expect(finding?.evidence[0]?.note).toContain("the same value, matched in");
    expect(step.reason).toContain("1 further hit matched the same value in the same file");
  });

  test("two different values in one file stay two findings", async () => {
    const lines = CHART_VALUES_BLOB.split("\n");
    const { ctx } = harness({
      files: { [`${TARGET}/${CHART}`]: CHART_VALUES_BLOB },
      report: sarifOf([
        genericHit(CHART, 11, lines[10] ?? "", CHART_SHA),
        genericHit(CHART, 17, lines[16] ?? "", CHART_SHA),
      ]),
      blobs: { [`${CHART_SHA}:${CHART}`]: CHART_VALUES_BLOB },
    });
    const step = await runGitleaks(ctx);
    expect(step.findings).toHaveLength(2);
    // And the ids differ, which a `ruleId:sha` symbol cannot manage: every hit
    // from one commit in one file collapses onto a single id under that scheme.
    expect(new Set(step.findings.map((finding) => finding.id)).size).toBe(2);
  });
});
