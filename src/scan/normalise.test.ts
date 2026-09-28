import { afterAll, describe, expect, test } from "bun:test";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding } from "../contracts/findings.ts";
import { createFileSystem } from "../ports/file-system.ts";
import { FIXTURE_TARGET, fixtureContext } from "./__fixtures__/harness.ts";
import {
  RULE_OVERLAP,
  SELF_VERIFIED_SOURCES,
  compareFindings,
  normaliseFindings,
  richness,
  stableFindingId,
} from "./normalise.ts";
import { runCiRules } from "./rules/ci.ts";
import { runContainerRules } from "./rules/container.ts";
import { runActionlint } from "./runners/actionlint.ts";
import { runHadolint } from "./runners/hadolint.ts";

/**
 * Every finding in these tests comes out of a real runner reading
 * `__fixtures__/target`: Sentinel's own Dockerfile and workflow packs read the
 * files directly, and hadolint and actionlint replay output captured from the
 * pinned 2.15.1 and 1.7.12 binaries against that same repository.
 */
const ctx = fixtureContext();

const [containerStep, ciStep, hadolintStep, actionlintStep] = await Promise.all([
  runContainerRules(ctx, { dockerfiles: ["Dockerfile"], composeFiles: ["docker-compose.yml"] }),
  runCiRules(ctx, { files: [".github/workflows/ci.yml"] }),
  runHadolint(ctx, { files: ["Dockerfile"] }),
  runActionlint(ctx, { files: [".github/workflows/ci.yml"] }),
]);

/** Everything the four delivery steps found, in the order the pool returns them. */
const collected: Finding[] = [
  ...containerStep.findings,
  ...ciStep.findings,
  ...hadolintStep.findings,
  ...actionlintStep.findings,
];

const options = { targetDir: FIXTURE_TARGET, fs: createFileSystem() };

/** Rule ids present in a finding list, for terse assertions. */
function rules(findings: readonly Finding[]): string[] {
  return findings.map((finding) => finding.rule);
}

describe("the fixture produces findings", () => {
  test("all four steps ran against the fixture repository", () => {
    for (const step of [containerStep, ciStep, hadolintStep, actionlintStep]) {
      expect(step.status).toBe("ok");
      expect(step.findings.length).toBeGreaterThan(0);
    }
  });
});

describe("verification", () => {
  test("every surviving finding carries a snippet read off disk", async () => {
    const result = await normaliseFindings(collected, options);
    expect(result.findings.length).toBeGreaterThan(0);
    for (const finding of result.findings) {
      expect(finding.location.snippet).toBeDefined();
      expect(finding.location.snippet).not.toBe("");
    }
  });

  test("the snippet is the repository's own text, not the tool's message", async () => {
    const result = await normaliseFindings(collected, options);
    const floating = result.findings.find(
      (finding) => finding.rule === "delivery.dockerfile.floating-base-tag",
    );
    expect(floating?.location.snippet).toContain("FROM node:latest");
  });

  test("a finding citing a file that is not there is dropped and counted", async () => {
    const ghost: Finding = {
      ...(collected[0] as Finding),
      id: "ghostghostghost0",
      location: { file: "src/deleted.ts", line: 9 },
    };
    const result = await normaliseFindings([...collected, ghost], options);
    expect(result.droppedFindings).toBe(1);
    expect(result.dropReasons["file-not-found"]).toBe(1);
    expect(result.dropped[0]?.file).toBe("src/deleted.ts");
    expect(result.findings.some((finding) => finding.location.file === "src/deleted.ts")).toBe(
      false,
    );
  });

  test("a citation past the end of a real file is dropped too", async () => {
    const overshoot: Finding = {
      ...(collected[0] as Finding),
      id: "overshootoversh0",
      location: { file: "Dockerfile", line: 9_000 },
    };
    const result = await normaliseFindings([overshoot], options);
    expect(result.droppedFindings).toBe(1);
    expect(result.dropReasons["line-out-of-range"]).toBe(1);
  });

  test("gitleaks is exempt, because re-extracting its snippet would print the secret", async () => {
    expect(SELF_VERIFIED_SOURCES.has("gitleaks")).toBe(true);
    const historical: Finding = {
      ...(collected[0] as Finding),
      id: "historyonly00000",
      domain: "appsec",
      rule: "appsec.hardcoded-secret",
      severity: "low",
      confidence: "high",
      title: "Hardcoded credential in src/deleted.ts (generic-api-key)",
      // The file is gone from the working tree on purpose: the value survives in
      // the history gitleaks walked, which is the whole point of the step.
      location: { file: "src/deleted.ts", line: 3, note: "still reachable in commit abc1234567" },
      source: { kind: "tool", name: "gitleaks" },
    };
    const result = await normaliseFindings([historical], options);
    expect(result.droppedFindings).toBe(0);
    expect(result.findings[0]?.location.snippet).toBeUndefined();
  });

  test("a gitleaks citation that escapes the repository is still refused", async () => {
    const escaping: Finding = {
      ...(collected[0] as Finding),
      id: "escaping00000000",
      rule: "appsec.hardcoded-secret",
      location: { file: "../../../etc/shadow", line: 1 },
      source: { kind: "tool", name: "gitleaks" },
    };
    const result = await normaliseFindings([escaping], options);
    expect(result.droppedFindings).toBe(1);
    expect(result.dropReasons["path-escape"]).toBe(1);
  });
});

describe("severity policy", () => {
  test("a secret gitleaks graded low is raised to the R1 floor", async () => {
    const secret: Finding = {
      ...(collected[0] as Finding),
      id: "secretsecret0000",
      domain: "appsec",
      rule: "appsec.hardcoded-secret",
      severity: "low",
      confidence: "high",
      title: "Hardcoded credential in Dockerfile (generic-api-key)",
      location: { file: "Dockerfile", line: 3, snippet: "ENV DATABASE_PASSWORD=[REDACTED]" },
      source: { kind: "tool", name: "gitleaks" },
    };
    const result = await normaliseFindings([secret], options);
    expect(result.findings[0]?.severity).toBe("high");
    expect(result.findings[0]?.description).toContain("(R1)");
    expect(result.escalations).toEqual([
      { id: "secretsecret0000", rule: "appsec.hardcoded-secret", from: "low", to: "high" },
    ]);
  });

  test("nothing the tools already graded correctly is moved", async () => {
    const result = await normaliseFindings(collected, options);
    expect(result.escalations).toEqual([]);
    expect(result.capped).toEqual([]);
  });
});

describe("the file-kind policy", () => {
  /**
   * The finding that opens a dossier when nothing grades test code differently:
   * an opengrep hit on `jwt.sign({ sub }, 'test')` inside a unit test, graded
   * `critical` and printed above every finding that reaches production.
   *
   * It cites a file that really exists under `__tests__/`, so verification reads
   * the line back off disk exactly as it does for a production finding.
   */
  const inTestCode: Finding = {
    ...(collected[0] as Finding),
    id: "testcodesecret00",
    domain: "appsec",
    rule: "appsec.auth.jwt-hardcoded-secret",
    severity: "critical",
    confidence: "high",
    title: "JWT secret hardcoded in the source in src/__tests__/auth-middleware.ts",
    description: "The JWT signing secret is a literal in the source.",
    location: { file: "src/__tests__/auth-middleware.ts", line: 12 },
    source: { kind: "rule", name: "opengrep" },
  };

  test("a critical finding in test code becomes low, labelled, and counted", async () => {
    const result = await normaliseFindings([inTestCode], options);
    const finding = result.findings[0];

    expect(finding?.severity).toBe("low");
    expect(finding?.title).toBe(
      "In test code: JWT secret hardcoded in the source in src/__tests__/auth-middleware.ts",
    );
    expect(finding?.description).toContain("capped this at low (T1)");
    expect(finding?.description).toContain("graded critical before the cap");
    // Nothing was dropped and the citation is still proved against disk.
    expect(result.droppedFindings).toBe(0);
    expect(finding?.location.snippet).toContain('const TEST_JWT_SECRET = "test"');

    expect(result.capped).toEqual([
      {
        id: "testcodesecret00",
        rule: "appsec.auth.jwt-hardcoded-secret",
        file: "src/__tests__/auth-middleware.ts",
        fileKind: "test",
        pattern: "__tests__/",
        from: "critical",
        to: "low",
      },
    ]);
  });

  test("the cap does not change the finding's identity between runs", async () => {
    const result = await normaliseFindings([inTestCode], options);
    // The id hashes (domain, rule, file, symbol), so yesterday's finding and
    // today's capped one are the same row in a diff.
    expect(result.findings[0]?.id).toBe(inTestCode.id);
  });

  test("the run's real findings are untouched by it", async () => {
    const baseline = await normaliseFindings(collected, options);
    const result = await normaliseFindings([...collected, inTestCode], options);
    const production = result.findings.filter(
      (finding) => !finding.location.file.startsWith("src/__tests__/"),
    );
    // Byte-identical to the same run without the test-code finding in it.
    expect(JSON.stringify(production)).toBe(JSON.stringify(baseline.findings));
    for (const finding of production) {
      expect(finding.title).not.toContain("In test code:");
      expect(finding.description).not.toContain("(T1)");
    }
    // Severity is the document's primary sort key, so the capped finding sinks
    // to the bottom instead of heading the dossier.
    expect(result.findings[0]?.severity).toBe("critical");
    expect(result.findings[0]?.location.file).not.toBe(inTestCode.location.file);
  });

  test("a heuristic gitleaks secret in a test file stays where the model put it", async () => {
    const generic: Finding = {
      ...(collected[0] as Finding),
      id: "generictestsecre",
      domain: "appsec",
      rule: "appsec.hardcoded-secret",
      severity: "low",
      // `generic-api-key` is one of gitleaks' entropy rules, which the runner
      // grades `medium`: a lead, and indistinguishable from a fake token.
      confidence: "medium",
      title: "Hardcoded credential in src/orders.test.ts (generic-api-key)",
      location: { file: "src/orders.test.ts", line: 3 },
      source: { kind: "tool", name: "gitleaks" },
    };
    const result = await normaliseFindings([generic], options);
    const finding = result.findings[0];

    expect(finding?.severity).toBe("low");
    expect(finding?.title).toStartWith("In test code: ");
    // R1's floor is gated on the evidence since the false-positive measurement:
    // it applies to a provider-specific match, and a `generic-api-key` hit
    // (`confidence: "medium"`) keeps the severity `severity.ts#gradeSecret` gave
    // it. So there is nothing to raise here and nothing to cap back down — the
    // finding arrives at `low` and stays there, and the file is still labelled.
    expect(finding?.description).not.toContain("(R1)");
    expect(result.escalations).toHaveLength(0);
    expect(result.capped).toHaveLength(0);
  });

  test("a provider-matched secret in a test file keeps its severity", async () => {
    const aws: Finding = {
      ...(collected[0] as Finding),
      id: "awstestsecret000",
      domain: "appsec",
      rule: "appsec.hardcoded-secret",
      severity: "critical",
      // The runner grades a provider-specific rule id `high`; that is the only
      // thing this exception reads.
      confidence: "high",
      title: "Hardcoded cloud provider credential in src/orders.test.ts (aws-access-token)",
      location: { file: "src/orders.test.ts", line: 3 },
      source: { kind: "tool", name: "gitleaks" },
    };
    const result = await normaliseFindings([aws], options);
    const finding = result.findings[0];

    expect(finding?.severity).toBe("critical");
    expect(finding?.title).toStartWith("In test code: ");
    expect(finding?.description).toContain("(T3)");
    expect(result.capped).toEqual([]);
  });

  test("shuffling the input cannot change what the policy did", async () => {
    const input = [...collected, inTestCode];
    const straight = await normaliseFindings(input, options);
    const reversed = await normaliseFindings([...input].reverse(), options);
    expect(JSON.stringify(reversed.findings)).toBe(JSON.stringify(straight.findings));
    expect(reversed.capped).toEqual(straight.capped);
  });
});

describe("subsumption between tools", () => {
  test("hadolint's DL3007 disappears into Sentinel's floating-base-tag on the same line", async () => {
    expect(rules(hadolintStep.findings)).toContain("delivery.dockerfile.DL3007");
    const result = await normaliseFindings(collected, options);
    expect(rules(result.findings)).not.toContain("delivery.dockerfile.DL3007");

    const floating = result.findings.find(
      (finding) => finding.rule === "delivery.dockerfile.floating-base-tag",
    );
    expect(floating?.description).toContain("Also reported by hadolint");
    expect(result.merged).toContainEqual({
      id: floating?.id ?? "",
      rule: "delivery.dockerfile.floating-base-tag",
      file: "Dockerfile",
      line: 1,
      kept: "container-rules",
      alsoReportedBy: ["hadolint"],
    });
  });

  test("both DL3064 hits collapse, one per ENV line, not one for the file", async () => {
    const before = hadolintStep.findings.filter(
      (finding) => finding.rule === "delivery.dockerfile.DL3064",
    );
    expect(before).toHaveLength(2);
    const result = await normaliseFindings(collected, options);
    expect(rules(result.findings)).not.toContain("delivery.dockerfile.DL3064");
    // Sentinel's own rule still reports both lines.
    expect(
      result.findings.filter((finding) => finding.rule === "delivery.dockerfile.secret-in-env"),
    ).toHaveLength(2);
  });

  test("a hadolint check Sentinel has no rule for survives untouched", async () => {
    const result = await normaliseFindings(collected, options);
    const kept = result.findings.find((finding) => finding.rule === "delivery.dockerfile.DL3025");
    expect(kept).toBeDefined();
    expect(kept?.source.name).toBe("hadolint");
    expect(kept?.description).not.toContain("Also reported by");
  });

  /**
   * A trivy configuration check, shaped the way `parsers/trivy.ts` emits one:
   * every check shares the rule id `delivery.dockerfile-misconfig` and carries
   * its own id at the front of the title.
   */
  function trivyCheck(id: string, line: number, severity: Finding["severity"]): Finding {
    return {
      ...(collected[0] as Finding),
      id: `trivy${id.replace("-", "")}00000`.slice(0, 16),
      domain: "delivery",
      rule: "delivery.dockerfile-misconfig",
      severity,
      title: `${id}: what trivy calls it`,
      location: { file: "Dockerfile", line },
      source: { kind: "tool", name: "trivy" },
    };
  }

  test("trivy's DS-0029 disappears into apt-install-unpinned on the same line", async () => {
    const result = await normaliseFindings(
      [...collected, trivyCheck("DS-0029", 5, "high")],
      options,
    );
    // Left alone, this pair is one problem reported twice at two severities.
    expect(rules(result.findings)).not.toContain("delivery.dockerfile-misconfig");
    const own = result.findings.find(
      (finding) => finding.rule === "delivery.dockerfile.apt-install-unpinned",
    );
    expect(own?.severity).toBe("low");
    expect(own?.description).toContain("Also reported by");
    expect(own?.description).toContain("trivy");
  });

  test("DS-0002 and DS-0001 fold into runs-as-root and floating-base-tag", async () => {
    const result = await normaliseFindings(
      [...collected, trivyCheck("DS-0002", 1, "high"), trivyCheck("DS-0001", 1, "medium")],
      options,
    );
    expect(rules(result.findings)).not.toContain("delivery.dockerfile-misconfig");
    for (const rule of [
      "delivery.dockerfile.runs-as-root",
      "delivery.dockerfile.floating-base-tag",
    ]) {
      const own = result.findings.find((finding) => finding.rule === rule);
      expect(own?.description).toContain("Also reported by");
      expect(own?.description).toContain("trivy");
    }
  });

  /**
   * The fallback asks "is each of these the only one of its kind in this file?".
   * Every trivy check shares one rule id, so asking that question of the rule id
   * would count four unrelated checks as four of a kind and never fold any of
   * them; it has to be asked of the check id.
   */
  test("a DS check on another line still folds when three other checks are present", async () => {
    const result = await normaliseFindings(
      [
        ...collected,
        trivyCheck("DS-0026", 9, "low"),
        trivyCheck("DS-0002", 1, "high"),
        trivyCheck("DS-0029", 5, "high"),
      ],
      options,
    );
    expect(rules(result.findings)).not.toContain("delivery.dockerfile-misconfig");
    const own = result.findings.find(
      (finding) => finding.rule === "delivery.dockerfile.no-healthcheck",
    );
    expect(own?.description).toContain("Also reported by");
    expect(own?.description).toContain("trivy");
  });

  test("a trivy check Sentinel has no rule for survives untouched", async () => {
    const result = await normaliseFindings(
      [...collected, trivyCheck("DS-0005", 6, "low")],
      options,
    );
    const kept = result.findings.find(
      (finding) => finding.rule === "delivery.dockerfile-misconfig",
    );
    expect(kept?.title).toStartWith("DS-0005");
    expect(kept?.description).not.toContain("Also reported by");
  });

  test("actionlint's script-injection folds into Sentinel's, which says more", async () => {
    expect(rules(actionlintStep.findings)).toEqual(["delivery.workflow.script-injection"]);
    expect(RULE_OVERLAP["delivery.ci.script-injection"]).toEqual([
      "delivery.workflow.script-injection",
    ]);
    const result = await normaliseFindings(collected, options);
    expect(rules(result.findings)).not.toContain("delivery.workflow.script-injection");
    const own = result.findings.find((finding) => finding.rule === "delivery.ci.script-injection");
    expect(own?.description).toContain("Also reported by actionlint");
  });
});

describe("deduplication on (rule, file, line)", () => {
  test("the richer of two identical reports survives, naming the other", async () => {
    const original = collected.find(
      (finding) => finding.rule === "delivery.dockerfile.copy-all-without-dockerignore",
    ) as Finding;
    const thin: Finding = {
      ...original,
      id: "thinthinthinthin",
      description: "Short.",
      evidence: [],
      acceptanceCriteria: [],
      cwe: ["CWE-200"],
      source: { kind: "tool", name: "other-linter" },
    };
    expect(richness(original)).toBeGreaterThan(richness(thin));

    const result = await normaliseFindings([...collected, thin], options);
    const kept = result.findings.filter((finding) => finding.rule === original.rule);
    expect(kept).toHaveLength(1);
    expect(kept[0]?.source.name).toBe("container-rules");
    expect(kept[0]?.description).toContain("Also reported by other-linter");
    // The loser's metadata is folded in rather than thrown away.
    expect(kept[0]?.cwe).toContain("CWE-200");
  });

  test("which duplicate survives does not depend on the order they arrived in", async () => {
    const original = collected.find(
      (finding) => finding.rule === "delivery.compose.privileged",
    ) as Finding;
    const thin: Finding = {
      ...original,
      id: "thin2thin2thin20",
      description: "Short.",
      evidence: [],
      acceptanceCriteria: [],
      source: { kind: "tool", name: "other-linter" },
    };
    const forwards = await normaliseFindings([original, thin], options);
    const backwards = await normaliseFindings([thin, original], options);
    expect(forwards.findings).toEqual(backwards.findings);
  });

  test("two CVEs trivy reports at the same manifest line stay two findings", async () => {
    // trivy locates every vulnerability of a package at the line that resolves
    // the package, so rule, file and line are identical for both of these.
    const base = {
      ...(collected[0] as Finding),
      domain: "dependencies" as const,
      rule: "dependencies.vulnerable-package",
      severity: "high" as const,
      location: { file: "Dockerfile", line: 1 },
      source: { kind: "tool" as const, name: "trivy" },
    };
    const first: Finding = {
      ...base,
      id: "cve0000000000001",
      title: "CVE-2024-45590 in body-parser@1.19.0",
    };
    const second: Finding = {
      ...base,
      id: "cve0000000000002",
      title: "CVE-2024-29041 in body-parser@1.19.0",
    };

    const result = await normaliseFindings([first, second], options);
    expect(result.findings).toHaveLength(2);
    expect(result.merged).toEqual([]);
    expect(result.findings.map((finding) => finding.title).sort()).toEqual([
      "CVE-2024-29041 in body-parser@1.19.0",
      "CVE-2024-45590 in body-parser@1.19.0",
    ]);
  });

  test("one tool reporting one finding twice still collapses to one", async () => {
    const original = collected.find(
      (finding) => finding.rule === "delivery.compose.missing-restart",
    ) as Finding;
    const result = await normaliseFindings([original, { ...original }], options);
    expect(result.findings.filter((finding) => finding.rule === original.rule)).toHaveLength(1);
    expect(result.merged).toEqual([]);
  });

  test("the same rule on two different lines stays two findings", async () => {
    const result = await normaliseFindings(collected, options);
    const cacheLeft = result.findings.filter(
      (finding) => finding.rule === "delivery.dockerfile.package-manager-cache-left",
    );
    expect(cacheLeft.map((finding) => finding.location.line).sort()).toEqual([5, 7]);
  });
});

describe("ordering", () => {
  test("severity, then domain, then file, then line", async () => {
    const result = await normaliseFindings(collected, options);
    for (let index = 1; index < result.findings.length; index += 1) {
      const previous = result.findings[index - 1] as Finding;
      const current = result.findings[index] as Finding;
      expect(compareFindings(previous, current)).toBeLessThanOrEqual(0);
    }
    expect(result.findings[0]?.severity).toBe("critical");
  });

  test("shuffling the input cannot change the document", async () => {
    const shuffled = [...collected].reverse();
    const straight = await normaliseFindings(collected, options);
    const reversed = await normaliseFindings(shuffled, options);
    expect(JSON.stringify(reversed.findings)).toBe(JSON.stringify(straight.findings));
  });
});

describe("stable ids", () => {
  test("the id is a hash of what a finding is about, and of nothing else", () => {
    const id = stableFindingId(
      "delivery",
      "delivery.dockerfile.secret-in-env",
      "Dockerfile",
      "ENV:DATABASE_PASSWORD",
    );
    expect(id).toMatch(/^[0-9a-f]{16}$/);
    expect(id).toBe(
      stableFindingId(
        "delivery",
        "delivery.dockerfile.secret-in-env",
        "Dockerfile",
        "ENV:DATABASE_PASSWORD",
      ),
    );
    expect(id).not.toBe(
      stableFindingId(
        "delivery",
        "delivery.dockerfile.secret-in-env",
        "Dockerfile",
        "ARG:NPM_TOKEN",
      ),
    );
  });

  test("an unrelated edit above a finding does not mint a new id", async () => {
    const fs = createFileSystem();
    const dir = join(tmpdir(), `sentinel-id-stability-${Bun.randomUUIDv7()}`);
    scratch.push(dir);
    const dockerfile = join(dir, "Dockerfile");
    const original = await fs.readFile(join(FIXTURE_TARGET, "Dockerfile"));

    await fs.writeFile(dockerfile, original);
    const before = await runContainerRules(fixtureContext({ targetDir: dir }), {
      dockerfiles: ["Dockerfile"],
    });

    // A comment on line 1 pushes every instruction down by one line.
    await fs.writeFile(dockerfile, `# renovate: pin this base image\n${original}`);
    const after = await runContainerRules(fixtureContext({ targetDir: dir }), {
      dockerfiles: ["Dockerfile"],
    });

    const idOf = (outcome: typeof before, rule: string): string | undefined =>
      outcome.findings.find((finding) => finding.rule === rule)?.id;
    const lineOf = (outcome: typeof before, rule: string): number | undefined =>
      outcome.findings.find((finding) => finding.rule === rule)?.location.line;

    expect(lineOf(after, "delivery.dockerfile.secret-in-env")).toBe(
      (lineOf(before, "delivery.dockerfile.secret-in-env") ?? 0) + 1,
    );
    expect(idOf(after, "delivery.dockerfile.secret-in-env")).toBe(
      idOf(before, "delivery.dockerfile.secret-in-env"),
    );
  });

  test("a finding whose producer left the id blank gets one", async () => {
    const blank: Finding = { ...(collected[0] as Finding), id: "" };
    const result = await normaliseFindings([blank], options);
    expect(result.findings[0]?.id).toMatch(/^[0-9a-f]{16}$/);
  });
});

/** Temp directories the id-stability test created. */
const scratch: string[] = [];

afterAll(async () => {
  const fs = createFileSystem();
  for (const dir of scratch) await fs.remove(dir);
});
