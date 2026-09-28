import { describe, expect, test } from "bun:test";
import type { Finding, Severity } from "../contracts/findings.ts";
import {
  SEVERITY_ORDER,
  type SecretContext,
  type SecretJudgement,
  atLeast,
  classifySecretName,
  classifySecretRule,
  classifySecretValue,
  compareSeverity,
  cveIdOf,
  escalate,
  escalateFinding,
  fromCvssScore,
  fromLintLevel,
  fromSarifLevel,
  fromToolSeverity,
  fromTrivySeverity,
  gradeSecret,
  isDemotedSecret,
  maxSeverity,
  severityRank,
  shannonEntropy,
  signalsOf,
} from "./severity.ts";

/**
 * The severity words in these tests are the ones the pinned tools actually
 * print: hadolint 2.15.1 emits `"level": "warning"` / `"info"` (see
 * `__fixtures__/hadolint-dockerfile.json`), trivy 0.74.0 emits `"Severity":
 * "CRITICAL"`, and gitleaks/opengrep emit SARIF `"level": "error"`.
 */

/** A finding with the shape the runners build, overridable field by field. */
function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "0123456789abcdef",
    domain: "appsec",
    rule: "appsec.hardcoded-secret",
    severity: "medium",
    confidence: "high",
    title: "Hardcoded credential in src/config.ts (generic-api-key)",
    description: "gitleaks matched its `generic-api-key` pattern.",
    location: { file: "src/config.ts", line: 4, snippet: "const key = [REDACTED];" },
    evidence: [],
    impact: "Anyone with read access can authenticate as this application.",
    recommendation: "Rotate the credential.",
    acceptanceCriteria: [],
    cwe: ["CWE-798: Use of Hard-coded Credentials"],
    owasp: [],
    source: { kind: "tool", name: "gitleaks" },
    ...overrides,
  };
}

describe("ordering", () => {
  test("ranks most severe first, which is the document's primary sort key", () => {
    expect(SEVERITY_ORDER).toEqual(["critical", "high", "medium", "low", "info"]);
    expect(severityRank("critical")).toBe(0);
    expect(severityRank("info")).toBe(4);
    expect(compareSeverity("critical", "low")).toBeLessThan(0);
    expect(compareSeverity("low", "low")).toBe(0);
  });

  test("maxSeverity and atLeast raise but never lower", () => {
    expect(maxSeverity("low", "critical")).toBe("critical");
    expect(atLeast("low", "high")).toBe("high");
    expect(atLeast("critical", "high")).toBe("critical");
  });
});

describe("translation", () => {
  test("reads hadolint's own vocabulary, as captured from 2.15.1", () => {
    expect(fromLintLevel("warning")).toBe("medium");
    expect(fromLintLevel("info")).toBe("low");
    expect(fromLintLevel("error")).toBe("high");
    expect(fromLintLevel("style")).toBe("info");
  });

  test("reads trivy's severity word case-insensitively", () => {
    expect(fromTrivySeverity("CRITICAL")).toBe("critical");
    expect(fromTrivySeverity("critical")).toBe("critical");
    expect(fromTrivySeverity("MEDIUM")).toBe("medium");
    expect(fromTrivySeverity("UNKNOWN")).toBe("info");
  });

  test("reads SARIF levels, which is what gitleaks and opengrep emit", () => {
    expect(fromSarifLevel("error")).toBe("high");
    expect(fromSarifLevel("warning")).toBe("medium");
    expect(fromSarifLevel("note")).toBe("low");
  });

  test("maps CVSS v3.1 scores onto the standard bands", () => {
    const bands: Array<[number, Severity]> = [
      [9.8, "critical"],
      [9, "critical"],
      [8.1, "high"],
      [7, "high"],
      [5.3, "medium"],
      [4, "medium"],
      [3.7, "low"],
      [0, "info"],
    ];
    for (const [score, expected] of bands) expect(fromCvssScore(score)).toBe(expected);
  });

  test("a word no table knows is info, never an invented alarm", () => {
    expect(fromToolSeverity("lint", "catastrophic")).toBe("info");
    expect(fromToolSeverity("trivy", undefined)).toBe("info");
    expect(fromCvssScore(Number.NaN)).toBe("info");
  });
});

describe("R1 — a committed provider-specific credential is never below high", () => {
  test("raises a secret the tool graded low", () => {
    const decision = escalate("low", { secret: "worktree", secretEvidence: "provider-specific" });
    expect(decision.severity).toBe("high");
    expect(decision.escalated).toBe(true);
    expect(decision.rationale).toContain("(R1)");
  });

  test("a secret that survives only in history is still high", () => {
    const decision = escalate("info", {
      secret: "history-only",
      secretEvidence: "provider-specific",
    });
    expect(decision.severity).toBe("high");
    expect(decision.rationale).toContain("deleting a file does not revoke a credential");
  });

  test("never lowers a secret the tool already graded critical", () => {
    const decision = escalate("critical", {
      secret: "worktree",
      secretEvidence: "provider-specific",
    });
    expect(decision.severity).toBe("critical");
    expect(decision.escalated).toBe(false);
    expect(decision.rationale).toBeUndefined();
  });

  /**
   * The specificity gate. Most of what a secret scanner matches in a real
   * repository is `generic-api-key`, so an unconditional floor is a floor under
   * every Kubernetes secret *name*, every public identifier and every
   * placeholder in the tree. A heuristic match now keeps the severity the model
   * gave it.
   */
  test("a shape-and-entropy match keeps the severity the model gave it", () => {
    expect(escalate("info", { secret: "worktree", secretEvidence: "heuristic" }).severity).toBe(
      "info",
    );
    expect(escalate("low", { secret: "history-only", secretEvidence: "heuristic" }).escalated).toBe(
      false,
    );
  });

  test("a producer that does not say how it matched gets no floor either", () => {
    // Missing information must not be able to manufacture an alarm, so the
    // default is the weaker reading, not the stronger one.
    expect(escalate("low", { secret: "worktree" }).severity).toBe("low");
  });
});

describe("R2 — a live cloud key is critical", () => {
  test("a cloud account credential outranks whatever the tool said", () => {
    const decision = escalate("medium", { secret: "worktree", credential: "cloud" });
    expect(decision.severity).toBe("critical");
    expect(decision.rationale).toContain("(R2)");
  });

  test("a private key is critical because it cannot be rotated away from the past", () => {
    const decision = escalate("high", { secret: "worktree", credential: "private-key" });
    expect(decision.severity).toBe("critical");
    expect(decision.rationale).toContain("already signed or decrypted");
  });

  test("a generic credential stops at the R1 floor", () => {
    expect(
      escalate("low", {
        secret: "worktree",
        secretEvidence: "provider-specific",
        credential: "generic",
      }).severity,
    ).toBe("high");
  });
});

describe("R3 — a known exploit outranks the CVSS band", () => {
  test("a medium CVE that is being exploited today is critical", () => {
    const decision = escalate("medium", { knownExploited: true });
    expect(decision.severity).toBe("critical");
    expect(decision.rationale).toContain("(R3)");
  });

  test("a CVE that is merely scored is left where the vendor put it", () => {
    expect(escalate("medium", { knownExploited: false }).severity).toBe("medium");
    expect(escalate("medium", {}).severity).toBe("medium");
  });
});

describe("signalsOf", () => {
  test("reads a worktree secret from the snippet the verifier could extract", () => {
    expect(signalsOf(finding()).secret).toBe("worktree");
  });

  test("a secret with no readable snippet lives only in history", () => {
    const historical = finding({
      location: { file: "src/old.ts", line: 4, note: "still reachable in commit abc1234567" },
    });
    expect(signalsOf(historical).secret).toBe("history-only");
  });

  test("CWE-321 identifies key material", () => {
    const key = finding({ cwe: ["CWE-798: Use of Hard-coded Credentials", "CWE-321: Key"] });
    expect(signalsOf(key).credential).toBe("private-key");
  });

  test("an entropy match is a lead, so R2 and the R1 floor are both withheld", () => {
    const heuristic = finding({
      confidence: "medium",
      title: "Hardcoded cloud provider credential in .env",
    });
    expect(signalsOf(heuristic).credential).toBeUndefined();
    expect(signalsOf(heuristic).secretEvidence).toBe("heuristic");
    // The words "cloud provider credential" in a title cannot manufacture a
    // critical, and a medium-confidence match cannot manufacture a high.
    expect(escalateFinding(heuristic).severity).toBe("medium");
  });

  test("confidence is the evidence channel, and high means provider-specific", () => {
    expect(signalsOf(finding({ confidence: "high" })).secretEvidence).toBe("provider-specific");
    expect(signalsOf(finding({ confidence: "low" })).secretEvidence).toBe("heuristic");
    // A finding that is not a secret carries no secret signal at all.
    expect(
      signalsOf(finding({ rule: "appsec.injection.sql-built-from-variables" })).secretEvidence,
    ).toBeUndefined();
  });

  test("R3 stays inert until a caller supplies a known-exploited feed", () => {
    const cve = finding({
      rule: "dependencies.vulnerable-package",
      domain: "dependencies",
      severity: "medium",
      title: "CVE-2024-21538 in cross-spawn@7.0.3",
      location: { file: "package-lock.json", line: 12, snippet: '"cross-spawn": "7.0.3"' },
      cwe: [],
      source: { kind: "tool", name: "trivy" },
    });
    expect(cveIdOf(cve)).toBe("CVE-2024-21538");
    expect(escalateFinding(cve).severity).toBe("medium");
    expect(escalateFinding(cve, { knownExploitedCves: new Set(["CVE-2024-21538"]) }).severity).toBe(
      "critical",
    );
    expect(escalateFinding(cve, { knownExploitedCves: new Set(["CVE-2021-44228"]) }).severity).toBe(
      "medium",
    );
  });

  test("no CVE id in the title means nothing to look up", () => {
    expect(cveIdOf(finding())).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The secret-strength model
// ---------------------------------------------------------------------------

/**
 * A credential-shaped stand-in, generated rather than written out: the label says
 * what it stands for, and every character after it is a function of its position.
 * A reader can see that nothing was copied in from anywhere, and a secret scanner
 * reading this file has no credential-shaped literal to match — while the value
 * still has the length and the entropy `classifySecretValue` asks of a credible
 * one, which is the whole point of the rows below.
 */
function syntheticValue(label: string, length: number): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let value = `synthetic-${label}-`;
  for (let index = 0; value.length < length; index += 1) {
    value += alphabet.charAt((index * 29 + 7) % alphabet.length);
  }
  return value;
}

/**
 * The positions a secret scanner matches in, and what each one is really worth.
 *
 * The cases below are the seven shapes that make this model necessary, built in
 * an invented **lending-library service** so that no row describes anybody's
 * repository:
 *
 * | where | what a generic rule matches |
 * |---|---|
 * | a Helm chart | `key: LOAN_RATE_POINTS_<id>` under `secretKeyRef:` |
 * | the same chart | `credentialKey: <id>`, the string the chart addresses a consumer by |
 * | `.env.example` | `LENDING_SSO_CLIENT_ID=<32 characters>` |
 * | `.env.example` | `LENDING_SSO_CLIENT_SECRET=<64 characters>` |
 * | a README usage line | `… <token> --account-id=123 --member-id=123 …` |
 * | a Makefile help line | ``## Decode a JWT. Usage: `JWT=eyJhbGciOiJIU... make jwt-decode` `` |
 * | a source file | `const ACCESS_TOKEN = '<36 characters>'` |
 *
 * Every value is generated by {@link syntheticValue}: a tool that exists to stop
 * credentials being committed does not commit one into its own fixtures, and it
 * does not write a literal that a scanner would have to match either.
 */
const CLIENT_ID = syntheticValue("client-id", 32);
const CLIENT_SECRET = syntheticValue("client-secret", 64);
const CONSUMER_ID = syntheticValue("consumer-id", 24);
const SERVICE_TOKEN = syntheticValue("service-token", 36);

describe("classifySecretValue", () => {
  test("the integer 123 is not a credential, however it was matched", () => {
    // A scanner reports `--account-id=123` and `JWT_SUBJECT=123` as credentials;
    // no three-character decimal is a credential of any kind.
    expect(classifySecretValue("123")).toBe("trivial");
    expect(classifySecretValue("1234567890123456")).toBe("trivial");
    expect(classifySecretValue("xxxxxxxxxxxxxxxxxxxx")).toBe("trivial");
    // `abc456` is on the placeholder list rather than merely short: it is what a
    // README usage line puts after `--access-token=`.
    expect(classifySecretValue("abc456")).toBe("placeholder");
  });

  test("an elided example is a placeholder, and a JWT needs three segments", () => {
    expect(classifySecretValue("eyJhbGciOiJIU...")).toBe("placeholder");
    // A header-only prefix without the two other segments carries no secret.
    expect(classifySecretValue("eyJhbGciOiJIUzI1NiJ9")).toBe("placeholder");
    expect(classifySecretValue("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIwIn0.QWxsT2ZJdA")).toBe("credible");
  });

  test("a slot to be filled in is a placeholder", () => {
    for (const value of [
      "<your-key>",
      "${API_KEY}",
      "{{ .Values.key }}",
      "changeme",
      "CHANGEME!",
    ]) {
      expect(classifySecretValue(value)).toBe("placeholder");
    }
  });

  test("the shapes a credential really has come back credible", () => {
    expect(classifySecretValue(CLIENT_ID)).toBe("credible");
    expect(classifySecretValue(CLIENT_SECRET)).toBe("credible");
    expect(classifySecretValue(CONSUMER_ID)).toBe("credible");
    expect(classifySecretValue(SERVICE_TOKEN)).toBe("credible");
  });

  test("a value the caller could not read is unknown, not assumed either way", () => {
    expect(classifySecretValue(undefined)).toBe("unknown");
  });

  test("entropy is measured, not guessed", () => {
    expect(shannonEntropy("")).toBe(0);
    expect(shannonEntropy("aaaa")).toBe(0);
    expect(shannonEntropy("123")).toBeCloseTo(Math.log2(3), 5);
    expect(shannonEntropy(CLIENT_ID)).toBeGreaterThan(3);
  });
});

describe("classifySecretName", () => {
  test("the public half and the secret half of an SSO block are told apart", () => {
    expect(classifySecretName("LENDING_SSO_CLIENT_ID")).toBe("identifier");
    expect(classifySecretName("LENDING_SSO_CLIENT_SECRET")).toBe("secret");
    expect(classifySecretName("LENDING_JWT_SIGNING_KEY")).toBe("secret");
    expect(classifySecretName("LENDING_TOKEN_ENCRYPTION_KEY")).toBe("secret");
  });

  test("an id that contains a secret word is still an id", () => {
    expect(classifySecretName("API_KEY_ID")).toBe("identifier");
    expect(classifySecretName("AWS_ACCESS_KEY_ID")).toBe("identifier");
    expect(classifySecretName("account-id")).toBe("identifier");
  });

  test("names the table does not know are unknown rather than assumed", () => {
    // A gateway chart's `credentialKey` is an access id in one deployment and the
    // secret half in another, so the name decides nothing and the reuse signal
    // does.
    expect(classifySecretName("credentialKey")).toBe("unknown");
    expect(classifySecretName(undefined)).toBe("unknown");
  });
});

describe("classifySecretRule", () => {
  test("the four classes, from the rule ids gitleaks ships", () => {
    expect(classifySecretRule("private-key")).toBe("private-key");
    expect(classifySecretRule("aws-access-token")).toBe("cloud");
    expect(classifySecretRule("github-pat")).toBe("provider");
    expect(classifySecretRule("generic-api-key")).toBe("generic");
    expect(classifySecretRule("jwt")).toBe("generic");
    // A rule id Sentinel has never seen is read as a heuristic, so an unknown
    // scanner cannot manufacture a provider-grade finding.
    expect(classifySecretRule("")).toBe("generic");
  });
});

/** One row of the model: facts in, the judgement and grade expected out. */
interface GradeCase {
  readonly what: string;
  readonly ruleId: string;
  readonly name?: string;
  readonly value?: string;
  readonly context: SecretContext;
  readonly reusedAsName?: boolean;
  readonly judgement: SecretJudgement;
  readonly severity: Severity;
  readonly confidence: "high" | "medium" | "low";
}

const CASES: readonly GradeCase[] = [
  {
    what: "a Helm chart's secretKeyRef — the name of a key in an external Secret",
    ruleId: "generic-api-key",
    name: "key",
    value: `LOAN_RATE_POINTS_${CONSUMER_ID}`,
    context: "reference",
    judgement: "secret-reference",
    severity: "info",
    confidence: "low",
  },
  {
    what: "an access id the same chart uses as a key name",
    ruleId: "generic-api-key",
    name: "credentialKey",
    value: CONSUMER_ID,
    context: "assignment",
    reusedAsName: true,
    judgement: "public-identifier",
    severity: "low",
    confidence: "medium",
  },
  {
    what: "an OAuth client_id in a template file, which is sent in the clear",
    ruleId: "generic-api-key",
    name: "LENDING_SSO_CLIENT_ID",
    value: CLIENT_ID,
    context: "template",
    judgement: "public-identifier",
    severity: "low",
    confidence: "medium",
  },
  {
    what: "the client secret beside it, which is not a placeholder",
    ruleId: "generic-api-key",
    name: "LENDING_SSO_CLIENT_SECRET",
    value: CLIENT_SECRET,
    context: "template",
    judgement: "likely-credential",
    severity: "high",
    confidence: "medium",
  },
  {
    what: "the integer 123 in a README usage line",
    ruleId: "generic-api-key",
    name: "account-id",
    value: "123",
    context: "documentation",
    judgement: "placeholder",
    severity: "info",
    confidence: "low",
  },
  {
    what: "an ellipsised JWT header in a Makefile `##` help string",
    ruleId: "generic-api-key",
    name: "JWT",
    value: "eyJhbGciOiJIU...",
    context: "documentation",
    judgement: "placeholder",
    severity: "info",
    confidence: "low",
  },
  {
    what: "a service's own access token, assigned in source",
    ruleId: "generic-api-key",
    name: "ACCESS_TOKEN",
    value: SERVICE_TOKEN,
    context: "assignment",
    judgement: "likely-credential",
    severity: "high",
    confidence: "medium",
  },
  {
    what: "a blob Sentinel could not read back",
    ruleId: "generic-api-key",
    context: "unknown",
    judgement: "unverified-match",
    severity: "medium",
    confidence: "low",
  },
  {
    what: "a cloud access key id, wherever it sits",
    ruleId: "aws-access-token",
    name: "AWS_ACCESS_KEY_ID",
    value: syntheticValue("cloud-key", 32),
    context: "assignment",
    judgement: "provider-credential",
    severity: "critical",
    confidence: "high",
  },
  {
    what: "a GitHub token: provider-specific, but not a cloud account",
    ruleId: "github-pat",
    // A single repeated character: the rule is what makes this a credential, so
    // the stand-in does not need to look like one, and this row proves the value
    // gate cannot swallow a provider match.
    value: `ghp_${"x".repeat(36)}`,
    name: "GITHUB_TOKEN",
    context: "assignment",
    judgement: "provider-credential",
    severity: "high",
    confidence: "high",
  },
  {
    what: "a vendor's own documentation example, which is not a credential",
    ruleId: "aws-access-token",
    name: "AWS_ACCESS_KEY_ID",
    // The key every AWS document uses, assembled from two pieces so that no
    // complete provider-format string is written in this file — and elided, which
    // is what makes it a placeholder whatever rule matched it.
    value: `AKIA${"IOSFODNN7EXAMPLE"}...`,
    context: "documentation",
    judgement: "placeholder",
    severity: "info",
    confidence: "low",
  },
];

describe("gradeSecret over the positions a scanner matches in", () => {
  for (const row of CASES) {
    test(row.what, () => {
      const grade = gradeSecret({
        ruleId: row.ruleId,
        ...(row.name === undefined ? {} : { name: row.name }),
        ...(row.value === undefined ? {} : { value: row.value }),
        context: row.context,
        ...(row.reusedAsName === undefined ? {} : { reusedAsName: row.reusedAsName }),
      });
      expect(grade.judgement).toBe(row.judgement);
      expect(grade.severity).toBe(row.severity);
      expect(grade.confidence).toBe(row.confidence);
      // Every grade says why, and a demoted one says what would change it.
      expect(grade.why.length).toBeGreaterThan(20);
      if (grade.judgement === "provider-credential") {
        expect(grade.whatWouldConfirm).toBeNull();
      } else {
        expect(grade.whatWouldConfirm).not.toBeNull();
      }
    });
  }

  test("only a provider-specific match carries high confidence", () => {
    // R1 in this module and T3 in `_file-kind.ts` both read `confidence === "high"`
    // as "a provider-specific rule matched". This is what makes that true.
    for (const row of CASES) {
      const grade = gradeSecret({
        ruleId: row.ruleId,
        ...(row.name === undefined ? {} : { name: row.name }),
        ...(row.value === undefined ? {} : { value: row.value }),
        context: row.context,
      });
      expect(grade.confidence === "high").toBe(grade.evidence === "provider-specific");
      expect(grade.evidence === "provider-specific").toBe(
        grade.judgement === "provider-credential",
      );
    }
  });

  test("a demoted judgement is named as one, so the run can count it", () => {
    expect(isDemotedSecret("secret-reference")).toBe(true);
    expect(isDemotedSecret("public-identifier")).toBe(true);
    expect(isDemotedSecret("placeholder")).toBe(true);
    expect(isDemotedSecret("documented-example")).toBe(true);
    expect(isDemotedSecret("likely-credential")).toBe(false);
    expect(isDemotedSecret("provider-credential")).toBe(false);
    expect(isDemotedSecret("unverified-match")).toBe(false);
  });

  test("a credential in a template file keeps its severity; a placeholder does not", () => {
    const real = gradeSecret({
      ruleId: "generic-api-key",
      name: "LENDING_JWT_SIGNING_KEY",
      value: syntheticValue("signing-key", 64),
      context: "template",
    });
    expect(real.severity).toBe("high");
    expect(real.hygiene).toBe(false);

    const slot = gradeSecret({
      ruleId: "generic-api-key",
      name: "LENDING_JWT_SIGNING_KEY",
      value: "<your-signing-key>",
      context: "template",
    });
    expect(slot.severity).toBe("info");
    expect(slot.hygiene).toBe(true);
  });

  test("the escalation that follows agrees with the grade", () => {
    // The model grades, then R1 either backs it or stays out of the way. The two
    // must not disagree, which is the composition an unconditional floor got wrong.
    for (const row of CASES) {
      const grade = gradeSecret({
        ruleId: row.ruleId,
        ...(row.name === undefined ? {} : { name: row.name }),
        ...(row.value === undefined ? {} : { value: row.value }),
        context: row.context,
        ...(row.reusedAsName === undefined ? {} : { reusedAsName: row.reusedAsName }),
      });
      const after = escalate(grade.severity, {
        secret: "worktree",
        secretEvidence: grade.evidence,
      });
      expect(after.severity).toBe(grade.severity);
    }
  });
});
