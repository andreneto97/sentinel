import { describe, expect, test } from "bun:test";
import type { Finding, Severity } from "../contracts/findings.ts";
import {
  FILE_KIND_ORDER,
  FILE_KIND_POLICY,
  FILE_KIND_RULES,
  type FileKind,
  classifyFile,
  decideFileKind,
  isNonProduction,
  isRotationRequiredSecret,
  withoutFileKindPrefix,
} from "./_file-kind.ts";
import { confidenceForRule, severityForRule } from "./runners/gitleaks.ts";
import { escalateFinding, gradeSecret } from "./severity.ts";

/**
 * A credential-shaped stand-in, generated rather than written out: the label says
 * what it stands for, and every character after it is a function of its position.
 * A reader can see that nothing was copied in from anywhere, and a secret scanner
 * reading this file has no credential-shaped literal to match — while the value
 * still has the length and the entropy `classifySecretValue` asks of a credible
 * one, which is what these tests need it to have.
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
 * The corpus the table is graded against: a **lending-library service** — a
 * lending API, a notifier, a staff portal, a catalogue library and a Helm chart —
 * plus this repository's own paths. The service is invented; the *shapes* are the
 * conventions every Node monorepo uses, which is the only thing a classifier can
 * read.
 *
 * The first column is the path; the second is what it has to be classified as.
 * Every `production` row is a path that a careless pattern would misfile —
 * `.github/workflows/tests.yaml` is the CI pipeline, and `service-tests/` only
 * *reads* like a test path.
 *
 * Two rows are the ones a careless classifier gets backwards. `README-TEST.md` and
 * `test-local.ts` look like paths that merely *read* as tests, and classifying
 * them as production is how a fenced usage line's `--account-id=123` is reported
 * as a `high` hardcoded credential, and how the same line printed by a harness's
 * `console.log` is reported twice more. Both are classified here, and
 * `apps/staff-portal/jest.config.ts` stays `production` because it is
 * configuration the build reads, not a test.
 */
const CORPUS: ReadonlyArray<readonly [string, FileKind]> = [
  // --- the lending-library monorepo -----------------------------------------
  ["apps/lending-api/src/http/middlewares/auth.test.ts", "test"],
  ["apps/lending-api/src/http/v1/holdings/bulk-update.test.ts", "test"],
  ["libs/lending/application/holds/service-tests/expiry.test.ts", "test"],
  ["libs/catalogue/infra/repositories/marc/marc.generated.spec.ts", "test"],
  ["libs/test-helpers/api-client.ts", "test"],
  ["libs/test-helpers/factories/member-factory.ts", "test"],
  ["libs/test-helpers/mocks/queue-client.mock.ts", "fixture"],
  ["apps/lending-api/src/http/v1/receipts/__snapshots__/render-receipt.test.ts.snap", "fixture"],
  ["ops/kubernetes/charts/lending-api/templates/tests/test-connection.yaml", "test"],
  ["@types/express/index.d.ts", "generated"],
  ["apps/lending-api/src/http/middlewares/auth.ts", "production"],
  ["libs/persistence/migrations/1730419200000-AddHoldExpiryIndex.ts", "production"],
  ["apps/notifier/src/workers/task-handlers/overdue-notice.handler.ts", "production"],
  // A workflow that runs the test suite is still the pipeline that holds the
  // deploy credentials, so what it is named after does not make it test code.
  [".github/workflows/tests.yaml", "production"],
  ["services/hold-reminder/test-local.ts", "test"],
  ["services/hold-reminder/README-TEST.md", "documentation"],
  [".env.example", "example"],
  ["apps/staff-portal/jest.config.ts", "production"],
  ["ops/dev-stack/Dockerfile", "production"],
  // The one `.md` that must stay out of the documentation bucket is none of
  // them: even `apps/lending-api/README.md` is documentation. What must not move
  // is a path that merely contains the word.
  ["src/markdown/render.ts", "production"],
  ["libs/members/application/docsigning/consent.ts", "production"],
  // --- a Next.js branch portal, in the same shape ---------------------------
  ["src/app/branches/reservations/actions.ts", "production"],
  ["src/lib/sms/send.ts", "production"],
  ["supabase/migrations/20260401090000_create_reservations.sql", "production"],
  ["node_modules/next/dist/server/index.js", "vendored"],
  [".next/server/app/page.js", "generated"],
  // --- Sentinel's own repository, which the enumerators are tested against ---
  ["src/inventory/__fixtures__/route-target/src/server/express-app.ts", "fixture"],
  ["src/scan/normalise.test.ts", "test"],
];

describe("classifying the paths a monorepo is made of", () => {
  for (const [path, expected] of CORPUS) {
    test(`${path} is ${expected}`, () => {
      expect(classifyFile(path).kind).toBe(expected);
    });
  }

  test("a production path carries no pattern, and a classified one names its shape", () => {
    expect(classifyFile("src/lib/auth.ts")).toEqual({ kind: "production", pattern: null });
    expect(classifyFile("apps/lending-api/src/auth.test.ts")).toEqual({
      kind: "test",
      pattern: "*.test.*",
    });
  });

  test("the sharpest signal wins: a generated spec file is a test", () => {
    // `.spec.` says "this file asserts things" more precisely than `.generated.`
    // says "a tool wrote it", and both put it outside production either way.
    expect(
      classifyFile("libs/catalogue/infra/repositories/marc/marc.generated.spec.ts").pattern,
    ).toBe("*.spec.*");
    expect(classifyFile("libs/catalogue/infra/repositories/marc/marc.generated.ts").pattern).toBe(
      "*.generated.*",
    );
  });

  test("build output beats the basename, so a compiled test is build output", () => {
    expect(classifyFile("dist/handlers.test.js").kind).toBe("generated");
    expect(classifyFile("node_modules/pkg/index.test.js").kind).toBe("vendored");
  });
});

describe("the shapes are matched as path segments, not as substrings", () => {
  test("a directory whose name merely contains a shape is production code", () => {
    expect(classifyFile("src/latest/handler.ts").kind).toBe("production");
    expect(classifyFile("src/contested/handler.ts").kind).toBe("production");
    expect(classifyFile("src/rebuild/index.ts").kind).toBe("production");
    expect(classifyFile("src/distribution/index.ts").kind).toBe("production");
    expect(classifyFile("src/e2ee/crypto.ts").kind).toBe("production");
  });

  test("a basename whose name merely contains a shape is production code", () => {
    expect(classifyFile("src/latest.ts").kind).toBe("production");
    expect(classifyFile("src/protest.ts").kind).toBe("production");
    expect(classifyFile("src/manifest.spec.json").kind).toBe("production");
  });

  test("separators, a ./ prefix and upper case are normalised away", () => {
    expect(classifyFile("apps\\lending-api\\src\\auth.test.ts").kind).toBe("test");
    expect(classifyFile("./apps/lending-api/src/auth.test.ts").kind).toBe("test");
    expect(classifyFile("/apps/lending-api/src/auth.test.ts").kind).toBe("test");
    expect(classifyFile("src/__TESTS__/Auth.TS").kind).toBe("test");
  });

  test("every rule is a stateless matcher, so asking twice gives one answer", () => {
    for (const rule of FILE_KIND_RULES) {
      expect(rule.match.flags).not.toContain("g");
      expect(rule.pattern).not.toBe("");
    }
    expect(classifyFile("src/auth.test.ts")).toEqual(classifyFile("src/auth.test.ts"));
  });
});

describe("the severity policy table", () => {
  test("test and fixture code are capped; generated and vendored code is not", () => {
    expect(FILE_KIND_POLICY.test.cap).toBe("low");
    expect(FILE_KIND_POLICY.fixture.cap).toBe("low");
    // Generated and vendored code compiles into the artifact that serves
    // requests, so lowering a finding in it would be hiding a live risk.
    expect(FILE_KIND_POLICY.generated.cap).toBeNull();
    expect(FILE_KIND_POLICY.vendored.cap).toBeNull();
    expect(FILE_KIND_POLICY.production.cap).toBeNull();
  });

  test("only the capped kinds prefix the title, and they say what they are", () => {
    expect(FILE_KIND_POLICY.test.titlePrefix).toBe("In test code: ");
    expect(FILE_KIND_POLICY.fixture.titlePrefix).toBe("In test fixture code: ");
    expect(FILE_KIND_POLICY.generated.titlePrefix).toBe("");
    expect(FILE_KIND_POLICY.production.titlePrefix).toBe("");
  });

  test("isNonProduction is true for everything the table classifies", () => {
    expect(isNonProduction("production")).toBe(false);
    for (const rule of FILE_KIND_RULES) expect(isNonProduction(rule.kind)).toBe(true);
  });
});

/** A finding shaped like the ones the runners build, with nothing else in it. */
function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "aaaaaaaaaaaaaaaa",
    domain: "appsec",
    rule: "appsec.auth.jwt-hardcoded-secret",
    severity: "critical",
    confidence: "high",
    title: "JWT secret hardcoded in the source",
    description: "The JWT signing secret is a literal in the source.",
    location: { file: "apps/lending-api/src/http/middlewares/auth.test.ts", line: 131 },
    evidence: [],
    impact: "Anyone with read access can forge a token for any user.",
    recommendation: "Read the secret from the environment.",
    acceptanceCriteria: [],
    cwe: [],
    owasp: [],
    source: { kind: "rule", name: "opengrep" },
    ...overrides,
  };
}

describe("deciding one finding", () => {
  test("a critical finding in a test file becomes low, and says why", () => {
    const decision = decideFileKind(finding());
    expect(decision.kind).toBe("test");
    expect(decision.severity).toBe("low");
    expect(decision.capped).toBe(true);
    expect(decision.titlePrefix).toBe("In test code: ");
    // Nothing is lost: the sentence names the severity it came from and where
    // the untouched grade still is.
    expect(decision.rationale).toContain("capped this at low (T1)");
    expect(decision.rationale).toContain("graded critical before the cap");
    expect(decision.rationale).toContain("`raw/`");
    expect(decision.rationale).toContain("`*.test.*`");
  });

  test("a finding in production code is not touched at all", () => {
    const decision = decideFileKind(
      finding({ location: { file: "apps/lending-api/src/http/middlewares/auth.ts", line: 40 } }),
    );
    expect(decision).toEqual({
      kind: "production",
      pattern: null,
      severity: "critical",
      capped: false,
      exempt: false,
      titlePrefix: "",
      rationale: null,
    });
  });

  test("a finding already at or below the cap keeps its severity and gains no sentence", () => {
    for (const severity of ["low", "info"] as const) {
      const decision = decideFileKind(finding({ severity }));
      expect(decision.severity).toBe(severity);
      expect(decision.capped).toBe(false);
      expect(decision.rationale).toBeNull();
      // The reader is still told where the code lives; that costs nothing.
      expect(decision.titlePrefix).toBe("In test code: ");
    }
  });

  test("a finding in generated or vendored code keeps its severity", () => {
    for (const file of ["dist/server.js", "node_modules/pkg/index.js"]) {
      const decision = decideFileKind(finding({ location: { file, line: 1 } }));
      expect(decision.severity).toBe("critical");
      expect(decision.capped).toBe(false);
      expect(decision.rationale).toBeNull();
    }
  });
});

/** A gitleaks secret finding, graded the way the runner grades that rule id. */
function secret(ruleId: string, file: string): Finding {
  const severity: Severity = severityForRule(ruleId);
  return finding({
    rule: "appsec.hardcoded-secret",
    severity,
    confidence: confidenceForRule(ruleId),
    title: `Hardcoded credential in ${file} (${ruleId})`,
    location: { file, line: 24 },
    source: { kind: "tool", name: "gitleaks" },
  });
}

describe("T3 — the credential that has to be rotated wherever it lives", () => {
  /**
   * The exception reads gitleaks' own rule id, through the `confidence` the
   * runner derives from it. These two assertions are the contract: if
   * `confidenceForRule` ever grades `generic-api-key` as high, the exception
   * would swallow every entropy hit in every test file — and this fails first.
   */
  test("gitleaks' heuristics are medium confidence and its provider rules are high", () => {
    expect(confidenceForRule("generic-api-key")).toBe("medium");
    expect(confidenceForRule("jwt")).toBe("medium");
    expect(confidenceForRule("aws-access-token")).toBe("high");
    expect(confidenceForRule("private-key")).toBe("high");
  });

  test("a cloud access key committed into a test file stays critical", () => {
    const cloud = secret("aws-access-token", "apps/lending-api/src/http/middlewares/auth.test.ts");
    expect(cloud.severity).toBe("critical");
    expect(isRotationRequiredSecret(cloud)).toBe(true);

    const decision = decideFileKind(cloud);
    expect(decision.kind).toBe("test");
    expect(decision.severity).toBe("critical");
    expect(decision.capped).toBe(false);
    expect(decision.exempt).toBe(true);
    // Still labelled, because where it sits is part of the fix.
    expect(decision.titlePrefix).toBe("In test code: ");
    expect(decision.rationale).toContain("(T3)");
    expect(decision.rationale).toContain("provider-specific rule");
  });

  test("a private key in a fixture directory stays critical too", () => {
    const key = secret("private-key", "src/inventory/__fixtures__/keys/id_rsa.ts");
    const decision = decideFileKind(key);
    expect(decision.kind).toBe("fixture");
    expect(decision.severity).toBe("critical");
    expect(decision.exempt).toBe(true);
  });

  test("a generic high-entropy string in a test file is capped", () => {
    // A `generic-api-key` hit is a lead, not proof of which account it opens,
    // and a high-entropy fixture token is exactly what one looks like.
    const generic = secret(
      "generic-api-key",
      "services/hold-reminder/domain/token.value-object.test.ts",
    );
    expect(generic.severity).toBe("high");
    expect(isRotationRequiredSecret(generic)).toBe(false);
    expect(decideFileKind(generic).severity).toBe("low");
  });

  test("Sentinel's own hardcoded-secret rules are not gitleaks, so they are capped", () => {
    // The same rule id, from an analyzer with no provider table behind it: the
    // exception is about what gitleaks matched, not about the words in the id.
    const own = finding({
      rule: "appsec.hardcoded-secret",
      severity: "high",
      confidence: "high",
      source: { kind: "rule", name: "opengrep" },
    });
    expect(isRotationRequiredSecret(own)).toBe(false);
    expect(decideFileKind(own).severity).toBe("low");
  });

  test("a non-secret finding is never exempt, however confident the analyzer is", () => {
    const injection = finding({
      rule: "appsec.injection.sql-built-from-variables",
      confidence: "high",
      source: { kind: "tool", name: "gitleaks" },
    });
    expect(isRotationRequiredSecret(injection)).toBe(false);
    expect(decideFileKind(injection).severity).toBe("low");
  });
});

describe("the two kinds a false-positive measurement adds", () => {
  test("documentation is capped, and says so under T4", () => {
    expect(FILE_KIND_POLICY.documentation.cap).toBe("low");
    const decision = decideFileKind(
      finding({
        location: { file: "services/hold-reminder/README-TEST.md", line: 24 },
      }),
    );
    expect(decision.kind).toBe("documentation");
    expect(decision.severity).toBe("low");
    expect(decision.capped).toBe(true);
    expect(decision.titlePrefix).toBe("In documentation: ");
    expect(decision.rationale).toContain("capped this at low (T4)");
  });

  /**
   * The caveat that outranks the instinct. A `.env.example` is committed, so a
   * value left in one is readable by everyone who can clone the repository: a cap
   * keyed on the filename would hide exactly the leak that matters most. The kind
   * therefore labels the file and changes nothing, and whether the value is real
   * is decided by `gradeSecret`, from the value.
   */
  test("an example/template file is labelled but never capped", () => {
    expect(FILE_KIND_POLICY.example.cap).toBeNull();
    const decision = decideFileKind(secret("generic-api-key", ".env.example"));
    expect(decision.kind).toBe("example");
    expect(decision.severity).toBe("high");
    expect(decision.capped).toBe(false);
    expect(decision.titlePrefix).toBe("In an example/template file: ");
  });

  test("the title prefixes still come back off, so volume grouping survives", () => {
    for (const kind of FILE_KIND_ORDER) {
      const prefix = FILE_KIND_POLICY[kind].titlePrefix;
      expect(withoutFileKindPrefix(`${prefix}Unused file candidate`)).toBe("Unused file candidate");
    }
  });
});

describe("the file-kind cap composes with the secret-strength model", () => {
  /**
   * The order in the pipeline is escalate → decideFileKind, and the two have to
   * agree. `gradeSecret` issues `high` confidence only for a provider-specific
   * match; T3 exempts exactly that; and R1's floor is gated on the same channel.
   * So these four rows are the whole composition.
   */
  const rows = [
    {
      what: "a provider credential in a test file keeps its severity (T3)",
      ruleId: "aws-access-token",
      file: "apps/lending-api/src/http/middlewares/auth.test.ts",
      value: syntheticValue("cloud-key", 32),
      context: "assignment",
      severity: "critical",
    },
    {
      what: "an entropy match in a test file is a fixture, and is capped (T1)",
      ruleId: "generic-api-key",
      file: "services/hold-reminder/domain/token.value-object.test.ts",
      value: syntheticValue("fixture-token", 44),
      context: "assignment",
      severity: "low",
    },
    {
      what: "a real credential in a template file is not capped",
      ruleId: "generic-api-key",
      file: ".env.example",
      name: "LENDING_SSO_CLIENT_SECRET",
      value: syntheticValue("client-secret", 64),
      context: "template",
      severity: "high",
    },
    {
      what: "a placeholder in documentation is already at info, so nothing moves",
      ruleId: "generic-api-key",
      file: "services/hold-reminder/README-TEST.md",
      name: "account-id",
      value: "123",
      context: "documentation",
      severity: "info",
    },
  ] as const;

  for (const row of rows) {
    test(row.what, () => {
      const grade = gradeSecret({
        ruleId: row.ruleId,
        ...("name" in row ? { name: row.name } : {}),
        value: row.value,
        context: row.context,
      });
      const graded = finding({
        rule: "appsec.hardcoded-secret",
        severity: grade.severity,
        confidence: grade.confidence,
        title: `Hardcoded credential in ${row.file} (${row.ruleId})`,
        location: { file: row.file, line: 4 },
        source: { kind: "tool", name: "gitleaks" },
      });
      const escalated = escalateFinding(graded);
      const decided = decideFileKind({ ...graded, severity: escalated.severity });
      expect(decided.severity).toBe(row.severity);
    });
  }
});
