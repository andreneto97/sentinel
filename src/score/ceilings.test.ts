import { describe, expect, test } from "bun:test";
import { DomainSchema } from "../contracts/findings.ts";
import { evidenceInput, finding } from "./__fixtures__/factories.ts";
import {
  SCORE_CEILINGS,
  UNEXAMINED_EVIDENCE_CAP,
  applyCeilings,
  canFireCeiling,
  capsScore,
  evidenceCeiling,
} from "./ceilings.ts";
import { domainEvidence } from "./evidence.ts";

/** The gitleaks finding that proves a credential reached the commit graph. */
const committedSecret = finding({
  id: "secret-1",
  domain: "appsec",
  rule: "appsec.hardcoded-secret",
  severity: "critical",
  title: "Hardcoded cloud provider credential in src/lib/aws.ts",
  location: { file: "src/lib/aws.ts", line: 12 },
  source: { kind: "tool", name: "gitleaks" },
});

/** The trivy finding for a critical advisory against the installed version. */
const criticalCve = finding({
  id: "cve-1",
  domain: "dependencies",
  rule: "dependencies.vulnerable-package",
  severity: "critical",
  title: "CVE-2024-0001 in left-pad@1.0.0",
  location: { file: "package-lock.json", line: 40 },
  source: { kind: "tool", name: "trivy" },
});

/** The migration audit's verdict that a statement drops or rewrites data. */
const destructiveMigration = finding({
  id: "migration-1",
  domain: "data",
  rule: "data.destructive-migration",
  severity: "medium",
  title: "0007_drop_legacy_email.sql drops a populated column",
  location: { file: "migrations/0007_drop_legacy_email.sql", line: 3 },
});

describe("the ceiling table", () => {
  test("holds the three caps the plan states, on the domains it names", () => {
    expect(SCORE_CEILINGS.map((ceiling) => [ceiling.domain, ceiling.cap])).toEqual([
      ["appsec", 50],
      ["dependencies", 60],
      ["data", 70],
    ]);
  });

  test("gives every ceiling a unique id, a real domain and a reason to exist", () => {
    const ids = SCORE_CEILINGS.map((ceiling) => ceiling.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const ceiling of SCORE_CEILINGS) {
      expect(DomainSchema.options).toContain(ceiling.domain);
      expect(ceiling.cap).toBeGreaterThanOrEqual(0);
      expect(ceiling.cap).toBeLessThanOrEqual(100);
      expect(ceiling.rationale.length).toBeGreaterThan(40);
      expect(ceiling.title.length).toBeGreaterThan(10);
    }
  });
});

describe("applyCeilings", () => {
  test("caps a healthy appsec domain at 50 for a committed credential", () => {
    const result = applyCeilings("appsec", 92, [committedSecret]);
    expect(result.score).toBe(50);
    expect(result.ceilings).toHaveLength(1);
    expect(result.ceilings[0]?.binding).toBe(true);
    expect(result.ceilings[0]?.triggeredBy).toEqual(["secret-1"]);
  });

  test("records why it applied, in the words the report renders", () => {
    const reason = applyCeilings("appsec", 92, [committedSecret]).ceilings[0]?.reason ?? "";
    expect(reason).toStartWith("Capped at 50:");
    expect(reason).toContain("src/lib/aws.ts:12");
    // The assumption Sentinel cannot verify is stated in the same breath.
    expect(reason).toContain("rotated");
    // The domain travels as data, not as a raw id spliced into the prose: the
    // renderers each have their own reader-facing label for it.
    expect(reason).not.toContain("appsec");
  });

  test("caps dependencies at 60 for a critical CVE and data at 70 for a destructive migration", () => {
    expect(applyCeilings("dependencies", 88, [criticalCve]).score).toBe(60);
    expect(applyCeilings("data", 76, [destructiveMigration]).score).toBe(70);
  });

  test("leaves a domain alone when nothing fires", () => {
    const result = applyCeilings("appsec", 92, [finding({ severity: "low" })]);
    expect(result.score).toBe(92);
    expect(result.ceilings).toEqual([]);
  });

  test("ignores a finding that belongs to another domain's ceiling", () => {
    expect(applyCeilings("appsec", 92, [criticalCve, destructiveMigration]).score).toBe(92);
  });

  test("never fires on a low-confidence lead", () => {
    const lead = finding({ ...committedSecret, id: "secret-2", confidence: "low" });
    expect(canFireCeiling(lead)).toBe(false);
    expect(applyCeilings("appsec", 92, [lead]).score).toBe(92);
  });

  test("does not cap on a hardcoded credential nobody proved was committed", () => {
    const inSource = finding({
      id: "cred-1",
      domain: "appsec",
      rule: "appsec.hardcoded-credential",
      severity: "high",
    });
    expect(applyCeilings("appsec", 92, [inSource]).score).toBe(92);
  });

  test("records a ceiling that fired without biting, and says it did not bite", () => {
    const result = applyCeilings("appsec", 31, [committedSecret]);
    expect(result.score).toBe(31);
    expect(result.ceilings[0]?.binding).toBe(false);
  });

  test("keeps a not-assessed domain unscored, and still names what fired", () => {
    const result = applyCeilings("appsec", null, [committedSecret]);
    expect(result.score).toBeNull();
    expect(result.ceilings).toHaveLength(1);
    expect(result.ceilings[0]?.binding).toBe(false);
  });

  test("names every finding that fired it, in a stable order", () => {
    const second = finding({
      ...committedSecret,
      id: "secret-0",
      location: { file: "a.ts", line: 1 },
    });
    const result = applyCeilings("appsec", 92, [committedSecret, second]);
    expect(result.ceilings[0]?.triggeredBy).toEqual(["secret-0", "secret-1"]);
    expect(result.ceilings[0]?.reason).toContain("2 committed credentials");
  });
});

describe("the unexamined-evidence ceiling", () => {
  /** A data layer of thousands of units, not one of them audited. */
  const unexamined = domainEvidence("data", evidenceInput({ "data-access": 4000, migration: 500 }));
  /** The same units, all audited. */
  const examined = domainEvidence(
    "data",
    evidenceInput(
      { "data-access": 4000, migration: 500 },
      {
        kinds: [
          { kind: "data-access", unitsTotal: 4000, unitsAudited: 4000, skipped: [] },
          { kind: "migration", unitsTotal: 500, unitsAudited: 500, skipped: [] },
        ],
      },
    ),
  );

  test("caps at the top of band C, because A and B are claims of health", () => {
    expect(UNEXAMINED_EVIDENCE_CAP).toBe(74);
    const result = applyCeilings("data", 100, [], unexamined);
    expect(result.score).toBe(74);
    expect(result.ceilings[0]?.id).toBe("evidence.unexamined-units");
    expect(result.ceilings[0]?.binding).toBe(true);
  });

  test("names the units it caps for, and how to lift it", () => {
    const reason = applyCeilings("data", 100, [], unexamined).ceilings[0]?.reason ?? "";
    expect(reason).toContain("only 0 of its 4,500 units were examined");
    expect(reason).toContain("4,000 data-access call sites and 500 migrations");
    expect(reason).toContain("it cannot certify one");
    expect(reason).toContain("Run the audit phase");
  });

  test("blames no finding, because no finding fired it", () => {
    expect(applyCeilings("data", 100, [], unexamined).ceilings[0]?.triggeredBy).toEqual([]);
  });

  test("does not fire once the units were examined", () => {
    expect(capsScore(examined)).toBe(false);
    expect(applyCeilings("data", 100, [], examined).ceilings).toEqual([]);
  });

  test("does not fire for a domain with no audit units", () => {
    const none = domainEvidence("dependencies", evidenceInput({ migration: 500 }));
    expect(evidenceCeiling("dependencies", none)).toBeNull();
    expect(applyCeilings("dependencies", 100, [], none).ceilings).toEqual([]);
  });

  test("is recorded but not binding when the findings had already gone lower", () => {
    const result = applyCeilings("data", 20, [], unexamined);
    expect(result.score).toBe(20);
    expect(result.ceilings[0]?.binding).toBe(false);
  });

  test("leaves a not-assessed domain unscored while still naming the units", () => {
    const result = applyCeilings("data", null, [], unexamined);
    expect(result.score).toBeNull();
    expect(result.ceilings[0]?.binding).toBe(false);
  });

  test("yields to a finding-driven cap, which is the more specific explanation", () => {
    const destructive = finding({
      id: "drop-1",
      domain: "data",
      rule: "data.destructive-migration",
      severity: "high",
    });
    const result = applyCeilings("data", 100, [destructive], unexamined);
    expect(result.score).toBe(70);
    expect(result.ceilings.map((ceiling) => ceiling.id)).toEqual([
      "data.destructive-migration",
      "evidence.unexamined-units",
    ]);
    expect(result.ceilings[0]?.binding).toBe(true);
    expect(result.ceilings[1]?.binding).toBe(false);
  });

  test("does not fire at all when no evidence is supplied, so old callers are unchanged", () => {
    expect(applyCeilings("data", 100, []).ceilings).toEqual([]);
  });
});
