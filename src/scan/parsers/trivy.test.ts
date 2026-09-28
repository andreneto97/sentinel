import { describe, expect, test } from "bun:test";
import type { Finding } from "../../contracts/findings.ts";
import {
  MISCONFIG_RULES,
  type ManifestDependencies,
  TRIVY_RULES,
  applicableFix,
  licenseFindings,
  misconfigRule,
  misconfigurationFindings,
  packageLocations,
  parseTrivyReport,
  parseTrivySbom,
  trivySeverity,
  vulnerabilityFindings,
} from "./trivy.ts";

/** The fixtures are real trivy 0.74.0 output, trimmed; see `__fixtures__/repo`. */
const fixture = (name: string): Promise<string> =>
  Bun.file(`${import.meta.dir}/__fixtures__/${name}`).text();

const fsReportRaw = await fixture("trivy-fs.json");
const emptyReportRaw = await fixture("trivy-fs-empty.json");
const sbomRaw = await fixture("trivy-sbom.cdx.json");
const configReportRaw = await fixture("trivy-config.json");

/** What `package.json` in the fixture repo declares. */
const demoManifest: ManifestDependencies = {
  runtime: new Set(["express", "lodash", "request"]),
  dev: new Set(["minimist"]),
};

/** The parsed vulnerability report, or a test failure if the fixture rotted. */
function parsedFsReport() {
  const parsed = parseTrivyReport(fsReportRaw);
  if (!parsed.ok) throw new Error(parsed.error);
  return parsed.value;
}

function parsedConfigReport() {
  const parsed = parseTrivyReport(configReportRaw);
  if (!parsed.ok) throw new Error(parsed.error);
  return parsed.value;
}

function parsedSbom() {
  const parsed = parseTrivySbom(sbomRaw);
  if (!parsed.ok) throw new Error(parsed.error);
  return parsed.value;
}

function byTitle(findings: readonly Finding[], needle: string): Finding {
  const found = findings.find((finding) => finding.title.includes(needle));
  if (found === undefined) {
    throw new Error(
      `no finding titled like "${needle}" in ${findings.map((f) => f.title).join(", ")}`,
    );
  }
  return found;
}

describe("parsing untrusted trivy payloads", () => {
  test("accepts a real `trivy fs --format json` report", () => {
    const report = parsedFsReport();
    expect(report.Results).toHaveLength(1);
    expect(report.Results?.[0]?.Target).toBe("package-lock.json");
    expect(report.Results?.[0]?.Vulnerabilities).toHaveLength(5);
  });

  test("accepts a report with no Results at all (nothing to scan)", () => {
    const parsed = parseTrivyReport(emptyReportRaw);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.value.Results).toBeUndefined();
    expect(vulnerabilityFindings(parsed.value)).toEqual([]);
    expect(misconfigurationFindings(parsed.value)).toEqual([]);
  });

  test("degrades instead of throwing on output that is not JSON", () => {
    const parsed = parseTrivyReport("FATAL\tFatal error\trun error: init error\n");
    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.error).toContain("not valid JSON");
  });

  test("degrades instead of throwing when the shape is wrong", () => {
    const parsed = parseTrivyReport('{"Results":[{"Class":"lang-pkgs"}]}');
    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.error).toContain("Target");
  });

  test("maps trivy severities onto Sentinel's scale", () => {
    expect(trivySeverity("CRITICAL")).toBe("critical");
    expect(trivySeverity("HIGH")).toBe("high");
    expect(trivySeverity("MEDIUM")).toBe("medium");
    expect(trivySeverity("LOW")).toBe("low");
    expect(trivySeverity("UNKNOWN")).toBe("info");
    expect(trivySeverity(undefined)).toBe("info");
    expect(trivySeverity("something-new")).toBe("info");
  });
});

describe("dependency vulnerabilities", () => {
  test("emits one finding per (package, vulnerability), located in the real manifest", () => {
    const findings = vulnerabilityFindings(parsedFsReport());
    expect(findings).toHaveLength(5);
    for (const finding of findings) {
      expect(finding.domain).toBe("dependencies");
      expect(finding.rule).toBe(TRIVY_RULES.vulnerablePackage);
      // The path trivy reported, never a hardcoded lockfile name.
      expect(finding.location.file).toBe("package-lock.json");
      expect(finding.source).toEqual({ kind: "tool", name: "trivy" });
      expect(finding.location.snippet).toBeUndefined();
    }
    const bodyParser = byTitle(findings, "CVE-2024-45590");
    expect(bodyParser.severity).toBe("high");
    expect(bodyParser.cwe).toEqual(["CWE-405"]);
    // body-parser@1.19.0 starts on line 28 of the fixture lockfile.
    expect(bodyParser.location.line).toBe(28);
    expect(bodyParser.location.endLine).toBe(34);
  });

  test("reads directness from the project's own manifest and names the path", () => {
    const findings = vulnerabilityFindings(parsedFsReport(), {
      manifests: new Map([["package-lock.json", demoManifest]]),
    });
    const lodash = byTitle(findings, "CVE-2021-23337");
    expect(lodash.description).toContain("Direct dependency");
    expect(lodash.location.note).toBe("direct dependency");

    const qs = byTitle(findings, "CVE-2022-24999");
    expect(qs.description).toContain("Transitive dependency");
    expect(qs.description).toContain("Pulled in by express@4.17.1 → qs@6.7.0");
    // The package that introduces it is cited as evidence, on its own lines.
    expect(qs.evidence[0]?.file).toBe("package-lock.json");
    expect(qs.evidence[0]?.line).toBe(19);
  });

  test("falls back to trivy's own relationship when no manifest was read", () => {
    const findings = vulnerabilityFindings(parsedFsReport());
    expect(byTitle(findings, "CVE-2024-45590").description).toContain("Transitive dependency");
    expect(byTitle(findings, "CVE-2021-23337").description).toContain("Direct dependency");
  });

  test("carries what trivy knows about exploitability: fix and CVSS", () => {
    const findings = vulnerabilityFindings(parsedFsReport());
    const fixed = byTitle(findings, "CVE-2024-45590");
    expect(fixed.exploitability).toContain("A fixed version exists: 1.20.3");
    expect(fixed.exploitability).toContain("CVSS 7.5");
    expect(fixed.exploitability).toContain("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
    expect(fixed.recommendation).toContain("1.20.3");

    const unfixed = byTitle(findings, "CVE-2023-28155");
    expect(unfixed.exploitability).toContain("No fixed version is published");
    expect(unfixed.exploitability).toContain("affected");
    expect(unfixed.recommendation).toContain("No fix is published");
    expect(unfixed.acceptanceCriteria[0]).toContain("decision");
  });

  test("never invents a CWE", () => {
    const findings = vulnerabilityFindings(parsedFsReport());
    // NSWG-ECO-516 is a real advisory with no CweIDs in trivy's payload.
    expect(byTitle(findings, "NSWG-ECO-516").cwe).toEqual([]);
    expect(byTitle(findings, "NSWG-ECO-516").owasp).toEqual([]);
  });

  test("ids are stable across runs and unique per (package, vulnerability)", () => {
    const first = vulnerabilityFindings(parsedFsReport()).map((finding) => finding.id);
    const second = vulnerabilityFindings(parsedFsReport()).map((finding) => finding.id);
    expect(second).toEqual(first);
    expect(new Set(first).size).toBe(first.length);
  });
});

describe("the fixed version a reader can act on", () => {
  test("picks the lowest fix above the installed version when the advisory lists several", () => {
    // CVE-2022-24999, as trivy 0.74.0 reports it: nine release lines patched.
    const fixes = "6.10.3, 6.9.7, 6.8.3, 6.7.3, 6.6.1, 6.5.3, 6.4.1, 6.3.3, 6.2.4";
    expect(applicableFix(fixes, "6.7.0")).toBe("6.7.3");
    expect(applicableFix(fixes, "6.2.0")).toBe("6.2.4");
    // Already past every listed fix: the newest is the only honest answer.
    expect(applicableFix(fixes, "6.11.0")).toBe("6.10.3");
  });

  test("a single fix, an unparseable one and an unknown install all survive", () => {
    expect(applicableFix("1.20.3", "1.19.0")).toBe("1.20.3");
    expect(applicableFix("6.10.3, 6.7.3")).toBe("6.10.3");
    expect(applicableFix("not-a-version", "1.0.0")).toBe("not-a-version");
  });

  test("the recommendation names one version, not the whole list", () => {
    const findings = vulnerabilityFindings(parsedFsReport(), {
      manifests: new Map([["package-lock.json", demoManifest]]),
    });
    const qs = findings.find((finding) => finding.title.includes("qs@"));
    expect(qs?.recommendation ?? "").not.toContain(", 6.");
  });

  test("the advisory's own headline does not run into the next sentence", () => {
    const findings = vulnerabilityFindings(parsedFsReport(), {
      manifests: new Map([["package-lock.json", demoManifest]]),
    });
    for (const finding of findings) {
      expect(finding.description).not.toMatch(/[a-z] (Direct|Transitive|Trivy did not) /);
    }
  });
});

describe("licence inventory from the SBOM", () => {
  test("flags copyleft licences and places them on the package's own line", () => {
    const findings = licenseFindings(parsedSbom(), packageLocations(parsedFsReport()));
    const copyleft = findings.filter((finding) => finding.rule === TRIVY_RULES.copyleftLicense);
    expect(copyleft.map((finding) => finding.title).sort()).toEqual([
      "lodash@4.17.15 is licensed GPL-3.0-only",
      "qs@6.7.0 is licensed MIT OR LGPL-2.1-or-later",
    ]);
    const gpl = byTitle(copyleft, "lodash");
    expect(gpl.severity).toBe("low");
    expect(gpl.domain).toBe("dependencies");
    expect(gpl.location.file).toBe("package-lock.json");
    expect(gpl.location.line).toBe(43);

    // A dual licence with a permissive arm is a decision to record, not a risk.
    const dual = byTitle(copyleft, "qs@6.7.0");
    expect(dual.severity).toBe("info");
    expect(dual.description).toContain("permissive alternative");
  });

  test("aggregates unknown licences into one info finding", () => {
    const findings = licenseFindings(parsedSbom(), packageLocations(parsedFsReport()));
    const unknown = findings.filter((finding) => finding.rule === TRIVY_RULES.unknownLicense);
    expect(unknown).toHaveLength(1);
    const aggregate = byTitle(unknown, "no licence in the SBOM");
    expect(aggregate.severity).toBe("info");
    expect(aggregate.title).toBe("1 of 7 dependencies have no licence in the SBOM");
    expect(aggregate.description).toContain("cookie@0.4.0");
  });

  test("still places findings when the vulnerability pass gave no lines", () => {
    const findings = licenseFindings(parsedSbom());
    expect(findings.length).toBeGreaterThan(0);
    for (const finding of findings) {
      expect(finding.location.file).toBe("package-lock.json");
      expect(finding.location.line).toBe(1);
    }
  });

  test("a scoped package keeps its scope, and matches the report's own line", () => {
    // Real trivy 0.74.0 output: the CycloneDX SBOM splits the npm scope into
    // `group`, while the vulnerability report keeps the qualified name.
    const sbom = parseTrivySbom(
      JSON.stringify({
        bomFormat: "CycloneDX",
        components: [
          {
            "bom-ref": "pkg:npm/%40img/sharp-libvips-darwin-arm64@1.3.3",
            type: "library",
            group: "@img",
            name: "sharp-libvips-darwin-arm64",
            version: "1.3.3",
            purl: "pkg:npm/%40img/sharp-libvips-darwin-arm64@1.3.3",
            licenses: [{ license: { id: "LGPL-3.0-or-later" } }],
          },
        ],
      }),
    );
    expect(sbom.ok).toBe(true);
    if (!sbom.ok) return;

    const locations = new Map([
      ["@img/sharp-libvips-darwin-arm64@1.3.3", { file: "pnpm-lock.yaml", line: 713 }],
    ]);
    const findings = licenseFindings(sbom.value, locations);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.title).toBe(
      "@img/sharp-libvips-darwin-arm64@1.3.3 is licensed LGPL-3.0-or-later",
    );
    expect(findings[0]?.recommendation).toContain("@img/sharp-libvips-darwin-arm64");
    // The qualified name is also what places the citation on a real line.
    expect(findings[0]?.location).toEqual({ file: "pnpm-lock.yaml", line: 713 });
  });

  test("a permissive-only SBOM produces nothing to report", () => {
    const parsed = parseTrivySbom(
      JSON.stringify({
        bomFormat: "CycloneDX",
        components: [
          {
            "bom-ref": "pkg:npm/express@4.17.1",
            type: "library",
            name: "express",
            version: "4.17.1",
            licenses: [{ license: { id: "MIT" } }],
          },
        ],
      }),
    );
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(licenseFindings(parsed.value)).toEqual([]);
  });
});

describe("misconfiguration (a first-class delivery pass, not a footnote)", () => {
  test("maps each config type onto its own delivery rule", () => {
    expect(misconfigRule("dockerfile")).toBe("delivery.dockerfile-misconfig");
    expect(MISCONFIG_RULES.dockerfile).toBe("delivery.dockerfile-misconfig");
    expect(misconfigRule("kubernetes")).toBe("delivery.kubernetes-misconfig");
    expect(misconfigRule("terraform")).toBe("delivery.terraform-misconfig");
    expect(misconfigRule("helm")).toBe("delivery.helm-misconfig");
    expect(misconfigRule("something-trivy-added-later")).toBe("delivery.config-misconfig");
    expect(misconfigRule(undefined)).toBe("delivery.config-misconfig");
  });

  test("turns every failing check into a delivery finding on a real line", () => {
    const findings = misconfigurationFindings(parsedConfigReport());
    // 3 Dockerfile + 2 Kubernetes + 2 Terraform; the empty `terraform` directory
    // result contributes nothing.
    expect(findings).toHaveLength(7);
    for (const finding of findings) {
      expect(finding.domain).toBe("delivery");
      expect(finding.location.line).toBeGreaterThanOrEqual(1);
      expect(finding.source.name).toBe("trivy");
    }
    expect(new Set(findings.map((finding) => finding.rule))).toEqual(
      new Set([
        "delivery.dockerfile-misconfig",
        "delivery.kubernetes-misconfig",
        "delivery.terraform-misconfig",
      ]),
    );
  });

  test("keeps trivy's line, and falls back to line 1 for a file-level check", () => {
    const findings = misconfigurationFindings(parsedConfigReport());
    const latestTag = byTitle(findings, "DS-0001");
    expect(latestTag.location.file).toBe("Dockerfile");
    expect(latestTag.location.line).toBe(1);

    const secret = byTitle(findings, "DS-0031");
    expect(secret.severity).toBe("critical");
    expect(secret.location.line).toBe(2);

    // DS-0002 ("image user should not be root") has no CauseMetadata lines.
    const rootUser = byTitle(findings, "DS-0002");
    expect(rootUser.location.line).toBe(1);
    expect(rootUser.severity).toBe("high");
    expect(rootUser.recommendation).toContain("USER");
  });

  test("carries the resource and the other places the same check fired", () => {
    const findings = misconfigurationFindings(parsedConfigReport());
    const securityGroup = byTitle(findings, "AWS-0107");
    expect(securityGroup.location.file).toBe("terraform/main.tf");
    expect(securityGroup.location.note).toBe("aws_security_group.open");
    expect(securityGroup.evidence.map((ref) => ref.line)).toContain(7);
    expect(securityGroup.evidence.every((ref) => ref.file === "terraform/main.tf")).toBe(true);
  });

  test("never invents a CWE for a check that carries none", () => {
    const findings = misconfigurationFindings(parsedConfigReport());
    expect(findings.every((finding) => finding.cwe.length === 0)).toBe(true);
  });

  test("ignores non-failing checks", () => {
    const parsed = parseTrivyReport(
      JSON.stringify({
        Results: [
          {
            Target: "Dockerfile",
            Class: "config",
            Type: "dockerfile",
            Misconfigurations: [
              { ID: "DS-0001", Title: "latest tag", Severity: "MEDIUM", Status: "PASS" },
              { ID: "DS-0002", Title: "root user", Severity: "HIGH", Status: "FAIL" },
            ],
          },
        ],
      }),
    );
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const findings = misconfigurationFindings(parsed.value);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.title).toContain("DS-0002");
  });
});
