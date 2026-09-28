import { describe, expect, test } from "bun:test";
import { createFileSystem } from "../../ports/file-system.ts";
import { levelToSeverity, parseSarif, tagValue } from "./sarif.ts";

const fs = createFileSystem();

/** Real captured output, trimmed: see `__fixtures__/README.md` for provenance. */
function fixture(name: string): Promise<string> {
  return fs.readFile(`${import.meta.dir}/__fixtures__/${name}`);
}

describe("parseSarif on real gitleaks output", () => {
  test("reads both hits with their rule descriptions", async () => {
    const parsed = parseSarif(await fixture("gitleaks-report.sarif"));
    if (!parsed.ok) throw new Error(parsed.error);

    expect(parsed.runs).toHaveLength(1);
    expect(parsed.runs[0]?.toolName).toBe("gitleaks");
    expect(parsed.findings.map((finding) => finding.ruleId)).toEqual(["private-key", "github-pat"]);
    expect(parsed.findings[0]?.rule?.shortDescription).toContain("Identified a Private Key");
  });

  test("keeps the commit metadata gitleaks hides in partialFingerprints", async () => {
    const parsed = parseSarif(await fixture("gitleaks-report.sarif"));
    if (!parsed.ok) throw new Error(parsed.error);

    const first = parsed.findings[0];
    expect(first?.fingerprints.commitSha).toBe("aaaa1111bbbb2222cccc3333dddd4444eeee5555");
    expect(first?.fingerprints.author).toBe("Dev Example");
    expect(first?.fingerprints.email).toBe("dev@example.com");
  });

  test("carries the multi-line region and the redacted snippet", async () => {
    const parsed = parseSarif(await fixture("gitleaks-report.sarif"));
    if (!parsed.ok) throw new Error(parsed.error);

    const location = parsed.findings[0]?.primary;
    expect(location?.file).toBe("src/key.pem");
    expect(location?.startLine).toBe(1);
    expect(location?.startColumn).toBe(1);
    expect(location?.endLine).toBe(4);
    expect(location?.endColumn).toBe(30);
    // gitleaks ran with --redact, so its own snippet holds no secret.
    expect(location?.snippet).toBe("REDACTED");
  });

  test("falls back to SARIF's default level when no one states one", async () => {
    const parsed = parseSarif(await fixture("gitleaks-report.sarif"));
    if (!parsed.ok) throw new Error(parsed.error);
    // gitleaks emits neither `result.level` nor `defaultConfiguration`.
    expect(parsed.findings.map((finding) => finding.level)).toEqual(["warning", "warning"]);
  });
});

describe("parseSarif on real opengrep output", () => {
  test("joins every result to its rule and its tags", async () => {
    const parsed = parseSarif(await fixture("opengrep-report.sarif"));
    if (!parsed.ok) throw new Error(parsed.error);

    expect(parsed.runs[0]?.toolName).toBe("Opengrep OSS");
    expect(parsed.runs[0]?.toolVersion).toBe("1.30.0");
    const hit = parsed.findings.find(
      (finding) => finding.ruleId === "appsec.xss.inner-html-assignment",
    );
    expect(hit?.level).toBe("error");
    expect(hit?.primary?.file).toBe("xss.js");
    expect(hit?.tags).toContain("sentinel-domain:appsec");
    expect(hit?.tags).toContain("sentinel-severity:high");
  });

  test("takes the level from the rule's defaultConfiguration", async () => {
    const parsed = parseSarif(await fixture("opengrep-report.sarif"));
    if (!parsed.ok) throw new Error(parsed.error);
    // The results carry no `level`; every level below comes from the rule.
    const cookies = parsed.findings.find(
      (finding) => finding.ruleId === "appsec.auth.insecure-cookie-flags",
    );
    expect(cookies?.level).toBe("warning");
    expect(cookies?.rule?.defaultLevel).toBe("warning");
  });

  test("exposes the match fingerprint the finding id is built from", async () => {
    const parsed = parseSarif(await fixture("opengrep-report.sarif"));
    if (!parsed.ok) throw new Error(parsed.error);
    for (const finding of parsed.findings) {
      expect(finding.fingerprints["matchBasedId/v1"]).toBeString();
    }
  });

  test("reports no errors for a healthy run", async () => {
    const parsed = parseSarif(await fixture("opengrep-report.sarif"));
    if (!parsed.ok) throw new Error(parsed.error);
    expect(parsed.errors).toEqual([]);
  });
});

describe("parseSarif surfaces what a tool says about itself", () => {
  test("collects the error notifications of a run that loaded no rules", async () => {
    const parsed = parseSarif(await fixture("opengrep-config-error.sarif"));
    if (!parsed.ok) throw new Error(parsed.error);

    // The invocation claims success and the results array is empty: without the
    // notifications, a broken scan reads exactly like a clean one.
    expect(parsed.findings).toEqual([]);
    expect(parsed.errors).toHaveLength(2);
    expect(parsed.errors[0]).toContain("Invalid YAML file");
    expect(parsed.errors[1]).toContain("invalid configuration file found");
  });
});

describe("parseSarif degrades instead of throwing", () => {
  test("an empty file", () => {
    const parsed = parseSarif("   \n");
    expect(parsed).toEqual({ ok: false, error: "the report file is empty" });
  });

  test("a truncated report", () => {
    const parsed = parseSarif('{"version":"2.1.0","runs":[{"resu');
    expect(parsed.ok).toBe(false);
    if (parsed.ok) throw new Error("expected a failure");
    expect(parsed.error).toStartWith("the report is not valid JSON:");
  });

  test("JSON that is not a SARIF log", () => {
    const parsed = parseSarif('{"results":[]}');
    expect(parsed.ok).toBe(false);
    if (parsed.ok) throw new Error("expected a failure");
    expect(parsed.error).toContain("no `runs` array");
  });

  test("a runs entry of the wrong shape", () => {
    const parsed = parseSarif('{"runs":"nope"}');
    expect(parsed.ok).toBe(false);
    if (parsed.ok) throw new Error("expected a failure");
    expect(parsed.error).toStartWith("the report is not valid SARIF:");
  });

  test("a result with no location at all", () => {
    const parsed = parseSarif(
      JSON.stringify({ runs: [{ results: [{ ruleId: "x", message: { text: "hi" } }] }] }),
    );
    if (!parsed.ok) throw new Error(parsed.error);
    expect(parsed.findings[0]?.primary).toBeNull();
    expect(parsed.findings[0]?.locations).toEqual([]);
  });

  test("an unknown level falls back rather than being trusted", () => {
    const parsed = parseSarif(
      JSON.stringify({ runs: [{ results: [{ ruleId: "x", level: "catastrophic" }] }] }),
    );
    if (!parsed.ok) throw new Error(parsed.error);
    expect(parsed.findings[0]?.level).toBe("warning");
  });

  test("a rule referenced only by index still resolves", () => {
    const parsed = parseSarif(
      JSON.stringify({
        runs: [
          {
            tool: { driver: { rules: [{ id: "first" }, { id: "second" }] } },
            results: [{ ruleIndex: 1, message: { text: "hi" } }],
          },
        ],
      }),
    );
    if (!parsed.ok) throw new Error(parsed.error);
    expect(parsed.findings[0]?.ruleId).toBe("second");
  });

  test("a file:// uri is reduced to a path", () => {
    const parsed = parseSarif(
      JSON.stringify({
        runs: [
          {
            results: [
              {
                ruleId: "x",
                locations: [
                  { physicalLocation: { artifactLocation: { uri: "file:///repo/src/a.ts" } } },
                ],
              },
            ],
          },
        ],
      }),
    );
    if (!parsed.ok) throw new Error(parsed.error);
    expect(parsed.findings[0]?.primary?.file).toBe("/repo/src/a.ts");
    // SARIF defaults an absent startLine to 1.
    expect(parsed.findings[0]?.primary?.startLine).toBe(1);
  });
});

describe("tagValue", () => {
  test("reads the value after the prefix", () => {
    expect(tagValue(["sentinel-domain:appsec", "security"], "sentinel-domain")).toBe("appsec");
  });

  test("keeps colons inside the value", () => {
    expect(tagValue(["sentinel-fix:Use A, not B: ever"], "sentinel-fix")).toBe(
      "Use A, not B: ever",
    );
  });

  test("is null when absent or empty", () => {
    expect(tagValue(["security"], "sentinel-domain")).toBeNull();
    expect(tagValue(["sentinel-domain:"], "sentinel-domain")).toBeNull();
  });

  test("does not match a prefix that is only a substring", () => {
    expect(tagValue(["not-sentinel-domain:appsec"], "sentinel-domain")).toBeNull();
  });
});

describe("levelToSeverity", () => {
  test("maps each SARIF level", () => {
    expect(levelToSeverity("error")).toBe("high");
    expect(levelToSeverity("warning")).toBe("medium");
    expect(levelToSeverity("note")).toBe("low");
    expect(levelToSeverity("none")).toBe("info");
  });
});
