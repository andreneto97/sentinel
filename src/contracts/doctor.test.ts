import { describe, expect, test } from "bun:test";
import {
  DOCTOR_EXIT_BLOCKED,
  DOCTOR_EXIT_OK,
  type DoctorCheck,
  DoctorCheckSchema,
  DoctorReportSchema,
  doctorExitCode,
  isReady,
  summarizeChecks,
} from "./doctor.ts";
import { SCHEMA_VERSION } from "./findings.ts";

function check(overrides: Partial<DoctorCheck> = {}): DoctorCheck {
  return {
    id: "required.bun",
    tier: "required",
    label: "Bun runtime",
    status: "ok",
    detail: "1.2.0",
    ...overrides,
  };
}

describe("DoctorCheckSchema", () => {
  test("accepts an ok check without a remediation hint", () => {
    expect(DoctorCheckSchema.parse(check()).status).toBe("ok");
  });

  test("rejects a failing check that carries no remediation hint", () => {
    const result = DoctorCheckSchema.safeParse(check({ status: "fail", detail: "missing" }));
    expect(result.success).toBe(false);
  });

  test("rejects a warning that carries no remediation hint", () => {
    const result = DoctorCheckSchema.safeParse(check({ status: "warn", detail: "drifted" }));
    expect(result.success).toBe(false);
  });

  test("accepts a failing check with a hint", () => {
    const parsed = DoctorCheckSchema.parse(
      check({ status: "fail", detail: "too old", remediation: "bun upgrade" }),
    );
    expect(parsed.remediation).toBe("bun upgrade");
  });
});

describe("summaries", () => {
  test("counts by status and reports readiness", () => {
    const checks = [
      check(),
      check({ id: "tools.gitleaks", tier: "tools", status: "warn", remediation: "setup" }),
      check({ id: "optional.disk", tier: "optional", status: "fail", remediation: "free space" }),
    ];
    expect(summarizeChecks(checks)).toEqual({ ok: 1, warn: 1, fail: 1 });
    // A failure outside the required tier must not block the run.
    expect(isReady(checks)).toBe(true);
  });

  test("a failed required check blocks the run", () => {
    expect(isReady([check({ status: "fail", remediation: "install git" })])).toBe(false);
  });
});

describe("doctorExitCode", () => {
  const base = {
    schemaVersion: SCHEMA_VERSION,
    generatedAt: "2026-01-01T00:00:00.000Z",
    target: "/repo",
    outputDir: "/repo/sentinel",
    cacheDir: "/cache",
    environment: { platform: "darwin", arch: "arm64", bunVersion: "1.2.0" },
    coverageLoss: [],
  };

  test("warnings only exit 0", () => {
    const report = DoctorReportSchema.parse({
      ...base,
      checks: [check({ id: "tools.knip", tier: "tools", status: "warn", remediation: "setup" })],
      summary: { ok: 0, warn: 1, fail: 0 },
      ready: true,
    });
    expect(doctorExitCode(report)).toBe(DOCTOR_EXIT_OK);
  });

  test("a required failure exits 2", () => {
    const report = DoctorReportSchema.parse({
      ...base,
      checks: [check({ status: "fail", remediation: "install git" })],
      summary: { ok: 0, warn: 0, fail: 1 },
      ready: false,
    });
    expect(doctorExitCode(report)).toBe(DOCTOR_EXIT_BLOCKED);
  });
});
