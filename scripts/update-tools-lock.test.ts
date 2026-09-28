import { describe, expect, test } from "bun:test";
import type { ToolsLock } from "../src/contracts/tools.ts";
import { parseUpdateArgs, selectTargets } from "./update-tools-lock.ts";

function lockFixture(): ToolsLock {
  return {
    schemaVersion: "1.0",
    binaries: {
      trivy: {
        version: "0.74.0",
        platforms: {
          "darwin-arm64": {
            url: "https://example.test/trivy-darwin-arm64.tar.gz",
            sha256: "a".repeat(64),
            archive: "tar.gz",
            binaryPath: "trivy",
          },
          "linux-x64": {
            url: "https://example.test/trivy-linux-x64.tar.gz",
            sha256: null,
            archive: "tar.gz",
            binaryPath: "trivy",
          },
        },
      },
      hadolint: {
        version: "2.15.1",
        platforms: {
          "linux-x64": {
            url: "https://example.test/hadolint-linux-x64",
            sha256: null,
            archive: "raw",
            binaryPath: "hadolint",
          },
        },
      },
    },
    node: {},
  };
}

const defaults = { only: new Set<string>(), force: false, check: false, help: false };

describe("parseUpdateArgs", () => {
  test("defaults to pinning only what is unpinned", () => {
    expect(parseUpdateArgs([])).toEqual(defaults);
  });

  test("reads --force, --check and a comma-separated --only", () => {
    const options = parseUpdateArgs(["--only", "trivy, gitleaks", "--force", "--check"]);

    expect(options.force).toBe(true);
    expect(options.check).toBe(true);
    expect([...options.only]).toEqual(["trivy", "gitleaks"]);
  });

  test("rejects --only without a value instead of silently widening the run", () => {
    expect(() => parseUpdateArgs(["--only"])).toThrow(/--only needs/);
    expect(() => parseUpdateArgs(["--only", "--force"])).toThrow(/--only needs/);
  });

  test("recognises --help without treating it as an unknown flag", () => {
    expect(parseUpdateArgs(["--help"]).help).toBe(true);
    expect(parseUpdateArgs(["-h"]).help).toBe(true);
  });

  test("rejects an unknown flag", () => {
    expect(() => parseUpdateArgs(["--all"])).toThrow(/unknown argument: --all/);
  });
});

describe("selectTargets", () => {
  test("picks up every unpinned artifact and leaves pinned ones alone", () => {
    const targets = selectTargets(lockFixture(), defaults);

    expect(targets.map((target) => `${target.tool}/${target.platform}`)).toEqual([
      "hadolint/linux-x64",
      "trivy/linux-x64",
    ]);
  });

  test("--force re-hashes artifacts that are already pinned", () => {
    const targets = selectTargets(lockFixture(), { ...defaults, force: true });

    expect(targets.map((target) => `${target.tool}/${target.platform}`)).toEqual([
      "hadolint/linux-x64",
      "trivy/darwin-arm64",
      "trivy/linux-x64",
    ]);
  });

  test("--check visits pinned artifacts so drift is detectable", () => {
    const targets = selectTargets(lockFixture(), { ...defaults, check: true });

    expect(targets.map((target) => target.platform)).toContain("darwin-arm64");
  });

  test("--only narrows the run to the named tools", () => {
    const targets = selectTargets(lockFixture(), { ...defaults, only: new Set(["trivy"]) });

    expect(targets.every((target) => target.tool === "trivy")).toBe(true);
    expect(targets).toHaveLength(1);
  });

  test("hands back live references, so writing a digest updates the lockfile", () => {
    const lock = lockFixture();
    const target = selectTargets(lock, defaults)[0];

    expect(target).toBeDefined();
    if (target === undefined) return;
    target.artifact.sha256 = "f".repeat(64);

    expect(lock.binaries.hadolint?.platforms["linux-x64"]?.sha256).toBe("f".repeat(64));
  });
});
