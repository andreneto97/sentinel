import { describe, expect, test } from "bun:test";
import { PLATFORMS, parseToolsLock, serializeToolsLock } from "../contracts/tools.ts";
import { TOOLS_LOCK_PATH } from "./installer.ts";

const raw = await Bun.file(TOOLS_LOCK_PATH).text();
const lock = parseToolsLock(raw);

describe("the shipped tools.lock.json", () => {
  test("parses against the contract", () => {
    expect(Object.keys(lock.binaries).length).toBeGreaterThan(0);
    expect(Object.keys(lock.node).length).toBeGreaterThan(0);
  });

  test("is byte-identical to what the regenerator would write", () => {
    // Guards against a hand-edit that reorders keys and makes the next
    // `update-tools-lock` run produce a noisy diff.
    expect(raw).toBe(serializeToolsLock(lock));
  });

  test("covers every supported tool on every supported platform", () => {
    for (const name of ["trivy", "gitleaks", "opengrep", "ast-grep", "hadolint", "actionlint"]) {
      const tool = lock.binaries[name];
      expect(tool, `${name} is missing from tools.lock.json`).toBeDefined();
      for (const platform of PLATFORMS) {
        expect(tool?.platforms[platform], `${name} has no ${platform} artifact`).toBeDefined();
      }
    }
  });

  test("pins every artifact to a digest and a GitHub release URL", () => {
    for (const [name, tool] of Object.entries(lock.binaries)) {
      for (const platform of PLATFORMS) {
        const artifact = tool.platforms[platform];
        if (artifact === undefined) continue;
        expect(artifact.sha256, `${name}/${platform} is unpinned`).not.toBeNull();
        expect(artifact.url).toStartWith("https://github.com/");
        expect(artifact.url).toContain("/releases/download/");
      }
    }
  });

  test("names the version in every artifact URL, so a bump cannot be half-applied", () => {
    for (const [name, tool] of Object.entries(lock.binaries)) {
      for (const platform of PLATFORMS) {
        const artifact = tool.platforms[platform];
        if (artifact === undefined) continue;
        expect(artifact.url, `${name}/${platform} url does not mention ${tool.version}`).toContain(
          tool.version,
        );
      }
    }
  });

  test("installs Node tools from a .bin path inside Sentinel's own prefix", () => {
    for (const tool of Object.values(lock.node)) {
      expect(tool.binaryPath).toStartWith("node_modules/.bin/");
    }
  });
});
