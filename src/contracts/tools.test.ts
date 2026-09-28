import { describe, expect, test } from "bun:test";
import type { ToolsLock } from "./tools.ts";
import { parseToolsLock, serializeToolsLock } from "./tools.ts";

function minimalLock(): ToolsLock {
  return {
    schemaVersion: "1.0",
    binaries: {
      trivy: {
        version: "0.74.0",
        platforms: {
          "linux-x64": {
            url: "https://example.test/trivy-linux-x64.tar.gz",
            sha256: "b".repeat(64),
            archive: "tar.gz",
            binaryPath: "trivy",
          },
          "darwin-arm64": {
            url: "https://example.test/trivy-darwin-arm64.tar.gz",
            sha256: null,
            archive: "tar.gz",
            binaryPath: "trivy",
          },
        },
      },
      actionlint: {
        version: "1.7.12",
        description: "GitHub Actions linting.",
        platforms: {
          "linux-x64": {
            url: "https://example.test/actionlint.tar.gz",
            sha256: "c".repeat(64),
            archive: "tar.gz",
            binaryPath: "actionlint",
          },
        },
      },
    },
    node: {
      knip: { package: "knip", version: "6.37.0", binaryPath: "node_modules/.bin/knip" },
    },
  };
}

describe("parseToolsLock", () => {
  test("round-trips a serialised lockfile", () => {
    const lock = minimalLock();
    expect(parseToolsLock(serializeToolsLock(lock))).toEqual(lock);
  });

  test("names the file when the JSON itself is broken", () => {
    expect(() => parseToolsLock("{ not json")).toThrow(/tools\.lock\.json is not valid JSON/);
  });

  test("rejects a digest that is not lowercase hex SHA-256", () => {
    const raw = serializeToolsLock(minimalLock()).replace("b".repeat(64), "NOTADIGEST");
    expect(() => parseToolsLock(raw)).toThrow();
  });

  test("rejects a Node tool pinned to a range instead of an exact version", () => {
    const raw = serializeToolsLock(minimalLock()).replace('"6.37.0"', '"^6.37.0"');
    expect(() => parseToolsLock(raw)).toThrow();
  });

  test("rejects an unknown schema version", () => {
    const raw = serializeToolsLock(minimalLock()).replace(
      '"schemaVersion": "1.0"',
      '"schemaVersion": "2.0"',
    );
    expect(() => parseToolsLock(raw)).toThrow();
  });

  test("accepts a null digest so an unpinned entry can be committed and filled in later", () => {
    const lock = parseToolsLock(serializeToolsLock(minimalLock()));
    expect(lock.binaries.trivy?.platforms["darwin-arm64"]?.sha256).toBeNull();
  });
});

describe("serializeToolsLock", () => {
  test("sorts tool keys and emits platforms in canonical order", () => {
    const text = serializeToolsLock(minimalLock());

    expect(text.indexOf('"actionlint"')).toBeLessThan(text.indexOf('"trivy"'));
    // trivy is built linux-first, but serialises darwin-first.
    const trivySection = text.slice(text.indexOf('"trivy"'));
    expect(trivySection.indexOf('"darwin-arm64"')).toBeLessThan(
      trivySection.indexOf('"linux-x64"'),
    );
    expect(text.endsWith("}\n")).toBe(true);
  });

  test("is stable no matter what order the keys were built in", () => {
    const reordered: ToolsLock = {
      schemaVersion: "1.0",
      binaries: {},
      node: {},
    };
    const source = minimalLock();
    for (const name of ["actionlint", "trivy"]) {
      const tool = source.binaries[name];
      if (tool !== undefined) reordered.binaries[name] = tool;
    }
    const knip = source.node.knip;
    if (knip !== undefined) reordered.node.knip = knip;

    expect(serializeToolsLock(reordered)).toBe(serializeToolsLock(source));
  });
});
