import { describe, expect, test } from "bun:test";
import type { ProposalSet } from "../contracts/proposal.ts";
import {
  emptySentinelConfig,
  mergeDecisionIntoConfig,
  parseSentinelConfig,
  serializeSentinelConfig,
} from "./config.ts";
import { decideScope } from "./decide.ts";

const set: ProposalSet = {
  proposals: [
    {
      id: "delivery.iac.terraform",
      title: "Terraform",
      domain: "delivery",
      detected: { summary: "terraform/", evidence: [] },
      wouldCheck: "trivy config",
      cost: { estimatedSeconds: 40, usesAi: false },
      defaultAnswer: "on",
      aliases: ["terraform"],
      attributes: {},
    },
    {
      id: "serverless.iam-audit",
      title: "IAM",
      domain: "serverless",
      detected: { summary: "12 functions", evidence: [] },
      wouldCheck: "iam audit",
      cost: { estimatedSeconds: 120, usesAi: true },
      defaultAnswer: "on",
      aliases: ["iam"],
      attributes: {},
    },
  ],
  notApplicable: [],
};

describe("parseSentinelConfig", () => {
  test("reads the answers a previous run wrote", () => {
    const { config, warnings } = parseSentinelConfig(
      JSON.stringify({
        schemaVersion: "1.0",
        answers: { "delivery.iac.terraform": "on", "serverless.iam-audit": "off" },
      }),
    );
    expect(warnings).toEqual([]);
    expect(config.answers["delivery.iac.terraform"]).toBe("on");
    expect(config.answers["serverless.iam-audit"]).toBe("off");
  });

  test("broken JSON degrades to no memory, with a warning rather than a crash", () => {
    const { config, warnings } = parseSentinelConfig("{ not json");
    expect(config.answers).toEqual({});
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain("not valid JSON");
  });

  test("a config from another schema version is ignored, loudly", () => {
    const { config, warnings } = parseSentinelConfig(
      JSON.stringify({ schemaVersion: "0.4", answers: { a: "on" } }),
    );
    expect(config.answers).toEqual({});
    expect(warnings[0]).toContain("0.4");
  });

  test("an answer value Sentinel cannot act on invalidates the file", () => {
    const { config, warnings } = parseSentinelConfig(
      JSON.stringify({ schemaVersion: "1.0", answers: { "x.y": "sometimes" } }),
    );
    expect(config.answers).toEqual({});
    expect(warnings[0]).toContain("does not match the expected shape");
  });
});

describe("mergeDecisionIntoConfig", () => {
  test("records accepted and declined answers, so the next run does not ask again", () => {
    const decision = decideScope(set, { include: ["terraform"], exclude: ["iam"] });
    const merged = mergeDecisionIntoConfig(emptySentinelConfig(), decision);
    expect(merged.answers).toEqual({
      "delivery.iac.terraform": "on",
      "serverless.iam-audit": "off",
    });
  });

  test("an untouched proposal is not recorded, so it is asked again next time", () => {
    const decision = decideScope(set, { include: ["terraform"] });
    const merged = mergeDecisionIntoConfig(emptySentinelConfig(), decision);
    expect(Object.keys(merged.answers)).toEqual(["delivery.iac.terraform"]);
  });

  test("keeps answers for proposals that did not come up this run", () => {
    const previous = parseSentinelConfig(
      JSON.stringify({ schemaVersion: "1.0", answers: { "data.deep-migrations": "off" } }),
    ).config;
    const merged = mergeDecisionIntoConfig(previous, decideScope(set, { include: ["terraform"] }));
    expect(merged.answers["data.deep-migrations"]).toBe("off");
  });
});

describe("serializeSentinelConfig", () => {
  test("is stable, sorted and newline-terminated, so it diffs cleanly", () => {
    const decision = decideScope(set, { include: ["iam"], exclude: ["terraform"] });
    const text = serializeSentinelConfig(mergeDecisionIntoConfig(emptySentinelConfig(), decision));
    expect(text.endsWith("\n")).toBe(true);
    expect(text.indexOf("delivery.iac.terraform")).toBeLessThan(
      text.indexOf("serverless.iam-audit"),
    );
    expect(parseSentinelConfig(text).config.answers["serverless.iam-audit"]).toBe("on");
  });
});
