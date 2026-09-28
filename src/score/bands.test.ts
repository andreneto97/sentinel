import { describe, expect, test } from "bun:test";
import { SCORE_BANDS } from "../contracts/scorecard.ts";
import { BAND_TABLE, NOT_ASSESSED_LABEL, bandFor, bandLabel, describeScore } from "./bands.ts";

describe("the band table", () => {
  test("covers every band the contract declares, once", () => {
    expect(BAND_TABLE.map((definition) => definition.band)).toEqual([...SCORE_BANDS]);
  });

  test("is ordered best first and reaches down to zero", () => {
    const mins = BAND_TABLE.map((definition) => definition.min);
    expect(mins).toEqual([...mins].sort((left, right) => right - left));
    expect(mins.at(-1)).toBe(0);
  });

  test("gives every band a sentence a client can read", () => {
    for (const definition of BAND_TABLE) {
      expect(definition.label.length).toBeGreaterThan(10);
      expect(bandLabel(definition.band)).toBe(definition.label);
    }
  });
});

describe("bandFor", () => {
  test("puts each boundary in the band the plan names", () => {
    expect(bandFor(100)).toBe("A");
    expect(bandFor(90)).toBe("A");
    expect(bandFor(89)).toBe("B");
    expect(bandFor(75)).toBe("B");
    expect(bandFor(74)).toBe("C");
    expect(bandFor(60)).toBe("C");
    expect(bandFor(59)).toBe("D");
    expect(bandFor(40)).toBe("D");
    expect(bandFor(39)).toBe("F");
    expect(bandFor(0)).toBe("F");
  });

  test("clamps a score that escaped the 0-100 range instead of failing", () => {
    expect(bandFor(120)).toBe("A");
    expect(bandFor(-5)).toBe("F");
  });
});

describe("describeScore", () => {
  test("never prints a number for a domain that was not assessed", () => {
    expect(describeScore(null)).toBe(NOT_ASSESSED_LABEL);
    expect(describeScore(null)).not.toContain("0");
    expect(describeScore(null)).not.toContain("100");
  });

  test("prints the number with its band when there is one", () => {
    expect(describeScore(82)).toBe("82 (B)");
    expect(describeScore(100)).toBe("100 (A)");
    // The two cases a reader must never confuse.
    expect(describeScore(0)).not.toBe(describeScore(null));
  });
});
