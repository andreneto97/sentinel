import { describe, expect, test } from "bun:test";
import { answerHint, createAsker, createLineReader, parseAnswer } from "./ask.ts";

/** An async iterable over fixed chunks, standing in for `process.stdin`. */
async function* chunks(...values: readonly (string | Uint8Array)[]) {
  for (const value of values) yield value;
}

describe("parseAnswer", () => {
  test("accepts y/yes and n/no in any case", () => {
    for (const yes of ["y", "Y", "yes", " YES "]) expect(parseAnswer(yes, false)).toBe(true);
    for (const no of ["n", "N", "no", " No "]) expect(parseAnswer(no, true)).toBe(false);
  });

  test("keeps the default for an empty or unrecognised answer", () => {
    expect(parseAnswer("", true)).toBe(true);
    expect(parseAnswer("", false)).toBe(false);
    expect(parseAnswer("maybe", true)).toBe(true);
  });
});

describe("answerHint", () => {
  test("shows which way enter goes", () => {
    expect(answerHint(true)).toBe("[Y/n]");
    expect(answerHint(false)).toBe("[y/N]");
  });
});

describe("createLineReader", () => {
  test("splits a stream into lines regardless of chunk boundaries", async () => {
    const reader = createLineReader(chunks("fir", "st\nsec", "ond\n"));
    expect(await reader.read()).toBe("first");
    expect(await reader.read()).toBe("second");
    expect(await reader.read()).toBe(null);
  });

  test("decodes bytes and strips a trailing carriage return", async () => {
    const reader = createLineReader(chunks(new TextEncoder().encode("yes\r\nno\r\n")));
    expect(await reader.read()).toBe("yes");
    expect(await reader.read()).toBe("no");
  });

  test("returns a final line that has no newline", async () => {
    const reader = createLineReader(chunks("last"));
    expect(await reader.read()).toBe("last");
    expect(await reader.read()).toBe(null);
  });

  test("keeps returning null after the stream ends", async () => {
    const reader = createLineReader(chunks());
    expect(await reader.read()).toBe(null);
    expect(await reader.read()).toBe(null);
  });
});

describe("createAsker", () => {
  test("prints the question with its hint and reads the answer", async () => {
    let written = "";
    const ask = createAsker(createLineReader(chunks("y\nn\n")), (text) => {
      written += text;
    });
    expect(await ask("Include terraform?", false)).toBe(true);
    expect(await ask("Include k8s?", true)).toBe(false);
    expect(written).toBe("Include terraform? [y/N] Include k8s? [Y/n] ");
  });

  test("answers with the default instead of blocking when input ends", async () => {
    const ask = createAsker(createLineReader(chunks()), () => {});
    expect(await ask("Include terraform?", true)).toBe(true);
    expect(await ask("Include k8s?", false)).toBe(false);
  });
});
