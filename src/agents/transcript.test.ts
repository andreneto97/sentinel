import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { parseAgentTranscript, serializeTranscript } from "./transcript.ts";

const DIR = join(import.meta.dir, "__fixtures__/transcripts");

/** Reads a committed fixture the way `loadAgentTranscript` would. */
async function fixture(name: string): Promise<string> {
  return await Bun.file(join(DIR, `${name}.json`)).text();
}

describe("parseAgentTranscript", () => {
  test("accepts the transcript recorded against the live subscription", async () => {
    const parsed = parseAgentTranscript(await fixture("routes-recorded"));
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.transcript.source).toBe("recorded");
    expect(parsed.transcript.model).toBe("claude-opus-5-5");
    expect(parsed.transcript.entries.map((entry) => entry.batchId)).toEqual([
      "appsec-routes-001",
      "appsec-routes-correction",
    ]);
    // The recorded correction cycle really is two turns.
    expect(parsed.transcript.entries[1]?.turns).toHaveLength(2);
  });

  test("accepts the handwritten failure transcript and keeps it labelled as such", async () => {
    const parsed = parseAgentTranscript(await fixture("failures-handwritten"));
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.transcript.source).toBe("handwritten");
    expect(parsed.transcript.note).toContain("HANDWRITTEN, NOT RECORDED");
  });

  test("rejects a turn that is neither a reply nor a failure", () => {
    const parsed = parseAgentTranscript(
      JSON.stringify({
        schemaVersion: "1.0",
        source: "handwritten",
        entries: [{ batchId: "b", turns: [{}] }],
      }),
    );
    expect(parsed.ok).toBe(false);
  });

  test("rejects a turn that is both a reply and a failure", () => {
    const parsed = parseAgentTranscript(
      JSON.stringify({
        schemaVersion: "1.0",
        source: "handwritten",
        entries: [
          { batchId: "b", turns: [{ reply: "{}", failure: { kind: "quota", detail: "x" } }] },
        ],
      }),
    );
    expect(parsed.ok).toBe(false);
  });

  test("rejects an unknown source label, so a fixture cannot quietly claim to be real", () => {
    const parsed = parseAgentTranscript(
      JSON.stringify({ schemaVersion: "1.0", source: "probably-real", entries: [] }),
    );
    expect(parsed.ok).toBe(false);
  });

  test("rejects an unknown failure kind", () => {
    const parsed = parseAgentTranscript(
      JSON.stringify({
        schemaVersion: "1.0",
        source: "handwritten",
        entries: [{ batchId: "b", turns: [{ failure: { kind: "exploded", detail: "x" } }] }],
      }),
    );
    expect(parsed.ok).toBe(false);
  });

  test("rejects a wrong schema version", () => {
    const parsed = parseAgentTranscript(
      JSON.stringify({ schemaVersion: "2.0", source: "handwritten", entries: [] }),
    );
    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.reason).toContain("schemaVersion");
  });

  test("reports unparseable JSON rather than throwing", () => {
    const parsed = parseAgentTranscript("{not json");
    expect(parsed.ok).toBe(false);
  });
});

describe("serializeTranscript", () => {
  test("round-trips through the schema, filling in defaults", () => {
    const text = serializeTranscript({
      schemaVersion: "1.0",
      source: "handwritten",
      entries: [{ batchId: "b", turns: [{ reply: "{}" }] }],
    });
    const parsed = parseAgentTranscript(text);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.transcript.entries[0]?.turns[0]?.expectPromptContains).toEqual([]);
    expect(text.endsWith("\n")).toBe(true);
  });
});
