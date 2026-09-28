import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { z } from "zod";
import { extractJson, formatSchemaViolation, parseStructured } from "./json.ts";
import { parseAgentTranscript } from "./transcript.ts";

/** The real reply a Claude subscription returned for a route batch, recorded live. */
const RECORDED = await Bun.file(
  join(import.meta.dir, "__fixtures__/transcripts/routes-recorded.json"),
).text();

const VerdictsSchema = z.object({
  verdicts: z
    .array(
      z.object({
        unitId: z.string(),
        ownershipChecked: z.boolean(),
        evidenceLine: z.number().int().positive(),
      }),
    )
    .min(1),
});

/** The first recorded reply body. */
function recordedReply(batchId: string, turn = 0): string {
  const parsed = parseAgentTranscript(RECORDED);
  if (!parsed.ok) throw new Error(parsed.reason);
  const entry = parsed.transcript.entries.find((candidate) => candidate.batchId === batchId);
  const reply = entry?.turns[turn]?.reply;
  if (reply === undefined) throw new Error(`no recorded reply for ${batchId}#${turn}`);
  return reply;
}

describe("extractJson", () => {
  test("reads the bare document a real agent reply contains", () => {
    const result = extractJson(recordedReply("appsec-routes-001"));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.strategy).toBe("bare");
    expect(result.value).toHaveProperty("verdicts");
  });

  test("prefers a fenced block over the prose around it", () => {
    const reply = 'Here is the result:\n\n```json\n{"verdicts": []}\n```\n\nLet me know.';
    const result = extractJson(reply);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.strategy).toBe("fenced");
    expect(result.text).toBe('{"verdicts": []}');
  });

  test("ignores a fence that is not JSON and falls through to the real document", () => {
    const reply = '```ts\nconst x = 1;\n```\n\n```json\n{"ok": true}\n```';
    const result = extractJson(reply);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value).toEqual({ ok: true });
  });

  test("finds an unfenced document buried in prose", () => {
    const result = extractJson('Sure thing. {"verdicts": [1, 2]} — hope that helps.');
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.strategy).toBe("brace-span");
    expect(result.value).toEqual({ verdicts: [1, 2] });
  });

  test("does not let a brace inside a quoted code snippet close the span early", () => {
    const reply = 'note:\n{"snippet": "if (x) { return { a: 1 }; }", "line": 4}';
    const result = extractJson(reply);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value).toEqual({ snippet: "if (x) { return { a: 1 }; }", line: 4 });
  });

  test("handles an escaped quote before a brace", () => {
    const result = extractJson('{"q": "he said \\"{\\" loudly", "n": 1}');
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value).toEqual({ q: 'he said "{" loudly', n: 1 });
  });

  test("reports an unterminated document separately from a malformed one", () => {
    const result = extractJson('{"verdicts": [{"unitId": "route-001", "note": "findUnique filt');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("unterminated");
  });

  test("reports a prose-only reply as no-json", () => {
    const result = extractJson("I reviewed the handler and it looks fine to me.");
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("no-json");
  });

  test("reports an empty reply", () => {
    const result = extractJson("   \n  ");
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("empty");
  });

  test("reports a balanced but invalid document as invalid-json", () => {
    const result = extractJson("prefix {not: json, at all} suffix");
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("invalid-json");
  });

  test("reads a top-level array", () => {
    const result = extractJson("[1, 2, 3]");
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value).toEqual([1, 2, 3]);
  });
});

describe("parseStructured", () => {
  test("validates a real recorded reply against the schema", () => {
    const parsed = parseStructured(recordedReply("appsec-routes-001"), VerdictsSchema);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.value.verdicts).toHaveLength(2);
    expect(parsed.value.verdicts[0]?.unitId).toBe("route-001");
    expect(parsed.value.verdicts[0]?.ownershipChecked).toBe(false);
  });

  test("names the missing field when the recorded first turn is checked against the stricter schema", () => {
    const Strict = VerdictsSchema.extend({
      verdicts: z.array(
        z.object({
          unitId: z.string(),
          ownershipChecked: z.boolean(),
          evidenceLine: z.number(),
          severity: z.enum(["critical", "high", "medium", "low", "info"]),
        }),
      ),
    });
    const parsed = parseStructured(recordedReply("appsec-routes-correction", 0), Strict);
    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.failure.kind).toBe("malformed-output");
    expect(parsed.failure.detail).toContain("verdicts.0.severity");
  });

  test("maps a cut-off reply to truncated-output, not malformed-output", () => {
    const parsed = parseStructured('{"verdicts": [{"unitId": "route-0', VerdictsSchema);
    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.failure.kind).toBe("truncated-output");
  });
});

describe("formatSchemaViolation", () => {
  test("renders one line per issue, with the path", () => {
    const result = z.object({ a: z.string(), b: z.number() }).safeParse({ a: 1 });
    expect(result.success).toBe(false);
    if (result.success) return;
    const text = formatSchemaViolation(result.error);
    expect(text).toContain("- a:");
    expect(text).toContain("- b:");
  });

  test("elides once there are more issues than a prompt can usefully carry", () => {
    const shape: Record<string, z.ZodTypeAny> = {};
    for (let index = 0; index < 12; index += 1) shape[`f${index}`] = z.string();
    const result = z.object(shape).safeParse({});
    expect(result.success).toBe(false);
    if (result.success) return;
    expect(formatSchemaViolation(result.error)).toContain("...and 4 more issues");
  });
});
