import { describe, expect, test } from "bun:test";
import type { CodeRef } from "../contracts/findings.ts";
import { MemoryFileSystem } from "./_memory-file-system.ts";
import type { VerifyContext, VerifyFileSystem } from "./context.ts";
import { createVerifyCache, verifyCodeRef } from "./verify-code-ref.ts";

const ORDERS = [
  'import { db } from "../db.ts";',
  "",
  "export async function listOrders(req, res) {",
  "  const rows = await db.order.findMany();",
  "  res.json(rows);",
  "}",
];

const DUPLICATED = [
  "function a() {",
  "  res.json(rows);",
  "}",
  "function b() {",
  "  res.json(rows);",
  "}",
];

const PNG = new Uint8Array([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
]);

function fixture(): MemoryFileSystem {
  return new MemoryFileSystem({
    files: {
      "/repo/src/api/orders.ts": `${ORDERS.join("\n")}\n`,
      "/repo/src/api/orders-crlf.ts": `${ORDERS.join("\r\n")}\r\n`,
      "/repo/src/api/duplicated.ts": DUPLICATED.join("\n"),
      "/repo/src/api/tabbed.ts": "function f() {\n\tconst a = 1;\n}\n",
      "/repo/src/empty.ts": "",
      "/repo/assets/logo.png": PNG,
      "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
    },
    links: { "/repo/src/api/leak.ts": "/etc/passwd" },
  });
}

function contextWith(fs: VerifyFileSystem): VerifyContext {
  return { fs, targetDir: "/repo", contextLines: 1 };
}

const ref = (partial: Partial<CodeRef> & Pick<CodeRef, "file" | "line">): CodeRef => partial;

describe("verifyCodeRef path safety", () => {
  test("refuses a path that escapes the target", async () => {
    const result = await verifyCodeRef(
      ref({ file: "../../etc/passwd", line: 1 }),
      contextWith(fixture()),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("path-escape");
  });

  test("refuses a symlink whose target is outside the target directory", async () => {
    const result = await verifyCodeRef(
      ref({ file: "src/api/leak.ts", line: 1 }),
      contextWith(fixture()),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("path-escape");
      expect(result.detail).toContain("links outside");
    }
  });

  test("refuses a file that does not exist", async () => {
    const result = await verifyCodeRef(
      ref({ file: "src/api/ghost.ts", line: 1 }),
      contextWith(fixture()),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("file-not-found");
  });

  test("normalises an absolute in-repo path to a repo-relative POSIX path", async () => {
    const result = await verifyCodeRef(
      ref({ file: "/repo/./src/api/orders.ts", line: 3 }),
      contextWith(fixture()),
    );
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.ref.file).toBe("src/api/orders.ts");
  });
});

describe("verifyCodeRef line bounds", () => {
  test("refuses a line past end of file", async () => {
    const result = await verifyCodeRef(
      ref({ file: "src/api/orders.ts", line: 900 }),
      contextWith(fixture()),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("line-out-of-range");
      expect(result.detail).toContain("6 lines");
    }
  });

  test("refuses line 1 of an empty file", async () => {
    const result = await verifyCodeRef(
      ref({ file: "src/empty.ts", line: 1 }),
      contextWith(fixture()),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("line-out-of-range");
  });

  test("refuses a binary file", async () => {
    const result = await verifyCodeRef(
      ref({ file: "assets/logo.png", line: 1 }),
      contextWith(fixture()),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("binary-file");
  });
});

describe("verifyCodeRef snippets", () => {
  test("extracts the snippet from disk even when the caller supplied one", async () => {
    const result = await verifyCodeRef(
      ref({
        file: "src/api/orders.ts",
        line: 5,
        snippet: "if (user.isAdmin) { grantEverything(); } // invented by the model",
      }),
      contextWith(fixture()),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.ref.snippet).toBe(
      [
        "  4 |   const rows = await db.order.findMany();",
        "> 5 |   res.json(rows);",
        "  6 | }",
      ].join("\n"),
    );
    expect(result.ref.snippet).not.toContain("grantEverything");
    expect(result.relocated).toBe(false);
  });

  test("numbers a CRLF file like an editor and strips the terminators", async () => {
    const result = await verifyCodeRef(
      ref({ file: "src/api/orders-crlf.ts", line: 3 }),
      contextWith(fixture()),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.ref.snippet).not.toContain("\r");
    expect(result.ref.snippet?.split("\n")[1]).toBe(
      "> 3 | export async function listOrders(req, res) {",
    );
  });

  test("normalises tabs in the snippet", async () => {
    const result = await verifyCodeRef(ref({ file: "src/api/tabbed.ts", line: 2 }), {
      fs: fixture(),
      targetDir: "/repo",
      contextLines: 0,
      tabWidth: 4,
    });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.ref.snippet).toBe("> 2 | const a = 1;");
  });

  test("keeps a valid endLine and drops one the file cannot support", async () => {
    const fs = fixture();
    const kept = await verifyCodeRef(
      ref({ file: "src/api/orders.ts", line: 3, endLine: 5 }),
      contextWith(fs),
    );
    expect(kept.ok).toBe(true);
    if (kept.ok) expect(kept.ref.endLine).toBe(5);

    const clamped = await verifyCodeRef(
      ref({ file: "src/api/orders.ts", line: 3, endLine: 2 }),
      contextWith(fs),
    );
    expect(clamped.ok).toBe(true);
    if (clamped.ok) expect(clamped.ref.endLine).toBeUndefined();
  });
});

describe("verifyCodeRef relocation", () => {
  test("corrects a drifted line and records where it came from", async () => {
    const result = await verifyCodeRef(
      ref({
        file: "src/api/orders.ts",
        line: 2,
        snippet: "  const rows = await db.order.findMany();",
        note: "from the audit agent",
      }),
      contextWith(fixture()),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.relocated).toBe(true);
    expect(result.ref.line).toBe(4);
    expect(result.ref.note).toBe("from the audit agent · relocated from line 2");
    expect(result.ref.snippet).toContain("> 4 |   const rows = await db.order.findMany();");
  });

  test("relocates a line past EOF using a symbol hint", async () => {
    const result = await verifyCodeRef(
      ref({ file: "src/api/orders.ts", line: 412 }),
      contextWith(fixture()),
      { symbol: "listOrders" },
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.ref.line).toBe(3);
      expect(result.relocated).toBe(true);
    }
  });

  test("shifts endLine by the same delta", async () => {
    const result = await verifyCodeRef(
      ref({
        file: "src/api/orders.ts",
        line: 2,
        endLine: 3,
        snippet: "const rows = await db.order.findMany();",
      }),
      contextWith(fixture()),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.ref.line).toBe(4);
      expect(result.ref.endLine).toBe(5);
    }
  });

  test("refuses to guess when the anchor is ambiguous, keeping a line that exists", async () => {
    const result = await verifyCodeRef(
      ref({ file: "src/api/duplicated.ts", line: 1, snippet: "  res.json(rows);" }),
      contextWith(fixture()),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.ref.line).toBe(1);
      expect(result.relocated).toBe(false);
      expect(result.ref.note).toBeUndefined();
    }
  });

  test("drops a past-EOF citation when the anchor is ambiguous", async () => {
    const result = await verifyCodeRef(
      ref({ file: "src/api/duplicated.ts", line: 90, snippet: "  res.json(rows);" }),
      contextWith(fixture()),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("line-out-of-range");
  });
});

describe("verifyCodeRef caching", () => {
  test("reads each file once per cache", async () => {
    const inner = fixture();
    let reads = 0;
    const counting: VerifyFileSystem = {
      realpath: (path) => inner.realpath(path),
      readBytes: (path) => {
        reads += 1;
        return inner.readBytes(path);
      },
    };
    const ctx = contextWith(counting);
    const cache = createVerifyCache();
    await verifyCodeRef(ref({ file: "src/api/orders.ts", line: 3 }), ctx, {}, cache);
    await verifyCodeRef(ref({ file: "src/api/orders.ts", line: 5 }), ctx, {}, cache);
    expect(reads).toBe(1);
  });
});
