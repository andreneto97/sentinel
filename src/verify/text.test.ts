import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { createFileSystem } from "../ports/file-system.ts";
import {
  decodeUtf8,
  expandTabs,
  leadingSpaces,
  looksBinary,
  splitLines,
  truncate,
} from "./text.ts";

const encode = (value: string): Uint8Array => new TextEncoder().encode(value);

describe("splitLines", () => {
  test("numbers CRLF lines the way an editor does", () => {
    expect(splitLines("a\r\nb\r\nc")).toEqual(["a", "b", "c"]);
  });

  test("handles LF, lone CR and a trailing terminator", () => {
    expect(splitLines("a\nb\n")).toEqual(["a", "b"]);
    expect(splitLines("a\rb")).toEqual(["a", "b"]);
    expect(splitLines("a\n\n")).toEqual(["a", ""]);
    expect(splitLines("")).toEqual([]);
  });
});

describe("looksBinary", () => {
  test("flags a NUL byte", () => {
    expect(looksBinary(new Uint8Array([0x89, 0x50, 0x00, 0x01]))).toBe(true);
  });

  test("flags UTF-16 text, which is NUL-heavy", () => {
    expect(looksBinary(new Uint8Array([0x61, 0x00, 0x62, 0x00]))).toBe(true);
  });

  test("accepts source code, including tabs and CRLF", () => {
    expect(looksBinary(encode("const a = 1;\r\n\tconst b = 2;\n"))).toBe(false);
    expect(looksBinary(encode(""))).toBe(false);
    expect(looksBinary(encode('const name = "café ☕";'))).toBe(false);
  });

  test("flags a control-byte soup with no NUL", () => {
    expect(looksBinary(new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x61, 0x62]))).toBe(true);
  });
});

describe("expandTabs", () => {
  test("expands to the next tab stop", () => {
    expect(expandTabs("\tconst a = 1;", 2)).toBe("  const a = 1;");
    expect(expandTabs("a\tb", 4)).toBe("a   b");
    expect(expandTabs("no tabs", 4)).toBe("no tabs");
  });
});

describe("truncate", () => {
  test("marks the cut with an ellipsis", () => {
    expect(truncate("abcdef", 4)).toBe("abc…");
    expect(truncate("abc", 4)).toBe("abc");
  });
});

describe("decodeUtf8", () => {
  test("drops a byte-order mark", () => {
    expect(decodeUtf8(encode("﻿const a = 1;"))).toBe("const a = 1;");
  });
});

describe("leadingSpaces", () => {
  test("reports indentation and ignores blank lines", () => {
    expect(leadingSpaces("    a")).toBe(4);
    expect(leadingSpaces("   ")).toBe(null);
  });
});

describe("Sentinel's own sources", () => {
  /**
   * A literal NUL in a source file — `\u0000` written as the byte rather than
   * the escape — makes that file binary to git, to grep, to an editor, and to
   * {@link looksBinary}. Three of Sentinel's own modules used one as a key
   * separator, and the effect was that this verifier refused to read them back:
   * a real finding citing `src/profile/fact-builder.ts` was dropped as "binary
   * file" on every run. The invariant is cheap to keep and expensive to lose.
   */
  test("carry no NUL byte, so the citation verifier can read them back", async () => {
    const fs = createFileSystem();
    const root = join(import.meta.dir, "..");
    const sources = await fs.glob(["**/*.ts", "**/*.tsx"], { cwd: root, onlyFiles: true });
    const binary: string[] = [];
    for (const source of sources) {
      if (looksBinary(await fs.readFileBytes(join(root, source)))) binary.push(source);
    }
    expect(binary).toEqual([]);
  });
});
