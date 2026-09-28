import { describe, expect, test } from "bun:test";
import {
  type CommandSpec,
  flagBoolean,
  flagList,
  flagNumber,
  flagProvided,
  flagString,
  parseArgs,
  renderCommandHelp,
} from "./args.ts";

const spec: CommandSpec = {
  name: "analyze",
  summary: "Analyse a repository.",
  positionals: [{ name: "target", description: "Repository path", required: true }],
  flags: {
    out: { kind: "string", short: "o", placeholder: "dir", description: "Output directory" },
    include: { kind: "list", description: "Domains to enable" },
    "max-parallel": { kind: "number", placeholder: "n", description: "Concurrent batches" },
    ai: { kind: "boolean", negatable: true, helpName: "--no-ai", description: "Skip AI phases" },
    verbose: { kind: "boolean", short: "v", description: "Log every step" },
    quiet: { kind: "boolean", short: "q", description: "Only failures" },
  },
};

/** Parse and assert success, so each test reads as one assertion. */
function parseOk(argv: readonly string[]) {
  const outcome = parseArgs(spec, argv);
  if (!outcome.ok) throw new Error(`expected a successful parse, got: ${outcome.error.message}`);
  return outcome.value;
}

describe("parseArgs", () => {
  test("accepts --flag=value", () => {
    const args = parseOk(["repo", "--out=/tmp/out"]);
    expect(flagString(args, "out")).toBe("/tmp/out");
    expect(args.positionals).toEqual(["repo"]);
  });

  test("accepts --flag value", () => {
    const args = parseOk(["--out", "/tmp/out", "repo"]);
    expect(flagString(args, "out")).toBe("/tmp/out");
    expect(args.positionals).toEqual(["repo"]);
  });

  test("bundles short boolean flags", () => {
    const args = parseOk(["-vq", "repo"]);
    expect(flagBoolean(args, "verbose")).toBe(true);
    expect(flagBoolean(args, "quiet")).toBe(true);
  });

  test("lets the last flag of a bundle take the rest of the token as its value", () => {
    const args = parseOk(["-vo/tmp/out", "repo"]);
    expect(flagBoolean(args, "verbose")).toBe(true);
    expect(flagString(args, "out")).toBe("/tmp/out");
  });

  test("lets the last flag of a bundle take the next token as its value", () => {
    const args = parseOk(["-vo", "/tmp/out", "repo"]);
    expect(flagString(args, "out")).toBe("/tmp/out");
  });

  test("stops parsing flags at the -- terminator", () => {
    const args = parseOk(["repo", "--", "--out", "-v"]);
    expect(args.rest).toEqual(["--out", "-v"]);
    expect(flagProvided(args, "out")).toBe(false);
    expect(flagBoolean(args, "verbose")).toBe(false);
  });

  test("rejects an unknown long flag as a usage error", () => {
    const outcome = parseArgs(spec, ["repo", "--nope"]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error.kind).toBe("unknown-flag");
    expect(outcome.error.command).toBe("analyze");
  });

  test("rejects an unknown short flag as a usage error", () => {
    const outcome = parseArgs(spec, ["repo", "-x"]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error.kind).toBe("unknown-flag");
    expect(outcome.error.message).toContain("-x");
  });

  test("rejects a value flag with nothing after it", () => {
    const outcome = parseArgs(spec, ["repo", "--out"]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error.kind).toBe("missing-value");
  });

  test("does not let a value flag swallow the next flag", () => {
    const outcome = parseArgs(spec, ["repo", "--out", "--verbose"]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error.kind).toBe("missing-value");
  });

  test("splits and accumulates list flags", () => {
    const args = parseOk(["repo", "--include", "appsec,data", "--include=deadcode"]);
    expect(flagList(args, "include")).toEqual(["appsec", "data", "deadcode"]);
  });

  test("reads an absent list flag as empty", () => {
    expect(flagList(parseOk(["repo"]), "include")).toEqual([]);
  });

  test("parses integer flags and rejects non-integers", () => {
    expect(flagNumber(parseOk(["repo", "--max-parallel", "4"]), "max-parallel")).toBe(4);
    const outcome = parseArgs(spec, ["repo", "--max-parallel", "two"]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error.kind).toBe("invalid-value");
  });

  test("accepts a negative number as a flag value", () => {
    expect(flagNumber(parseOk(["repo", "--max-parallel", "-1"]), "max-parallel")).toBe(-1);
  });

  test("turns --no-<flag> into false for a negatable boolean", () => {
    const args = parseOk(["repo", "--no-ai"]);
    expect(flagProvided(args, "ai")).toBe(true);
    expect(flagBoolean(args, "ai", true)).toBe(false);
  });

  test("leaves an unprovided boolean at its fallback", () => {
    const args = parseOk(["repo"]);
    expect(flagProvided(args, "ai")).toBe(false);
    expect(flagBoolean(args, "ai", true)).toBe(true);
  });

  test("rejects a value attached to a switch", () => {
    const outcome = parseArgs(spec, ["repo", "--verbose=loud"]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error.kind).toBe("invalid-value");
  });

  test("requires declared positionals and rejects extra ones", () => {
    const missing = parseArgs(spec, ["--verbose"]);
    expect(missing.ok).toBe(false);
    if (!missing.ok) expect(missing.error.kind).toBe("missing-positional");

    const extra = parseArgs(spec, ["one", "two"]);
    expect(extra.ok).toBe(false);
    if (!extra.ok) expect(extra.error.kind).toBe("unexpected-positional");
  });

  test("skips positional checks when --help is asked for", () => {
    const args = parseOk(["--help"]);
    expect(flagBoolean(args, "help")).toBe(true);
  });

  test("treats a lone dash as a positional", () => {
    expect(parseOk(["-"]).positionals).toEqual(["-"]);
  });
});

describe("renderCommandHelp", () => {
  test("shows the usage line, arguments and every flag", () => {
    const help = renderCommandHelp(spec);
    expect(help).toContain("Usage: sentinel analyze <target> [options]");
    expect(help).toContain("<target>");
    expect(help).toContain("-o, --out <dir>");
    expect(help).toContain("--no-ai");
    expect(help).toContain("-h, --help");
  });
});
