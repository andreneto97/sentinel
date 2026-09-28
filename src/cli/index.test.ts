import { describe, expect, test } from "bun:test";
import {
  type AnalyzeInvocation,
  type CommandHandlers,
  EXIT,
  type RunDirInvocation,
  type SetupInvocation,
  runCli,
} from "./index.ts";

/** Run the CLI with captured streams and a fixed cwd. */
async function run(argv: readonly string[], handlers: Partial<CommandHandlers> = {}) {
  let stdout = "";
  let stderr = "";
  const code = await runCli(argv, {
    context: {
      cwd: "/work",
      write: (text) => {
        stdout += text;
      },
      writeError: (text) => {
        stderr += text;
      },
    },
    handlers,
  });
  return { code, stdout, stderr };
}

describe("global behaviour", () => {
  test("prints the root help to stderr and fails when given nothing", async () => {
    const result = await run([]);
    expect(result.code).toBe(EXIT.usage);
    expect(result.stderr).toContain("Usage: sentinel <command>");
    expect(result.stdout).toBe("");
  });

  test("prints the version", async () => {
    const result = await run(["--version"]);
    expect(result.code).toBe(EXIT.ok);
    expect(result.stdout.trim()).toMatch(/^\d+\.\d+\.\d+$/);
  });

  test("prints the root help on --help", async () => {
    const result = await run(["--help"]);
    expect(result.code).toBe(EXIT.ok);
    expect(result.stdout).toContain("Commands:");
    expect(result.stdout).toContain("analyze");
  });

  test("prints one command's help via `help <command>`", async () => {
    const result = await run(["help", "analyze"]);
    expect(result.stdout).toContain("Usage: sentinel analyze <target> [options]");
    expect(result.stdout).toContain("--no-ai");
  });

  test("prints one command's help via `<command> --help` without running it", async () => {
    let called = false;
    const result = await run(["analyze", "--help"], {
      analyze: async () => {
        called = true;
        return EXIT.ok;
      },
    });
    expect(result.code).toBe(EXIT.ok);
    expect(called).toBe(false);
    expect(result.stdout).toContain("Usage: sentinel analyze");
  });

  test("rejects an unknown command", async () => {
    const result = await run(["analyse", "/repo"]);
    expect(result.code).toBe(EXIT.usage);
    expect(result.stderr).toContain('unknown command "analyse"');
  });

  test("rejects an unknown global flag", async () => {
    const result = await run(["--lint"]);
    expect(result.code).toBe(EXIT.usage);
    expect(result.stderr).toContain('unknown flag "--lint"');
  });

  test("rejects an unknown flag on a command, naming the command in the hint", async () => {
    const result = await run(["analyze", "/repo", "--deep"]);
    expect(result.code).toBe(EXIT.usage);
    expect(result.stderr).toContain('unknown flag "--deep"');
    expect(result.stderr).toContain("sentinel analyze --help");
  });

  test("rejects --verbose together with --quiet", async () => {
    const result = await run(["analyze", "/repo", "-vq"]);
    expect(result.code).toBe(EXIT.usage);
    expect(result.stderr).toContain("cannot be combined");
  });
});

describe("analyze", () => {
  /** Capture the invocation an analyze handler receives. */
  async function invoke(argv: readonly string[]) {
    let seen: AnalyzeInvocation | undefined;
    const result = await run(argv, {
      analyze: async (_context, invocation) => {
        seen = invocation;
        return EXIT.ok;
      },
    });
    return { result, seen };
  }

  test("requires a target", async () => {
    const result = await run(["analyze"]);
    expect(result.code).toBe(EXIT.usage);
    expect(result.stderr).toContain("<target>");
  });

  test("resolves the target against the cwd", async () => {
    const { result, seen } = await invoke(["analyze", "api"]);
    expect(result.code).toBe(EXIT.ok);
    expect(seen?.target).toBe("/work/api");
    expect(seen?.cwd).toBe("/work");
  });

  test("passes only the flags that were given, so the config can fill the rest", async () => {
    const { seen } = await invoke(["analyze", "/repo"]);
    expect(seen?.flags).toEqual({ json: false, verbose: false, quiet: false });
  });

  test("collects every analyze flag", async () => {
    const { seen } = await invoke([
      "analyze",
      "/repo",
      "--out=/tmp/out",
      "--include",
      "terraform,iam",
      "--exclude=deadcode",
      "--propose-only",
      "--yes",
      "--no-ai",
      "--max-parallel",
      "4",
      "--skip-scan",
      "--path=apps/api",
      "--json",
    ]);
    expect(seen?.flags).toEqual({
      out: "/tmp/out",
      path: ["apps/api"],
      include: ["terraform", "iam"],
      exclude: ["deadcode"],
      proposeOnly: true,
      yes: true,
      ai: false,
      maxParallel: 4,
      skipScan: true,
      json: true,
      verbose: false,
      quiet: false,
    });
  });

  test("collects the audit budget flags", async () => {
    const { seen } = await invoke([
      "analyze",
      "/repo",
      "--max-batches",
      "12",
      "--max-units=300",
      "--max-audit-minutes",
      "5",
    ]);
    expect(seen?.flags.maxBatches).toBe(12);
    expect(seen?.flags.maxUnits).toBe(300);
    expect(seen?.flags.maxAuditMinutes).toBe(5);
    expect(seen?.flags.noBudget).toBeUndefined();
  });

  test("--no-budget turns every ceiling off", async () => {
    const { seen } = await invoke(["analyze", "/repo", "--no-budget"]);
    expect(seen?.flags.noBudget).toBe(true);
  });

  test("an absent budget flag is absent, so the built-in default answers", async () => {
    const { seen } = await invoke(["analyze", "/repo"]);
    expect(seen?.flags.maxBatches).toBeUndefined();
    expect(seen?.flags.noBudget).toBeUndefined();
  });

  test("--path is repeatable, and comma-separated, and keeps the case it was typed in", async () => {
    const { seen } = await invoke([
      "analyze",
      "/repo",
      "--path",
      "apps/API",
      "-p",
      "libs/shared,libs/other",
    ]);
    expect(seen?.flags.path).toEqual(["apps/API", "libs/shared", "libs/other"]);
  });

  test("an absent --path is absent, so the config file can answer instead", async () => {
    const { seen } = await invoke(["analyze", "/repo"]);
    expect(seen?.flags.path).toBeUndefined();
  });

  test("--path appears in the analyze help", async () => {
    const result = await run(["analyze", "--help"]);
    expect(result.stdout).toContain("--path <glob-or-dir>");
  });

  test("rejects a non-positive --max-parallel", async () => {
    const result = await run(["analyze", "/repo", "--max-parallel", "0"]);
    expect(result.code).toBe(EXIT.usage);
    expect(result.stderr).toContain("--max-parallel must be at least 1");
  });

  // `analyze` is wired to the real handler (src/cli/analyze.ts), so with no
  // injected handler the command runs for real and fails its own preflight.
  test("falls back to the real handler when none is injected", async () => {
    const result = await run(["analyze", "/no/such/repository-9c1f"]);
    expect(result.code).toBe(EXIT.preflight);
    expect(result.stderr).toContain("does not exist");
  });

  test("turns a handler failure into exit 1 with its message", async () => {
    const result = await run(["analyze", "/repo"], {
      analyze: async () => {
        throw new Error("phase 0 blew up");
      },
    });
    expect(result.code).toBe(EXIT.failure);
    expect(result.stderr).toContain("analyze failed: phase 0 blew up");
  });
});

describe("setup", () => {
  test("parses --only and --force", async () => {
    let seen: SetupInvocation | undefined;
    const result = await run(["setup", "--only", "trivy", "-f"], {
      setup: async (_context, invocation) => {
        seen = invocation;
        return EXIT.ok;
      },
    });
    expect(result.code).toBe(EXIT.ok);
    expect(seen?.only).toBe("trivy");
    expect(seen?.force).toBe(true);
  });

  test("leaves --only absent when it was not given", async () => {
    let seen: SetupInvocation | undefined;
    await run(["setup"], {
      setup: async (_context, invocation) => {
        seen = invocation;
        return EXIT.ok;
      },
    });
    expect(seen).toEqual({ force: false, output: { json: false, verbose: false, quiet: false } });
  });
});

describe("doctor", () => {
  test("forwards its argv untouched, because doctor parses its own", async () => {
    let seen: readonly string[] | undefined;
    const result = await run(["doctor", "/repo", "--json"], {
      doctor: async (_context, argv) => {
        seen = argv;
        return EXIT.ok;
      },
    });
    expect(result.code).toBe(EXIT.ok);
    expect(seen).toEqual(["/repo", "--json"]);
  });

  test("asks doctor for its own help text", async () => {
    let seen: readonly string[] | undefined;
    await run(["help", "doctor"], {
      doctor: async (_context, argv) => {
        seen = argv;
        return EXIT.ok;
      },
    });
    expect(seen).toEqual(["--help"]);
  });

  test("passes the preflight exit code through", async () => {
    const result = await run(["doctor"], { doctor: async () => EXIT.preflight });
    expect(result.code).toBe(EXIT.preflight);
  });
});

describe("resume, status and report", () => {
  for (const command of ["resume", "status", "report"] as const) {
    test(`${command} requires a run directory`, async () => {
      const result = await run([command]);
      expect(result.code).toBe(EXIT.usage);
      expect(result.stderr).toContain("<run-dir>");
    });

    test(`${command} passes the run directory through verbatim`, async () => {
      let seen: RunDirInvocation | undefined;
      const result = await run([command, "sentinel", "--verbose"], {
        [command]: async (_context: unknown, invocation: RunDirInvocation) => {
          seen = invocation;
          return EXIT.ok;
        },
      });
      expect(result.code).toBe(EXIT.ok);
      expect(seen?.runDir).toBe("sentinel");
      expect(seen?.cwd).toBe("/work");
      expect(seen?.output.verbose).toBe(true);
    });

    test(`${command} runs its real handler, which refuses a run directory that is not there`, async () => {
      // No handler override: this is the default wiring, reaching the real
      // filesystem port for a path that does not exist.
      const result = await run([command, "sentinel"]);
      expect(result.code).toBe(EXIT.preflight);
      expect(result.stderr).toContain("does not exist");
    });
  }

  test("report rejects a format it cannot render", async () => {
    const result = await run(["report", "sentinel", "--format", "docx"]);
    expect(result.code).toBe(EXIT.usage);
    expect(result.stderr).toContain("--format must be one of");
  });

  test("report passes the format and the output override through", async () => {
    let seen: { format?: string | undefined; out?: string | undefined } | undefined;
    const result = await run(["report", "sentinel", "--format", "md", "--out", "dossier"], {
      report: async (
        _context: unknown,
        invocation: { format: string; out?: string | undefined },
      ) => {
        seen = invocation;
        return EXIT.ok;
      },
    });
    expect(result.code).toBe(EXIT.ok);
    expect(seen?.format).toBe("md");
    expect(seen?.out).toBe("dossier");
  });

  test("report passes --triage through as typed", async () => {
    let seen: { triage?: string | undefined } | undefined;
    const result = await run(["report", "sentinel", "--triage", "review/triage.json"], {
      report: async (_context: unknown, invocation: { triage?: string | undefined }) => {
        seen = invocation;
        return EXIT.ok;
      },
    });
    expect(result.code).toBe(EXIT.ok);
    expect(seen?.triage).toBe("review/triage.json");
  });

  test("report rejects --triage with no file, rather than rendering the raw run", async () => {
    const result = await run(["report", "sentinel", "--triage="]);
    expect(result.code).toBe(EXIT.usage);
    expect(result.stderr).toContain("--triage needs the path of a triage file");
  });

  test("report passes --brief through, and leaves it off when it is not asked for", async () => {
    let seen: { brief?: boolean | undefined } | undefined;
    const handler = async (_context: unknown, invocation: { brief?: boolean | undefined }) => {
      seen = invocation;
      return EXIT.ok;
    };
    await run(["report", "sentinel", "--brief"], { report: handler });
    expect(seen?.brief).toBe(true);
    await run(["report", "sentinel"], { report: handler });
    expect(seen?.brief).toBeUndefined();
  });

  test("report accepts brief as a format, so the brief can be rendered on its own", async () => {
    let seen: { format?: string | undefined } | undefined;
    const result = await run(["report", "sentinel", "--format", "brief"], {
      report: async (_context: unknown, invocation: { format?: string | undefined }) => {
        seen = invocation;
        return EXIT.ok;
      },
    });
    expect(result.code).toBe(EXIT.ok);
    expect(seen?.format).toBe("brief");
  });

  test("report renders without a review when --triage is not given", async () => {
    let seen: { triage?: string | undefined } | undefined = { triage: "sentinel" };
    await run(["report", "sentinel"], {
      report: async (_context: unknown, invocation: { triage?: string | undefined }) => {
        seen = invocation;
        return EXIT.ok;
      },
    });
    expect(seen?.triage).toBeUndefined();
  });

  test("resume rejects a phase name that is not a phase", async () => {
    const result = await run(["resume", "sentinel", "--force-phase", "scoring"]);
    expect(result.code).toBe(EXIT.usage);
    expect(result.stderr).toContain("--force-phase must name a phase");
  });

  test("resume passes --force-phase, --retry-failed and --max-parallel through", async () => {
    let seen:
      | {
          forcePhase?: string | undefined;
          retryFailed?: boolean | undefined;
          maxParallel?: number | undefined;
        }
      | undefined;
    const result = await run(
      ["resume", "sentinel", "--force-phase", "audit", "--retry-failed", "--max-parallel", "4"],
      {
        resume: async (
          _context: unknown,
          invocation: {
            forcePhase?: string | undefined;
            retryFailed?: boolean | undefined;
            maxParallel?: number | undefined;
          },
        ) => {
          seen = invocation;
          return EXIT.ok;
        },
      },
    );
    expect(result.code).toBe(EXIT.ok);
    expect(seen?.forcePhase).toBe("audit");
    expect(seen?.retryFailed).toBe(true);
    expect(seen?.maxParallel).toBe(4);
  });
});
