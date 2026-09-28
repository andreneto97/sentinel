import { describe, expect, test } from "bun:test";
import { DoctorReportSchema } from "../contracts/doctor.ts";
import type {
  CommandResult,
  DoctorFileSystemPort,
  DoctorProcessPort,
  PinnedTool,
  ToolProbe,
} from "../tools/doctor.ts";
import { DOCTOR_USAGE, type DoctorCliDeps, doctorCommand, parseDoctorArgs } from "./doctor.ts";

const TARGET = "/repo";
const CACHE = "/cache";

/** Enough of a filesystem for the preflight: a readable repo and a writable output dir. */
const fileSystem: DoctorFileSystemPort = {
  async exists(path: string): Promise<boolean> {
    return path === TARGET || path === `${TARGET}/.git` || path === CACHE;
  },
  async isDirectory(path: string): Promise<boolean> {
    return path === TARGET;
  },
  async listDirectory(path: string): Promise<readonly string[]> {
    if (path !== TARGET) {
      throw new Error(`ENOENT: ${path}`);
    }
    return ["package.json", ".git"];
  },
  async ensureDirectory(): Promise<void> {},
  async writeFile(): Promise<void> {},
  async remove(): Promise<void> {},
};

const commands: Record<string, CommandResult> = {
  "git --version": { exitCode: 0, stdout: "git version 2.50.1\n", stderr: "" },
  "df -Pk /cache": {
    exitCode: 0,
    stdout:
      "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/disk3s5 9 9 456789012 22% /\n",
    stderr: "",
  },
  "/cache/trivy/trivy --version": { exitCode: 0, stdout: "Version: 0.58.1\n", stderr: "" },
};

const processPort: DoctorProcessPort = {
  async run(command: string, args: readonly string[]): Promise<CommandResult> {
    return (
      commands[[command, ...args].join(" ")] ?? {
        exitCode: 127,
        stdout: "",
        stderr: `command not found: ${command}`,
      }
    );
  },
};

/** trivy installed, gitleaks missing — the case the coverage disclosure exists for. */
const tools: ToolProbe = {
  async listPinned(): Promise<readonly PinnedTool[]> {
    return [
      { name: "trivy", version: "0.58.1" },
      { name: "gitleaks", version: "8.18.4" },
    ];
  },
  async resolve(name: string): Promise<string | null> {
    return name === "trivy" ? "/cache/trivy/trivy" : null;
  },
};

interface Captured {
  readonly deps: DoctorCliDeps;
  readonly out: string[];
  readonly err: string[];
}

function capture(overrides: Partial<DoctorCliDeps> = {}): Captured {
  const out: string[] = [];
  const err: string[] = [];
  const deps: DoctorCliDeps = {
    cwd: TARGET,
    fs: fileSystem,
    proc: processPort,
    stdout: (text) => out.push(text),
    stderr: (text) => err.push(text),
    tools,
    cacheDir: CACHE,
    bunVersion: "1.2.0",
    now: () => new Date("2026-01-01T00:00:00.000Z"),
    probeNetwork: async () => true,
    ...overrides,
  };
  return { deps, out, err };
}

describe("parseDoctorArgs", () => {
  test("defaults to the current directory and <target>/sentinel", () => {
    const parsed = parseDoctorArgs([], "/work/repo");
    expect(parsed).toEqual({
      ok: true,
      value: { target: "/work/repo", outputDir: "/work/repo/sentinel", json: false, help: false },
    });
  });

  test("resolves a relative target and an explicit output directory", () => {
    const parsed = parseDoctorArgs(["../api", "--out", "out/dossier", "--json"], "/work/repo");
    expect(parsed).toEqual({
      ok: true,
      value: {
        target: "/work/api",
        outputDir: "/work/repo/out/dossier",
        json: true,
        help: false,
      },
    });
  });

  test("accepts --out=<dir>", () => {
    const parsed = parseDoctorArgs(["--out=/tmp/x"], "/work/repo");
    expect(parsed.ok && parsed.value.outputDir).toBe("/tmp/x");
  });

  test("rejects an unknown option, a dangling --out and a second target", () => {
    expect(parseDoctorArgs(["--wat"], "/work")).toEqual({
      ok: false,
      error: "unknown option: --wat",
    });
    expect(parseDoctorArgs(["--out"], "/work")).toEqual({
      ok: false,
      error: "--out needs a directory",
    });
    expect(parseDoctorArgs(["a", "b"], "/work")).toEqual({
      ok: false,
      error: "unexpected extra argument: b",
    });
  });
});

describe("doctorCommand", () => {
  test("--json prints a report that validates against the schema", async () => {
    const { deps, out } = capture();
    const code = await doctorCommand(["--json"], deps);

    expect(code).toBe(0);
    expect(out).toHaveLength(1);
    const report = DoctorReportSchema.parse(JSON.parse(out[0] ?? ""));
    expect(report.target).toBe(TARGET);
    expect(report.ready).toBe(true);
    expect(report.coverageLoss).toContainEqual({
      tool: "gitleaks",
      sentence: "gitleaks missing → no secret scanning, including git history.",
      domains: ["appsec"],
    });
  });

  test("the table shows the tier, the coverage loss and a ready verdict", async () => {
    const { deps, out } = capture();
    const code = await doctorCommand([], deps);
    const rendered = out[0] ?? "";

    expect(code).toBe(0);
    expect(rendered).toContain("REQUIRED");
    expect(rendered).toContain("ANALYSIS TOOLS");
    expect(rendered).toContain("[warn]");
    expect(rendered).toContain("COVERAGE LOST");
    expect(rendered).toContain("no secret scanning, including git history.");
    expect(rendered).toContain("fix: Run `sentinel setup`");
    expect(rendered).toContain("Ready to analyse.");
  });

  test("a failed required check exits 2 and says the run is blocked", async () => {
    const { deps, out } = capture({ bunVersion: "1.1.0" });
    const code = await doctorCommand([], deps);

    expect(code).toBe(2);
    expect(out[0] ?? "").toContain("Not ready");
  });

  test("a usage error exits 2 and prints the usage to stderr", async () => {
    const { deps, out, err } = capture();
    const code = await doctorCommand(["--nope"], deps);

    expect(code).toBe(2);
    expect(out).toHaveLength(0);
    expect(err[0] ?? "").toContain("unknown option: --nope");
    expect(err[0] ?? "").toContain("Usage: sentinel doctor");
  });

  test("--help prints the usage and exits 0", async () => {
    const { deps, out } = capture();
    const code = await doctorCommand(["--help"], deps);

    expect(code).toBe(0);
    expect(out[0]).toBe(DOCTOR_USAGE);
  });
});
