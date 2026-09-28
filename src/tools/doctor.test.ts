import { describe, expect, test } from "bun:test";
import type { DoctorCheck, DoctorReport } from "../contracts/doctor.ts";
import {
  type CommandResult,
  type DoctorFileSystemPort,
  type DoctorProcessPort,
  type PinnedTool,
  TOOL_CATALOGUE,
  type ToolProbe,
  compareVersions,
  coverageLossFor,
  extractVersion,
  meetsMinimum,
  parseDfAvailableBytes,
  runDoctor,
} from "./doctor.ts";

/** In-memory filesystem: directories carry their entries, writes can be blocked. */
class MemoryFileSystem implements DoctorFileSystemPort {
  readonly directories = new Map<string, readonly string[]>();
  readonly files = new Map<string, string>();
  readonly unwritable = new Set<string>();

  constructor(directories: Record<string, readonly string[]> = {}) {
    for (const [path, entries] of Object.entries(directories)) {
      this.directories.set(path, entries);
    }
  }

  async exists(path: string): Promise<boolean> {
    return this.directories.has(path) || this.files.has(path);
  }

  async isDirectory(path: string): Promise<boolean> {
    return this.directories.has(path);
  }

  async listDirectory(path: string): Promise<readonly string[]> {
    const entries = this.directories.get(path);
    if (entries === undefined) {
      throw new Error(`ENOENT: no such directory, ${path}`);
    }
    return entries;
  }

  async ensureDirectory(path: string): Promise<void> {
    if (this.unwritable.has(path)) {
      throw new Error("EACCES: permission denied");
    }
    if (!this.directories.has(path)) {
      this.directories.set(path, []);
    }
  }

  async writeFile(path: string, contents: string): Promise<void> {
    for (const blocked of this.unwritable) {
      if (path.startsWith(`${blocked}/`)) {
        throw new Error("EACCES: permission denied");
      }
    }
    this.files.set(path, contents);
  }

  async remove(path: string): Promise<void> {
    this.files.delete(path);
  }
}

/** Scripted process port: unknown commands behave like "not found". */
class ScriptedProcess implements DoctorProcessPort {
  readonly calls: string[] = [];

  constructor(private readonly responses: Record<string, Partial<CommandResult>>) {}

  async run(command: string, args: readonly string[]): Promise<CommandResult> {
    const key = [command, ...args].join(" ");
    this.calls.push(key);
    const scripted = this.responses[key];
    if (scripted === undefined) {
      return { exitCode: 127, stdout: "", stderr: `command not found: ${command}` };
    }
    return {
      exitCode: scripted.exitCode ?? 0,
      stdout: scripted.stdout ?? "",
      stderr: scripted.stderr ?? "",
    };
  }
}

/** Tool probe backed by a fixed pin list and a fixed set of installed paths. */
function toolProbe(pinned: readonly PinnedTool[], installed: Record<string, string>): ToolProbe {
  return {
    async listPinned(): Promise<readonly PinnedTool[]> {
      return pinned;
    },
    async resolve(name: string): Promise<string | null> {
      return installed[name] ?? null;
    },
  };
}

const TARGET = "/repo";
const OUTPUT = "/repo/sentinel";
const CACHE = "/cache";

function memoryFs(): MemoryFileSystem {
  return new MemoryFileSystem({
    [TARGET]: ["package.json", "src", ".git"],
    [`${TARGET}/.git`]: ["HEAD"],
    [CACHE]: [],
  });
}

const HEALTHY_COMMANDS: Record<string, Partial<CommandResult>> = {
  "git --version": { stdout: "git version 2.50.1 (Apple Git-155)\n" },
  "df -Pk /cache": {
    stdout:
      "Filesystem 1024-blocks      Used Available Capacity Mounted on\n/dev/disk3s5  971350180 123456789 456789012    22%    /\n",
  },
  "/cache/trivy/trivy --version": { stdout: "Version: 0.58.1\n" },
  "/cache/gitleaks/gitleaks version": { stdout: "8.18.4\n" },
};

function checkById(report: DoctorReport, id: string): DoctorCheck {
  const found = report.checks.find((item) => item.id === id);
  if (found === undefined) {
    throw new Error(`no check with id ${id}: ${report.checks.map((item) => item.id).join(", ")}`);
  }
  return found;
}

interface ScenarioOverrides {
  readonly fs?: MemoryFileSystem;
  readonly commands?: Record<string, Partial<CommandResult>>;
  readonly pinned?: readonly PinnedTool[];
  readonly installed?: Record<string, string>;
  readonly bunVersion?: string;
  readonly probeNetwork?: () => Promise<boolean>;
}

async function scenario(overrides: ScenarioOverrides = {}): Promise<DoctorReport> {
  return await runDoctor({
    target: TARGET,
    outputDir: OUTPUT,
    cacheDir: CACHE,
    fs: overrides.fs ?? memoryFs(),
    proc: new ScriptedProcess(overrides.commands ?? HEALTHY_COMMANDS),
    tools: toolProbe(
      overrides.pinned ?? [
        { name: "trivy", version: "0.58.1" },
        { name: "gitleaks", version: "8.18.4" },
      ],
      overrides.installed ?? {
        trivy: "/cache/trivy/trivy",
        gitleaks: "/cache/gitleaks/gitleaks",
      },
    ),
    bunVersion: overrides.bunVersion ?? "1.2.0",
    platform: "darwin",
    arch: "arm64",
    now: () => new Date("2026-01-01T00:00:00.000Z"),
    probeNetwork: overrides.probeNetwork ?? (async () => true),
  });
}

describe("version helpers", () => {
  test("extracts a version from arbitrary tool output", () => {
    expect(extractVersion("git version 2.50.1 (Apple Git-155)")).toBe("2.50.1");
    expect(extractVersion("Haskell Dockerfile Linter 2.12.0")).toBe("2.12.0");
    expect(extractVersion("v0.58.1")).toBe("0.58.1");
    expect(extractVersion("no version here")).toBeNull();
  });

  test("compares dotted versions, treating missing segments as zero", () => {
    expect(compareVersions("1.3.0", "1.2.0")).toBe(1);
    expect(compareVersions("1.2", "1.2.0")).toBe(0);
    expect(compareVersions("2.29.9", "2.30.0")).toBe(-1);
    expect(meetsMinimum("1.2.0", "1.2.0")).toBe(true);
    expect(meetsMinimum("1.1.45", "1.2.0")).toBe(false);
  });

  test("reads available bytes out of df -Pk output", () => {
    expect(parseDfAvailableBytes(HEALTHY_COMMANDS["df -Pk /cache"]?.stdout ?? "")).toBe(
      456789012 * 1024,
    );
    expect(parseDfAvailableBytes("")).toBeNull();
  });
});

describe("coverage loss", () => {
  test("every catalogued tool names what is lost in one sentence", () => {
    for (const [name, coverage] of Object.entries(TOOL_CATALOGUE)) {
      expect(coverage.sentence).toContain(name);
      expect(coverage.sentence.trimEnd().endsWith(".")).toBe(true);
    }
  });

  test("an unknown pinned tool still gets a disclosure sentence", () => {
    const loss = coverageLossFor("semgrep-pro");
    expect(loss.tool).toBe("semgrep-pro");
    expect(loss.sentence).toContain("semgrep-pro");
    expect(loss.domains).toEqual([]);
  });
});

describe("runDoctor", () => {
  test("a healthy environment is ready and loses no coverage", async () => {
    const report = await scenario();
    expect(report.ready).toBe(true);
    expect(report.coverageLoss).toEqual([]);
    expect(report.summary.fail).toBe(0);
    expect(checkById(report, "tools.trivy").status).toBe("ok");
    expect(checkById(report, "tools.trivy").version).toBe("0.58.1");
    expect(checkById(report, "required.target-readable").status).toBe("ok");
  });

  test("a missing tool warns with the coverage-loss sentence and a remediation hint", async () => {
    const report = await scenario({ installed: { trivy: "/cache/trivy/trivy" } });
    const gitleaks = checkById(report, "tools.gitleaks");

    expect(gitleaks.status).toBe("warn");
    expect(gitleaks.detail).toBe("gitleaks missing → no secret scanning, including git history.");
    expect(gitleaks.remediation).toContain("sentinel setup");
    expect(report.coverageLoss).toContainEqual({
      tool: "gitleaks",
      sentence: "gitleaks missing → no secret scanning, including git history.",
      domains: ["appsec"],
    });
    // Missing tools reduce coverage; they never block the run.
    expect(report.ready).toBe(true);
  });

  test("a drifted tool version warns but costs no coverage", async () => {
    const report = await scenario({
      commands: { ...HEALTHY_COMMANDS, "/cache/gitleaks/gitleaks version": { stdout: "8.16.0\n" } },
    });
    const gitleaks = checkById(report, "tools.gitleaks");

    expect(gitleaks.status).toBe("warn");
    expect(gitleaks.detail).toContain("pinned 8.18.4");
    expect(report.coverageLoss).toEqual([]);
  });

  test("an installed tool that cannot report a version warns without coverage loss", async () => {
    const report = await scenario({
      commands: {
        ...HEALTHY_COMMANDS,
        "/cache/gitleaks/gitleaks version": { exitCode: 1, stderr: "killed" },
      },
    });

    expect(checkById(report, "tools.gitleaks").detail).toContain("did not report a version");
    expect(report.coverageLoss).toEqual([]);
  });

  test("an old runtime or missing git fails the required tier", async () => {
    const report = await scenario({ bunVersion: "1.1.45", commands: {} });

    expect(checkById(report, "required.bun").status).toBe("fail");
    expect(checkById(report, "required.bun").remediation).toBeDefined();
    expect(checkById(report, "required.git").status).toBe("fail");
    expect(report.ready).toBe(false);
  });

  test("an unreadable target and an unwritable output dir fail the required tier", async () => {
    const fs = new MemoryFileSystem({ [CACHE]: [] });
    fs.unwritable.add(OUTPUT);
    const report = await scenario({ fs });

    expect(checkById(report, "required.target-readable").status).toBe("fail");
    expect(checkById(report, "required.output-writable").status).toBe("fail");
    expect(checkById(report, "required.output-writable").remediation).toContain("--out");
    expect(report.ready).toBe(false);
  });

  test("a target without git history warns and discloses the lost history scan", async () => {
    const report = await scenario({
      fs: new MemoryFileSystem({ [TARGET]: ["package.json"], [CACHE]: [] }),
    });
    const history = checkById(report, "optional.git-history");

    expect(history.status).toBe("warn");
    expect(report.coverageLoss.map((loss) => loss.tool)).toContain("git-history");
  });

  test("the network is not probed when every pinned tool is installed", async () => {
    let probed = false;
    const report = await scenario({
      probeNetwork: async () => {
        probed = true;
        return true;
      },
    });

    expect(probed).toBe(false);
    expect(checkById(report, "optional.network").detail).toContain("not needed");
  });

  test("an unreachable network warns only while a tool is still missing", async () => {
    const report = await scenario({
      installed: {},
      probeNetwork: async () => false,
    });

    expect(checkById(report, "optional.network").status).toBe("warn");
    expect(report.coverageLoss).toHaveLength(2);
  });

  test("an unreadable tools.lock falls back to the built-in catalogue", async () => {
    const report = await runDoctor({
      target: TARGET,
      outputDir: OUTPUT,
      cacheDir: CACHE,
      fs: memoryFs(),
      proc: new ScriptedProcess(HEALTHY_COMMANDS),
      tools: {
        async listPinned(): Promise<readonly PinnedTool[]> {
          throw new Error("tools.lock.json not found");
        },
        async resolve(): Promise<string | null> {
          return null;
        },
      },
      bunVersion: "1.2.0",
      now: () => new Date("2026-01-01T00:00:00.000Z"),
      probeNetwork: async () => true,
    });

    expect(checkById(report, "tools.lock").status).toBe("warn");
    expect(report.coverageLoss).toHaveLength(Object.keys(TOOL_CATALOGUE).length);
    expect(report.ready).toBe(true);
  });
});
