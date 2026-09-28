import { describe, expect, test } from "bun:test";
import type { Finding } from "../../contracts/findings.ts";
import type { DetectedFact, StackProfile } from "../../contracts/profile.ts";
import { createFileSystem } from "../../ports/file-system.ts";
import { createStubProcessExecutor } from "../../ports/process-executor.ts";
import type { RunnerContext, RunnerFileSystem } from "../runners/_runner-support.ts";
import { parseYaml } from "./_mini-yaml.ts";
import type { SuppressionNote } from "./ci.ts";
import {
  CONTAINER_RULES_STEP,
  HADOLINT_OVERLAP,
  TRIVY_CONFIG_OVERLAP,
  analyseCompose,
  analyseDockerfile,
  buildsTypeScript,
  classifyCompose,
  classifyDockerfileRole,
  classifyImage,
  imageRepository,
  parseAssignments,
  parseDockerfile,
  roleOfImage,
  roleOfServiceName,
  runContainerRules,
} from "./container.ts";

/** A real repository fixture: one deliberately careless image and one careful one. */
const TARGET_DIR = `${import.meta.dir}/__fixtures__/repo`;
const BAD_DOCKERFILE = "docker/Dockerfile";
const GOOD_DOCKERFILE = "Dockerfile.good";
const COMPOSE = "docker-compose.yml";
/** The developer-local artifacts a whole-repository scan finds beside the shipped ones. */
const EMULATOR_DOCKERFILE = "ops/localstack/Dockerfile";
const WATCHER_DOCKERFILE = "ops/docker/nodejs/Dockerfile";
const DEV_COMPOSE = "ops/docker/dev-compose.yml";
const RUN_DIR = "/tmp/sentinel-run";

const bad = await Bun.file(`${TARGET_DIR}/${BAD_DOCKERFILE}`).text();
const good = await Bun.file(`${TARGET_DIR}/${GOOD_DOCKERFILE}`).text();
const compose = await Bun.file(`${TARGET_DIR}/${COMPOSE}`).text();
const emulator = await Bun.file(`${TARGET_DIR}/${EMULATOR_DOCKERFILE}`).text();
const watcher = await Bun.file(`${TARGET_DIR}/${WATCHER_DOCKERFILE}`).text();
const devCompose = await Bun.file(`${TARGET_DIR}/${DEV_COMPOSE}`).text();

/** Reads through the real port; the rules never write anything. */
function readOnlyFileSystem(): RunnerFileSystem {
  const real = createFileSystem();
  return {
    readFile: (path) => real.readFile(path),
    readFileBytes: (path) => real.readFileBytes(path),
    realpath: (path) => real.realpath(path),
    exists: (path) => real.exists(path),
    mkdirp: async () => undefined,
    writeFile: async () => undefined,
  };
}

function context(overrides: Partial<RunnerContext> = {}): RunnerContext {
  return {
    fs: readOnlyFileSystem(),
    exec: createStubProcessExecutor(() => ({})),
    tools: { resolve: async () => null },
    targetDir: TARGET_DIR,
    runDir: RUN_DIR,
    ...overrides,
  };
}

/** A profile that proves exactly the given facts. */
function profileWith(facts: ReadonlyArray<[DetectedFact["kind"], string, string]>): StackProfile {
  return {
    schemaVersion: "1.0",
    target: TARGET_DIR,
    facts: facts.map(([kind, value, file]) => ({
      kind,
      value,
      confidence: "high",
      evidence: [{ file, line: 1 }],
    })),
    absences: [],
    warnings: [],
    scan: { filesSeen: 3, filesRead: 3, truncated: false },
  };
}

/** The findings for one rule leaf. */
function hits(findings: readonly Finding[], rule: string): Finding[] {
  return findings.filter((finding) => finding.rule === rule);
}

/** The withheld findings for one rule. */
function withheld(notes: readonly SuppressionNote[], rule: string): SuppressionNote[] {
  return notes.filter((note) => note.rule === rule);
}

describe("parseDockerfile", () => {
  test("splits the fixture into instructions with real line numbers", () => {
    const parsed = parseDockerfile(bad);
    expect(parsed.instructions.map((item) => item.keyword)).toEqual([
      "FROM",
      "ARG",
      "ENV",
      "WORKDIR",
      "RUN",
      "COPY",
      "RUN",
      "EXPOSE",
      "CMD",
    ]);
    expect(parsed.instructions[4]?.line).toBe(5);
    expect(parsed.stages).toHaveLength(1);
  });

  test("folds a `\\` continuation into one instruction spanning both lines", () => {
    const parsed = parseDockerfile("RUN apt-get update \\\n  && apt-get install -y curl\n");
    expect(parsed.instructions).toHaveLength(1);
    expect(parsed.instructions[0]?.argument).toBe("apt-get update && apt-get install -y curl");
    expect(parsed.instructions[0]?.line).toBe(1);
    expect(parsed.instructions[0]?.endLine).toBe(2);
  });

  test("skips whole-line comments but keeps a `#` inside an argument", () => {
    const parsed = parseDockerfile("# a comment\nRUN echo 'issue #42'\n");
    expect(parsed.instructions).toHaveLength(1);
    expect(parsed.instructions[0]?.argument).toBe("echo 'issue #42'");
  });

  test("reads the stages and aliases of a multi-stage build", () => {
    const parsed = parseDockerfile(good);
    expect(parsed.stages.map((stage) => stage.alias)).toEqual(["build", "runtime"]);
    expect(parsed.stages[1]?.image).toBe("node:20.11.0-alpine3.19");
  });
});

describe("classifyImage", () => {
  test("separates a digest, an exact version, a floating tag and latest", () => {
    expect(classifyImage("node@sha256:abc").precision).toBe("digest");
    expect(classifyImage("node:20.11.0-alpine3.19").precision).toBe("exact");
    expect(classifyImage("node:20-alpine").precision).toBe("floating");
    expect(classifyImage("node:latest").precision).toBe("latest");
    expect(classifyImage("node").precision).toBe("none");
  });

  test("does not mistake a registry port for a tag", () => {
    expect(classifyImage("registry.internal:5000/app").precision).toBe("none");
    expect(classifyImage("registry.internal:5000/app:1.2.3").precision).toBe("exact");
  });
});

describe("the image → role table", () => {
  test("reads the repository without the tag or the digest", () => {
    expect(imageRepository("opensearchproject/opensearch-dashboards:3.1.0")).toBe(
      "opensearchproject/opensearch-dashboards",
    );
    expect(imageRepository("postgres:14.17")).toBe("postgres");
    expect(imageRepository("registry.internal:5000/app:1.2.3")).toBe("registry.internal:5000/app");
  });

  test("separates the dashboard from the datastore it sits beside", () => {
    // The substring match this replaces reported the Kibana fork as a published
    // database, with an impact about "a client speaking the wire protocol".
    expect(roleOfImage("opensearchproject/opensearch-dashboards:3.1.0").role).toBe("web-ui");
    expect(roleOfImage("opensearchproject/opensearch:3.1.0").role).toBe("datastore");
    expect(roleOfImage("postgres:14.17").role).toBe("datastore");
    expect(roleOfImage("redis:latest").role).toBe("datastore");
    expect(roleOfImage("localstack/localstack").role).toBe("emulator");
    expect(roleOfImage("myorg/api:latest").role).toBe("unknown");
  });

  test("uses the same table for a service that builds its own image", () => {
    expect(roleOfServiceName("opensearch-dashboard").role).toBe("web-ui");
    expect(roleOfServiceName("localstack").role).toBe("emulator");
    expect(roleOfServiceName("db").role).toBe("datastore");
    expect(roleOfServiceName("nodejs").role).toBe("unknown");
  });
});

describe("classifyDockerfileRole", () => {
  test("a LocalStack image is tooling, and its base image needs uid 0", () => {
    const verdict = classifyDockerfileRole(parseDockerfile(emulator));
    expect(verdict.role).toBe("tooling");
    expect(verdict.requiresRoot).toBe(true);
    expect(verdict.signals[0]).toContain("FROM localstack/localstack");
  });

  test("an image that maps the host's uid is tooling too", () => {
    const verdict = classifyDockerfileRole(parseDockerfile(watcher));
    expect(verdict.role).toBe("tooling");
    expect(verdict.requiresRoot).toBe(false);
    expect(verdict.signals.join(" ")).toContain("DOCKER_USER_ID");
  });

  test("anything else is graded as if it ships", () => {
    expect(classifyDockerfileRole(parseDockerfile(good)).role).toBe("shipped");
    expect(classifyDockerfileRole(parseDockerfile(bad)).role).toBe("shipped");
  });
});

describe("parseAssignments", () => {
  test("reads the `NAME=value` spelling, including several per instruction", () => {
    expect(parseAssignments('A=1 B="two words"')).toEqual([
      { name: "A", value: "1" },
      { name: "B", value: "two words" },
    ]);
  });

  test("reads the legacy `ENV NAME the value` spelling", () => {
    expect(parseAssignments("MY_TOKEN abc def")).toEqual([{ name: "MY_TOKEN", value: "abc def" }]);
  });

  test("reads an ARG with no default as having no value", () => {
    expect(parseAssignments("NPM_TOKEN")).toEqual([{ name: "NPM_TOKEN", value: null }]);
  });
});

describe("analyseDockerfile on the careless fixture", () => {
  const { findings } = analyseDockerfile(BAD_DOCKERFILE, bad, {
    hasDockerignore: false,
    buildsTypeScript: true,
  });

  test("flags the latest base tag on the FROM line", () => {
    const finding = hits(findings, "delivery.dockerfile.floating-base-tag")[0];
    expect(finding?.severity).toBe("high");
    expect(finding?.location.line).toBe(1);
  });

  test("flags running as root, anchored on the final stage's FROM", () => {
    const finding = hits(findings, "delivery.dockerfile.runs-as-root")[0];
    expect(finding?.severity).toBe("high");
    expect(finding?.location.line).toBe(1);
    expect(finding?.cwe).toContain("CWE-250");
  });

  test("separates a declared build ARG from a literal ENV credential", () => {
    const secrets = hits(findings, "delivery.dockerfile.secret-in-env");
    expect(secrets).toHaveLength(2);
    const arg = secrets.find((finding) => finding.location.line === 2);
    const env = secrets.find((finding) => finding.location.line === 3);
    expect(arg?.severity).toBe("medium");
    expect(env?.severity).toBe("high");
    expect(env?.title).toContain("API_SECRET");
  });

  test("flags `COPY . .` when the build context has no .dockerignore", () => {
    expect(
      hits(findings, "delivery.dockerfile.copy-all-without-dockerignore")[0]?.location.line,
    ).toBe(6);
  });

  test("flags the single-stage build and the missing HEALTHCHECK", () => {
    expect(hits(findings, "delivery.dockerfile.no-multi-stage-build")).toHaveLength(1);
    expect(hits(findings, "delivery.dockerfile.no-healthcheck")).toHaveLength(1);
  });

  test("flags both leftover caches and the unpinned apt install", () => {
    const caches = hits(findings, "delivery.dockerfile.package-manager-cache-left");
    expect(caches.map((finding) => finding.location.line)).toEqual([5, 7]);
    expect(hits(findings, "delivery.dockerfile.apt-install-unpinned")[0]?.location.line).toBe(5);
  });

  test("gives every finding a distinct id", () => {
    expect(new Set(findings.map((finding) => finding.id)).size).toBe(findings.length);
  });
});

describe("analyseDockerfile on a developer-tooling image", () => {
  const options = { hasDockerignore: true, buildsTypeScript: true } as const;
  const emulatorAnalysis = analyseDockerfile(EMULATOR_DOCKERFILE, emulator, options);
  const watcherAnalysis = analyseDockerfile(WATCHER_DOCKERFILE, watcher, options);

  test("runs-as-root is still reported, at the severity a workstation earns", () => {
    const finding = hits(emulatorAnalysis.findings, "delivery.dockerfile.runs-as-root")[0];
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("low");
    expect(finding?.description).toContain("developer-tooling image");
    expect(finding?.description).toContain("initialises as uid 0 by design");
    // The recommendation changes with the role: appending USER breaks the emulator.
    expect(finding?.recommendation).toContain("userns-remap");
  });

  test("an untagged emulator base image cannot outrank a tagged production one", () => {
    const tooling = hits(emulatorAnalysis.findings, "delivery.dockerfile.floating-base-tag")[0];
    // `FROM localstack/localstack` has no tag at all, which used to make it `high`.
    expect(tooling?.severity).toBe("low");
    const shipped = analyseDockerfile("apps/api/ops/Dockerfile", "FROM node:24-bookworm-slim\n", {
      hasDockerignore: true,
      buildsTypeScript: false,
    });
    expect(hits(shipped.findings, "delivery.dockerfile.floating-base-tag")[0]?.severity).toBe(
      "low",
    );
  });

  test("the single-stage rule is withheld, with the reason, rather than fired", () => {
    expect(hits(watcherAnalysis.findings, "delivery.dockerfile.no-multi-stage-build")).toEqual([]);
    const notes = withheld(watcherAnalysis.suppressed, "delivery.dockerfile.no-multi-stage-build");
    expect(notes).toHaveLength(1);
    expect(notes[0]?.reason).toContain("no production runtime");
  });

  test("an image that ships keeps `runs-as-root` at high", () => {
    const shipped = analyseDockerfile(
      "apps/api/ops/Dockerfile",
      'FROM node:24-bookworm-slim\nCOPY build ./build\nCMD ["node", "./build/main.js"]\n',
      { hasDockerignore: true, buildsTypeScript: false },
    );
    expect(hits(shipped.findings, "delivery.dockerfile.runs-as-root")[0]?.severity).toBe("high");
  });
});

describe("analyseDockerfile on the careful fixture", () => {
  test("reports nothing on a pinned, multi-stage, non-root image", () => {
    expect(
      analyseDockerfile(GOOD_DOCKERFILE, good, { hasDockerignore: true, buildsTypeScript: true }),
    ).toEqual({ findings: [], suppressed: [] });
  });

  test("an explicit `USER root` is as much a finding as no USER at all", () => {
    const { findings } = analyseDockerfile(
      "D",
      'FROM node:20.11.0\nUSER node\nUSER root\nCMD ["node"]\n',
      { hasDockerignore: true, buildsTypeScript: false },
    );
    const finding = hits(findings, "delivery.dockerfile.runs-as-root")[0];
    expect(finding?.location.line).toBe(3);
  });

  test("only the final stage decides whether the image runs as root", () => {
    const { findings } = analyseDockerfile(
      "D",
      'FROM node:20.11.0 AS build\nRUN npm run build --no-cache\n\nFROM node:20.11.0\nUSER 10001\nHEALTHCHECK CMD ["node"]\nCMD ["node"]\n',
      { hasDockerignore: true, buildsTypeScript: false },
    );
    expect(hits(findings, "delivery.dockerfile.runs-as-root")).toEqual([]);
  });

  test("a stage that copies from an earlier stage is not an unpinned base image", () => {
    const { findings } = analyseDockerfile(
      "D",
      'FROM node:20.11.0 AS build\nFROM build\nUSER 1\nCMD ["node"]\nHEALTHCHECK CMD ["node"]\n',
      { hasDockerignore: true, buildsTypeScript: false },
    );
    expect(hits(findings, "delivery.dockerfile.floating-base-tag")).toEqual([]);
  });

  test("a single-stage build in a repository with no TypeScript is left alone", () => {
    const { findings } = analyseDockerfile("D", 'FROM node:20.11.0\nUSER 1\nCMD ["node"]\n', {
      hasDockerignore: true,
      buildsTypeScript: false,
    });
    expect(hits(findings, "delivery.dockerfile.no-multi-stage-build")).toEqual([]);
  });

  test("an ENV that persists a build ARG into the shipping stage outranks a bare ARG", () => {
    // `ARG NODE_AUTH_TOKEN` / `ENV NODE_AUTH_TOKEN=$NODE_AUTH_TOKEN` at the top of
    // a *build* stage is not shipped, and stays a medium.
    const buildStage = analyseDockerfile(
      "D",
      'FROM node:20.11.0 AS build\nARG NODE_AUTH_TOKEN\nENV NODE_AUTH_TOKEN=$NODE_AUTH_TOKEN\nRUN npm ci --no-cache\n\nFROM node:20.11.0\nUSER 1\nHEALTHCHECK CMD ["node"]\nCMD ["node"]\n',
      { hasDockerignore: true, buildsTypeScript: false },
    );
    const inBuild = hits(buildStage.findings, "delivery.dockerfile.secret-in-env").map(
      (finding) => finding.severity,
    );
    expect(inBuild).toEqual(["medium", "medium"]);

    const finalStage = analyseDockerfile(
      "D",
      'FROM node:20.11.0\nARG NODE_AUTH_TOKEN\nENV NODE_AUTH_TOKEN=$NODE_AUTH_TOKEN\nUSER 1\nHEALTHCHECK CMD ["node"]\nCMD ["node"]\n',
      { hasDockerignore: true, buildsTypeScript: false },
    );
    const persisted = hits(finalStage.findings, "delivery.dockerfile.secret-in-env").find(
      (finding) => finding.location.line === 3,
    );
    expect(persisted?.severity).toBe("high");
    expect(persisted?.description).toContain("docker inspect");
  });

  test("an empty file produces nothing rather than throwing", () => {
    expect(analyseDockerfile("D", "", { hasDockerignore: true, buildsTypeScript: true })).toEqual({
      findings: [],
      suppressed: [],
    });
  });
});

describe("analyseCompose", () => {
  const { findings } = analyseCompose(COMPOSE, compose);

  test("flags only the database port that binds every interface", () => {
    const ports = hits(findings, "delivery.compose.database-port-published");
    expect(ports).toHaveLength(1);
    expect(ports[0]?.severity).toBe("high");
    expect(ports[0]?.location.line).toBe(5);
    // redis is a database too, but it is bound to loopback, so it is not a finding.
    expect(ports[0]?.title).toContain('"db"');
  });

  test("flags the privileged service", () => {
    expect(hits(findings, "delivery.compose.privileged")[0]?.location.line).toBe(13);
  });

  test("grades the Docker socket above an absolute host path above a project path", () => {
    const mounts = hits(findings, "delivery.compose.host-bind-mount");
    const bySeverity = Object.fromEntries(
      mounts.map((finding) => [finding.location.line, finding.severity]),
    );
    // Nothing in this file says it is developer-local, and the service that
    // mounts the socket never says it needs one.
    expect(bySeverity[21]).toBe("critical");
    expect(bySeverity[10]).toBe("medium");
    expect(bySeverity[22]).toBe("low");
    // A named volume is not a host mount.
    expect(bySeverity[29]).toBeUndefined();
  });

  test("flags default credentials in both environment spellings", () => {
    const credentials = hits(findings, "delivery.compose.default-credentials");
    expect(credentials.map((finding) => finding.location.line)).toEqual([7, 19]);
    for (const finding of credentials) expect(finding.severity).toBe("high");
  });

  test("leaves a `${VAR}` reference alone", () => {
    const credentials = hits(findings, "delivery.compose.default-credentials");
    expect(credentials.some((finding) => finding.title.includes("DATABASE_URL"))).toBe(false);
  });

  test("flags a `${VAR:-fallback}` default, which is a real credential when unset", () => {
    const local = analyseCompose(
      "c.yml",
      "services:\n  db:\n    image: postgres:15\n    restart: always\n    environment:\n      POSTGRES_PASSWORD: ${DB_PASSWORD:-postgres}\n",
    );
    const finding = hits(local.findings, "delivery.compose.default-credentials")[0];
    expect(finding?.severity).toBe("high");
    expect(finding?.description).toContain("falls back to");
  });

  test("an empty or whitespace default is an optional variable, and the decision is counted", () => {
    // Without this branch the finding lands at `high` with a recommendation to
    // rotate the exposed credential, and the credential is a single space.
    for (const spelling of ["${TOKEN- }", "${TOKEN-}", "${TOKEN:-}"]) {
      const local = analyseCompose(
        "c.yml",
        `services:\n  app:\n    image: app:1.0.0\n    restart: always\n    environment:\n      - API_TOKEN=${spelling}\n`,
      );
      expect(hits(local.findings, "delivery.compose.default-credentials")).toEqual([]);
      const notes = withheld(local.suppressed, "delivery.compose.default-credentials");
      expect(notes).toHaveLength(1);
      expect(notes[0]?.reason).toContain("optional variable");
    }
  });

  test("flags only the service with no restart policy", () => {
    const restarts = hits(findings, "delivery.compose.missing-restart");
    expect(restarts.map((finding) => finding.title)).toEqual([
      'Service "db" declares no `restart:` policy',
    ]);
  });

  test("accepts a `deploy.restart_policy` as a restart policy", () => {
    const local = analyseCompose(
      "c.yml",
      "services:\n  api:\n    image: app:1.0.0\n    deploy:\n      restart_policy:\n        condition: any\n",
    );
    expect(hits(local.findings, "delivery.compose.missing-restart")).toEqual([]);
  });

  test("gives every finding a distinct id", () => {
    expect(new Set(findings.map((finding) => finding.id)).size).toBe(findings.length);
  });
});

describe("classifyCompose", () => {
  test("names the signals that make a compose file developer-local", () => {
    const verdict = classifyCompose(devCompose, parseYaml(devCompose).root);
    expect(verdict.scope).toBe("development");
    const signals = verdict.signals.join(" | ");
    expect(signals).toContain("local service emulator");
    expect(signals).toContain("bind-mounts the repository root");
    expect(signals).toContain("uid/gid of whoever started compose");
    expect(signals).toContain("NODE_ENV: dev");
  });

  test("an override header is a signal on its own", () => {
    const override = [
      "# Override file for the local emulator stack",
      "# Use with: docker-compose -f docker-compose.yml -f docker-compose-emulator.yml up",
      "",
      "services:",
      "  localstack:",
      "    volumes:",
      "      - '/var/run/docker.sock:/var/run/docker.sock'",
      "",
    ].join("\n");
    const verdict = classifyCompose(override, parseYaml(override).root);
    expect(verdict.scope).toBe("development");
    expect(verdict.signals[0]).toContain("override");
  });

  test("a file with no developer-local signal is graded as if it ships", () => {
    const verdict = classifyCompose(compose, parseYaml(compose).root);
    expect(verdict.scope).toBe("unknown");
    expect(verdict.signals).toEqual([]);
  });
});

describe("analyseCompose on a developer-local compose file", () => {
  const analysis = analyseCompose(DEV_COMPOSE, devCompose);

  test("the socket mount is still the strongest host mount, and still reported", () => {
    const mounts = hits(analysis.findings, "delivery.compose.host-bind-mount");
    const socket = mounts.find((finding) => finding.title.includes("Docker socket"));
    expect(socket).toBeDefined();
    expect(socket?.severity).toBe("low");
    expect(socket?.description).toContain("declares that it needs the socket");
    expect(socket?.description).toContain("developer-local compose file");
    // The fix is a socket proxy, not "delete the mount", which would break it.
    expect(socket?.recommendation).toContain("socket proxy");
    expect(socket?.acceptanceCriteria.join(" ")).toContain("No deploy path references");
  });

  test("an unexplained socket mount in the same file would still be critical", () => {
    const shipped = analyseCompose(
      "ops/docker/compose.yml",
      "services:\n  api:\n    image: myorg/api:1.0.0\n    restart: always\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
    );
    expect(hits(shipped.findings, "delivery.compose.host-bind-mount")[0]?.severity).toBe(
      "critical",
    );
  });

  test("a published datastore port in a dev compose is a medium, not a high", () => {
    const port = hits(analysis.findings, "delivery.compose.database-port-published")[0];
    expect(port?.severity).toBe("medium");
    expect(port?.title).toContain('"db"');
    expect(port?.description).toContain("developer-local compose file");
  });

  test("a real weak credential keeps its severity wherever the file runs", () => {
    // The cap is about blast radius, not about the value: `postgres/postgres` is
    // the first pair an attacker tries and has to be changed in any case.
    const credential = hits(analysis.findings, "delivery.compose.default-credentials")[0];
    expect(credential?.severity).toBe("high");
    expect(credential?.title).toContain("POSTGRES_PASSWORD=postgres");
  });

  test("the dashboard beside the datastore is not reported as a published database", () => {
    const ports = hits(analysis.findings, "delivery.compose.database-port-published");
    expect(ports.some((finding) => finding.title.includes("grafana"))).toBe(false);
    const notes = withheld(analysis.suppressed, "delivery.compose.database-port-published");
    expect(notes).toHaveLength(1);
    expect(notes[0]?.reason).toContain("browser UI served over HTTP");
  });
});

describe("buildsTypeScript", () => {
  test("is true when the profile proves the language or a tsconfig", () => {
    expect(buildsTypeScript(profileWith([["language", "typescript", "src/a.ts"]]))).toBe(true);
    expect(buildsTypeScript(profileWith([["tsconfig", "strict", "tsconfig.json"]]))).toBe(true);
    expect(buildsTypeScript(profileWith([["language", "javascript", "src/a.js"]]))).toBe(false);
  });
});

describe("HADOLINT_OVERLAP", () => {
  test("names the hadolint codes each Sentinel rule subsumes, so nothing is reported twice", () => {
    expect(HADOLINT_OVERLAP["delivery.dockerfile.runs-as-root"]).toEqual(["DL3002"]);
    expect(HADOLINT_OVERLAP["delivery.dockerfile.secret-in-env"]).toEqual(["DL3064"]);
    for (const rule of Object.keys(HADOLINT_OVERLAP)) {
      expect(rule.startsWith("delivery.dockerfile.")).toBe(true);
    }
  });
});

describe("TRIVY_CONFIG_OVERLAP", () => {
  test("names the trivy check ids each Sentinel rule subsumes", () => {
    // Each id here is one `trivy config` reports beside the Sentinel rule that
    // makes the same claim, at a different severity.
    expect(TRIVY_CONFIG_OVERLAP["delivery.dockerfile.runs-as-root"]).toEqual(["DS-0002"]);
    expect(TRIVY_CONFIG_OVERLAP["delivery.dockerfile.apt-install-unpinned"]).toEqual(["DS-0029"]);
    for (const [rule, ids] of Object.entries(TRIVY_CONFIG_OVERLAP)) {
      expect(rule.startsWith("delivery.dockerfile.")).toBe(true);
      for (const id of ids) expect(id).toMatch(/^DS-\d{4}$/);
    }
  });
});

describe("runContainerRules", () => {
  test("verifies every citation and puts a disk-read snippet on it", async () => {
    const result = await runContainerRules(context(), {
      dockerfiles: [BAD_DOCKERFILE, GOOD_DOCKERFILE],
      composeFiles: [COMPOSE],
      buildsTypeScript: true,
    });
    expect(result.status).toBe("ok");
    expect(result.step).toBe(CONTAINER_RULES_STEP);
    expect(result.findings).toHaveLength(18);
    for (const finding of result.findings) {
      expect(finding.location.snippet).toBeDefined();
    }
    const root = result.findings.find((f) => f.rule === "delivery.dockerfile.runs-as-root");
    expect(root?.location.snippet).toContain("FROM node:latest");
    const socket = result.findings.find(
      (f) => f.rule === "delivery.compose.host-bind-mount" && f.severity === "critical",
    );
    expect(socket?.location.snippet).toContain("docker.sock");
  });

  test("counts the withheld findings in the step's reason", async () => {
    const result = await runContainerRules(context(), {
      dockerfiles: [EMULATOR_DOCKERFILE],
      composeFiles: [DEV_COMPOSE],
      buildsTypeScript: true,
    });
    expect(result.status).toBe("ok");
    expect(result.reason).toContain("withheld by a rule's own gate");
    expect(result.reason).toContain("delivery.compose.database-port-published");
    expect(result.reason).toContain("delivery.dockerfile.no-multi-stage-build");
  });

  test("takes both file lists and the TypeScript fact from the profile", async () => {
    const ctx = context({
      profile: profileWith([
        ["container", "dockerfile", BAD_DOCKERFILE],
        ["container", "docker-compose", COMPOSE],
        ["language", "typescript", "src/index.ts"],
      ]),
    });
    const result = await runContainerRules(ctx);
    expect(result.status).toBe("ok");
    expect(result.findings.some((f) => f.rule === "delivery.dockerfile.no-multi-stage-build")).toBe(
      true,
    );
  });

  test("skips when the repository has neither a Dockerfile nor a compose file", async () => {
    const result = await runContainerRules(context(), { dockerfiles: [], composeFiles: [] });
    expect(result.status).toBe("skipped");
    expect(result.reason).toContain("no Dockerfile");
  });

  test("degrades, and names the file, when one cannot be read", async () => {
    const result = await runContainerRules(context(), {
      dockerfiles: [BAD_DOCKERFILE, "missing/Dockerfile"],
      composeFiles: [],
      buildsTypeScript: true,
    });
    expect(result.status).toBe("degraded");
    expect(result.reason).toContain("missing/Dockerfile");
    expect(result.findings.length).toBeGreaterThan(0);
  });
});
