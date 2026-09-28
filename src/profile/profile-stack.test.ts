import { beforeAll, describe, expect, test } from "bun:test";
import { SCHEMA_VERSION } from "../contracts/findings.ts";
import { type StackProfile, StackProfileSchema } from "../contracts/profile.ts";
import {
  type FixtureName,
  createFixtureFileSystem,
  fixturePath,
} from "./__fixtures__/fixture-file-system.ts";
import {
  absenceOf,
  authHelperFiles,
  authProviders,
  backendFrameworks,
  bestFact,
  dataLayers,
  databaseEngines,
  envVarNames,
  evidenceFiles,
  findFact,
  hasAsyncWorkloads,
  hasFact,
  hasFrontend,
  isAbsent,
  isMonorepo,
  isPureApi,
  moduleSystem,
  nodeVersion,
  packageManager,
  routeDirs,
  validatesConfig,
  valuesOf,
  workspacePackages,
} from "./accessors.ts";
import type { ProfileDirEntry, ProfileFileSystem } from "./file-system-port.ts";
import { profileStack, withAnalysisScope } from "./profile-stack.ts";
import { RepoSnapshot } from "./repo-snapshot.ts";

/** A one-directory filesystem, for repositories a fixture tree cannot express. */
function flatFileSystem(tree: Record<string, string>): ProfileFileSystem {
  return {
    async readFile(path: string): Promise<string> {
      const content = tree[path];
      if (content === undefined) throw new Error(`ENOENT ${path}`);
      return content;
    },
    async exists(path: string): Promise<boolean> {
      return tree[path] !== undefined;
    },
    async readDir(): Promise<readonly ProfileDirEntry[]> {
      return Object.keys(tree).map((name) => ({ name, isFile: true, isDirectory: false }));
    },
  };
}

const fileSystem = createFixtureFileSystem();
const profiles = new Map<FixtureName, StackProfile>();

beforeAll(async () => {
  for (const name of ["next-prisma", "express-knex", "pure-api", "monorepo"] as const) {
    profiles.set(name, await profileStack(fileSystem, fixturePath(name)));
  }
});

function profileOf(name: FixtureName): StackProfile {
  const profile = profiles.get(name);
  if (profile === undefined) throw new Error(`profile for ${name} was not built`);
  return profile;
}

describe("the profile artifact", () => {
  test("validates against its own schema and carries the shared schema version", () => {
    for (const name of profiles.keys()) {
      const profile = profileOf(name);
      expect(StackProfileSchema.parse(profile)).toEqual(profile);
      expect(profile.schemaVersion).toBe(SCHEMA_VERSION);
      expect(profile.target).toContain(name);
    }
  });

  test("every fact carries at least one citation that resolves to a file in the repo", async () => {
    for (const name of profiles.keys()) {
      const profile = profileOf(name);
      for (const detected of profile.facts) {
        expect(detected.evidence.length).toBeGreaterThan(0);
        for (const codeRef of detected.evidence) {
          expect(codeRef.line).toBeGreaterThan(0);
          const file = Bun.file(`${fixturePath(name)}/${codeRef.file}`);
          expect(await file.exists()).toBe(true);
          const lines = (await file.text()).split("\n");
          expect(codeRef.line).toBeLessThanOrEqual(Math.max(lines.length, 1));
        }
      }
    }
  });

  test("states a fact at most once per (kind, value)", () => {
    for (const name of profiles.keys()) {
      const keys = profileOf(name).facts.map((detected) => `${detected.kind}/${detected.value}`);
      expect(keys).toEqual([...new Set(keys)]);
    }
  });

  test("never contradicts itself by reporting a kind as both present and absent", () => {
    for (const name of profiles.keys()) {
      const profile = profileOf(name);
      const proven = new Set(profile.facts.map((detected) => detected.kind));
      for (const absence of profile.absences) expect(proven.has(absence.kind)).toBe(false);
    }
  });

  test("is stable across runs, so two runs diff to nothing", async () => {
    const again = await profileStack(fileSystem, fixturePath("next-prisma"));
    expect(again).toEqual(profileOf("next-prisma"));
  });
});

describe("a Next.js app-router repository on Prisma", () => {
  test("names the package manager, module system and Node version from the manifest", () => {
    const profile = profileOf("next-prisma");
    expect(packageManager(profile)).toBe("npm");
    expect(moduleSystem(profile)).toBe("esm");
    expect(nodeVersion(profile)).toBe(">=20.0.0");
    expect(valuesOf(profile, "language")).toEqual(["typescript"]);
    expect(isMonorepo(profile)).toBe(false);
  });

  test("calls Next a backend only because route handlers exist, and finds their directory", () => {
    const profile = profileOf("next-prisma");
    expect(backendFrameworks(profile)).toEqual(["next"]);
    expect(valuesOf(profile, "next-router")).toEqual(["app"]);
    expect(routeDirs(profile)).toEqual(["src/app/api"]);
    expect(evidenceFiles(profile, "route-dir")).toContain("src/app/api/users/route.ts");
  });

  test("proves the database engine from the Prisma datasource, not from a guess", () => {
    const profile = profileOf("next-prisma");
    expect(dataLayers(profile)).toEqual(["prisma"]);
    expect(databaseEngines(profile)).toEqual(["postgresql"]);
    const engine = findFact(profile, "database-engine", "postgresql");
    expect(engine?.confidence).toBe("high");
    expect(engine?.evidence.some((item) => item.file === "prisma/schema.prisma")).toBe(true);
    expect(valuesOf(profile, "migrations-dir")).toEqual(["prisma/migrations"]);
    expect(findFact(profile, "migrations-dir", "prisma/migrations")?.detail).toBe("1 migration(s)");
  });

  test("points the appsec phase at the files that check the session", () => {
    const profile = profileOf("next-prisma");
    expect(authProviders(profile)).toEqual(["next-auth"]);
    expect(authHelperFiles(profile)).toContain("src/lib/auth.ts");
    expect(authHelperFiles(profile)).toContain("src/app/api/users/route.ts");
  });

  test("sees the frontend, the Vercel cron and the delivery pipeline", () => {
    const profile = profileOf("next-prisma");
    expect(hasFrontend(profile)).toBe(true);
    expect(valuesOf(profile, "frontend")).toEqual(["next", "react"]);
    expect(hasFact(profile, "serverless-platform", "vercel")).toBe(true);
    expect(valuesOf(profile, "scheduled-job")).toEqual(["/api/cron/digest", "0 3 * * 1"]);
    expect(hasAsyncWorkloads(profile)).toBe(true);
    expect(valuesOf(profile, "container")).toEqual(["dockerfile"]);
    expect(valuesOf(profile, "ci")).toEqual(["github-actions"]);
  });

  test("lists environment variable names and never their values", () => {
    const profile = profileOf("next-prisma");
    expect(envVarNames(profile)).toEqual(["DATABASE_URL", "NEXTAUTH_SECRET", "NEXTAUTH_URL"]);
    expect(validatesConfig(profile)).toBe(true);
    const serialised = JSON.stringify(profile);
    expect(serialised).not.toContain("PASSWORD@localhost");
    expect(serialised).not.toContain("http://localhost:3000");
  });

  test("reports the things it looked for and did not find", () => {
    const profile = profileOf("next-prisma");
    expect(isAbsent(profile, "iac")).toBe(true);
    expect(isAbsent(profile, "queue")).toBe(true);
    expect(isAbsent(profile, "session-store")).toBe(true);
    expect(absenceOf(profile, "iac")?.searched).toContain("*.tf");
  });
});

describe("a CommonJS Express API on Knex", () => {
  test("reads the lockfile and the absent type field", () => {
    const profile = profileOf("express-knex");
    expect(packageManager(profile)).toBe("yarn");
    expect(moduleSystem(profile)).toBe("commonjs");
    expect(bestFact(profile, "module-system")?.confidence).toBe("low");
    expect(valuesOf(profile, "language")).toEqual(["javascript"]);
  });

  test("finds the routers through the framework import, not the directory name", () => {
    const profile = profileOf("express-knex");
    expect(backendFrameworks(profile)).toEqual(["express"]);
    expect(routeDirs(profile)).toContain("src/routes");
    expect(evidenceFiles(profile, "route-dir", "src/routes")).toEqual(["src/routes/users.js"]);
  });

  test("corroborates MySQL from four independent places", () => {
    const profile = profileOf("express-knex");
    expect(dataLayers(profile)).toEqual(["knex", "mysql2"]);
    expect(databaseEngines(profile)).toEqual(["mysql"]);
    const engine = findFact(profile, "database-engine", "mysql");
    expect(engine?.evidence.map((item) => item.file).sort()).toEqual([
      ".env.example",
      "docker-compose.yml",
      "knexfile.js",
      "package.json",
    ]);
    expect(valuesOf(profile, "migrations-dir")).toEqual(["migrations"]);
  });

  test("recognises hand-rolled JWT auth and its guard", () => {
    const profile = profileOf("express-knex");
    expect(authProviders(profile)).toEqual(["hand-rolled-jwt", "jsonwebtoken"]);
    expect(authHelperFiles(profile)).toEqual(["src/middleware/auth.js"]);
    expect(valuesOf(profile, "session-store")).toEqual(["express-session"]);
  });

  test("is a pure API, with no CI and no infrastructure code", () => {
    const profile = profileOf("express-knex");
    expect(isPureApi(profile)).toBe(true);
    expect(isAbsent(profile, "frontend")).toBe(true);
    expect(absenceOf(profile, "frontend")?.note).toContain("not applicable");
    expect(isAbsent(profile, "ci")).toBe(true);
    expect(isAbsent(profile, "iac")).toBe(true);
    expect(isAbsent(profile, "config-validation")).toBe(true);
    expect(valuesOf(profile, "container")).toEqual(["docker-compose"]);
  });

  test("collects env var names from both the example file and the code that reads them", () => {
    const profile = profileOf("express-knex");
    expect(envVarNames(profile)).toEqual(["DATABASE_URL", "JWT_SECRET", "PORT", "SESSION_SECRET"]);
    const jwtSecret = findFact(profile, "env-var", "JWT_SECRET");
    expect(jwtSecret?.evidence.map((item) => item.note)).toEqual(["declared", "read"]);
    expect(JSON.stringify(profile)).not.toContain("PASSWORD@localhost");
  });
});

describe("an API with no user interface at all", () => {
  test("proves the stack it has", () => {
    const profile = profileOf("pure-api");
    expect(packageManager(profile)).toBe("pnpm");
    expect(backendFrameworks(profile)).toEqual(["fastify"]);
    expect(dataLayers(profile)).toEqual(["pg"]);
    expect(databaseEngines(profile)).toEqual(["postgresql"]);
    expect(validatesConfig(profile)).toBe(true);
    expect(routeDirs(profile)).toContain("src/routes");
  });

  test("reports every category it has nothing for", () => {
    const profile = profileOf("pure-api");
    for (const kind of [
      "frontend",
      "container",
      "ci",
      "iac",
      "serverless-platform",
      "queue",
      "scheduler",
      "scheduled-job",
      "migrations-dir",
      "auth-provider",
      "auth-helper",
      "env-file",
      "env-var",
      "node-version",
    ] as const) {
      expect(isAbsent(profile, kind)).toBe(true);
    }
    expect(hasAsyncWorkloads(profile)).toBe(false);
    expect(hasFrontend(profile)).toBe(false);
    expect(nodeVersion(profile)).toBeUndefined();
  });

  test("does not invent a schema file for a repository that writes raw SQL", () => {
    const profile = profileOf("pure-api");
    expect(isAbsent(profile, "db-schema-file")).toBe(true);
    expect(absenceOf(profile, "db-schema-file")?.searched).toContain("*.prisma");
  });

  // pnpm 10 writes `pnpm-workspace.yaml` for settings such as
  // `ignoredBuiltDependencies`, so the file alone must not promote a
  // single-package repository to a monorepo.
  test("a pnpm-workspace.yaml without member packages is still a single package", () => {
    const profile = profileOf("pure-api");
    expect(isMonorepo(profile)).toBe(false);
    expect(findFact(profile, "repo-layout", "single-package")).toBeDefined();
    expect(workspacePackages(profile)).toEqual([]);
  });
});

describe("a pnpm monorepo", () => {
  test("lists the workspace packages and the monorepo tool", () => {
    const profile = profileOf("monorepo");
    expect(isMonorepo(profile)).toBe(true);
    expect(workspacePackages(profile)).toEqual(["apps/api", "packages/shared"]);
    expect(valuesOf(profile, "monorepo-tool")).toEqual(["turborepo"]);
    expect(findFact(profile, "repo-layout", "monorepo")?.evidence[0]?.file).toBe(
      "pnpm-workspace.yaml",
    );
  });

  test("detects a framework declared in a nested package, citing that package.json", () => {
    const profile = profileOf("monorepo");
    expect(backendFrameworks(profile)).toEqual(["nestjs"]);
    expect(evidenceFiles(profile, "backend-framework")).toEqual(["apps/api/package.json"]);
    expect(routeDirs(profile)).toEqual(["apps/api/src/users"]);
    expect(dataLayers(profile)).toEqual(["pg", "typeorm"]);
    expect(valuesOf(profile, "db-schema-file")).toEqual(["apps/api/src/users/user.entity.ts"]);
  });

  test("separates the queue, the Terraform Lambda and the Kubernetes manifests", () => {
    const profile = profileOf("monorepo");
    expect(valuesOf(profile, "queue")).toEqual(["bullmq"]);
    expect(hasFact(profile, "serverless-platform", "aws-lambda")).toBe(true);
    expect(valuesOf(profile, "iac")).toEqual(["kubernetes", "terraform"]);
    expect(evidenceFiles(profile, "iac", "kubernetes")).toEqual(["k8s/deployment.yaml"]);
  });

  test("finds a guard with no auth library, and says the library is missing", () => {
    const profile = profileOf("monorepo");
    expect(authHelperFiles(profile)).toEqual(["apps/api/src/users/users.controller.ts"]);
    expect(isAbsent(profile, "auth-provider")).toBe(true);
  });
});

describe("warnings", () => {
  test("flags two lockfiles instead of silently picking one", async () => {
    const profile = await profileStack(
      flatFileSystem({
        "package.json": '{"name":"two-managers","dependencies":{}}',
        "package-lock.json": "{}",
        "yarn.lock": "# yarn lockfile v1",
      }),
      "",
    );
    expect(valuesOf(profile, "package-manager")).toEqual(["npm", "yarn"]);
    expect(profile.warnings.join(" ")).toContain("More than one package manager");
  });

  test("says a framework is declared but registers no routes", async () => {
    const profile = await profileStack(
      flatFileSystem({
        "package.json": '{"name":"no-routes","dependencies":{"express":"4.19.2"}}',
      }),
      "",
    );
    expect(backendFrameworks(profile)).toEqual(["express"]);
    expect(routeDirs(profile)).toEqual([]);
    expect(profile.warnings.join(" ")).toContain("no route registration");
  });

  test("does not claim a frontend from a dependency with no view files", async () => {
    const profile = await profileStack(
      flatFileSystem({
        "package.json": '{"name":"api","dependencies":{"react":"18.3.1"}}',
      }),
      "",
    );
    expect(hasFrontend(profile)).toBe(false);
    expect(isAbsent(profile, "frontend")).toBe(true);
    expect(profile.warnings.join(" ")).toContain("no *.tsx / *.jsx file was found");
  });
});

describe("profileStack options", () => {
  test("an empty detector list yields a valid, empty profile", async () => {
    const profile = await profileStack(fileSystem, fixturePath("pure-api"), { detectors: [] });
    expect(profile.facts).toEqual([]);
    expect(profile.absences).toEqual([]);
    expect(profile.scan.filesSeen).toBeGreaterThan(0);
  });

  test("--path is recorded on the profile, which still reads the whole repository", async () => {
    const profile = await profileStack(fileSystem, fixturePath("monorepo"), {
      analysisScope: ["apps/api"],
    });
    // The stack is a property of the repository: the root manifest, the lockfile
    // and the second workspace package are all still proven.
    expect(workspacePackages(profile)).toEqual(["apps/api", "packages/shared"]);
    expect(profile.analysis?.paths).toEqual(["apps/api"]);
    expect(profile.analysis?.filesTotal).toBe(profile.scan.filesSeen);
    const inScope = profile.analysis?.filesInScope ?? 0;
    expect(inScope).toBeGreaterThan(0);
    expect(inScope).toBeLessThan(profile.scan.filesSeen);
  });

  test("a whole-repository run records no subtree, rather than recording an empty one", async () => {
    const profile = await profileStack(fileSystem, fixturePath("monorepo"));
    expect(profile.analysis).toBeUndefined();
  });

  test("withAnalysisScope records the same numbers after the fact", async () => {
    const snapshot = await RepoSnapshot.create(fileSystem, fixturePath("monorepo"));
    const profile = await profileStack(fileSystem, fixturePath("monorepo"), { snapshot });
    const recorded = withAnalysisScope(profile, snapshot, ["apps/api"]);
    const upFront = await profileStack(fileSystem, fixturePath("monorepo"), {
      analysisScope: ["apps/api"],
    });
    expect(recorded.analysis).toEqual(upFront.analysis);
    // Resolving the scope needs the profile (a selector may be a package name),
    // so the two orders have to agree.
    expect(withAnalysisScope(profile, snapshot, []).analysis).toBeUndefined();
  });

  test("an additional ignored directory removes its files from the profile", async () => {
    const profile = await profileStack(fileSystem, fixturePath("monorepo"), {
      ignoreDirectories: ["node_modules", ".git", "apps"],
    });
    expect(workspacePackages(profile)).toEqual(["packages/shared"]);
    expect(backendFrameworks(profile)).toEqual([]);
    expect(isAbsent(profile, "backend-framework")).toBe(true);
  });
});
