import type { CodeRef } from "../contracts/findings.ts";
import type { DetectedFact } from "../contracts/profile.ts";
import type { DetectionContext } from "./detector.ts";
import { type DetectionResult, type Probe, ref } from "./fact-builder.ts";
import {
  type DependencySignal,
  factsFromDependencies,
  rootManifest,
  signalLabels,
} from "./manifest.ts";
import { lineOf, lineOfJsonKey } from "./text.ts";

/** Root lockfiles, each of which names exactly one package manager. */
export const LOCKFILES: ReadonlyArray<{ readonly file: string; readonly manager: string }> = [
  { file: "bun.lock", manager: "bun" },
  { file: "bun.lockb", manager: "bun" },
  { file: "pnpm-lock.yaml", manager: "pnpm" },
  { file: "yarn.lock", manager: "yarn" },
  { file: "package-lock.json", manager: "npm" },
  { file: "npm-shrinkwrap.json", manager: "npm" },
];

const BUILD_TOOL_DEPENDENCIES: readonly DependencySignal[] = [
  { value: "next", packages: ["next"] },
  { value: "vite", packages: ["vite"] },
  { value: "tsup", packages: ["tsup"] },
  { value: "esbuild", packages: ["esbuild"] },
  { value: "rollup", packages: ["rollup"] },
  { value: "webpack", packages: ["webpack"] },
  { value: "parcel", packages: ["parcel"] },
  { value: "swc", packages: ["@swc/core", "@swc/cli"] },
  { value: "babel", packages: ["@babel/core"] },
  { value: "turbo", packages: ["turbo"] },
  { value: "nx", packages: ["nx"] },
  { value: "nest-cli", packages: ["@nestjs/cli"] },
  { value: "expo", packages: ["expo"] },
];

const BUILD_TOOL_FILES: ReadonlyArray<{ readonly pattern: RegExp; readonly value: string }> = [
  { pattern: /^next\.config\.(m|c)?(j|t)s$/, value: "next" },
  { pattern: /^vite\.config\.(m|c)?(j|t)s$/, value: "vite" },
  { pattern: /^tsup\.config\.(m|c)?(j|t)s$/, value: "tsup" },
  { pattern: /^rollup\.config\.(m|c)?(j|t)s$/, value: "rollup" },
  { pattern: /^webpack\.config\.(m|c)?(j|t)s$/, value: "webpack" },
  { pattern: /^nest-cli\.json$/, value: "nest-cli" },
];

const MONOREPO_TOOLS: ReadonlyArray<{ readonly file: string; readonly value: string }> = [
  { file: "turbo.json", value: "turborepo" },
  { file: "nx.json", value: "nx" },
  { file: "lerna.json", value: "lerna" },
  { file: "rush.json", value: "rush" },
];

const NODE_VERSION_FILES: readonly string[] = [".nvmrc", ".node-version"];

function normaliseNodeVersion(raw: string): string | undefined {
  const trimmed = raw.trim().replace(/^v/i, "");
  return trimmed.length === 0 ? undefined : trimmed;
}

async function detectPackageManager(context: DetectionContext): Promise<DetectedFact[]> {
  const { snapshot, manifests } = context;
  const facts: DetectedFact[] = [];
  for (const { file, manager } of LOCKFILES) {
    if (snapshot.has(file)) {
      facts.push({
        kind: "package-manager",
        value: manager,
        confidence: "high",
        detail: `lockfile ${file}`,
        evidence: [ref(file, 1, "lockfile")],
      });
    }
  }
  const root = rootManifest(manifests);
  const declared = root?.data.packageManager;
  if (root !== undefined && declared !== undefined) {
    const name = declared.split("@")[0];
    if (name !== undefined && name.length > 0) {
      facts.push({
        kind: "package-manager",
        value: name,
        confidence: "high",
        detail: `packageManager: ${declared}`,
        evidence: [ref(root.path, lineOfJsonKey(root.lines, "packageManager") ?? 1)],
      });
    }
  }
  return facts;
}

async function detectNodeVersion(context: DetectionContext): Promise<DetectedFact[]> {
  const { snapshot, manifests } = context;
  const facts: DetectedFact[] = [];
  const root = rootManifest(manifests);
  const engines = root?.data.engines?.node;
  if (root !== undefined && engines !== undefined) {
    facts.push({
      kind: "node-version",
      value: engines,
      confidence: "high",
      detail: "engines.node",
      evidence: [ref(root.path, lineOfJsonKey(root.lines, "node") ?? 1, "engines.node")],
    });
  }
  for (const file of NODE_VERSION_FILES) {
    if (!snapshot.has(file)) continue;
    const content = await snapshot.read(file);
    const version = content === undefined ? undefined : normaliseNodeVersion(content);
    if (version !== undefined) {
      facts.push({
        kind: "node-version",
        value: version,
        confidence: "high",
        detail: file,
        evidence: [ref(file, 1)],
      });
    }
  }
  // Dockerfiles and CI workflows pin a version too, but only for one stage of
  // the pipeline, so they are corroborating rather than authoritative.
  const dockerfiles = snapshot.filesMatching(/(^|\/)Dockerfile(\.[\w.-]+)?$/);
  const dockerHits = await snapshot.grep(/^\s*FROM\s+(?:--\S+\s+)*node:([\w.-]+)/i, {
    files: dockerfiles,
    limit: 20,
  });
  for (const hit of dockerHits) {
    const tag = /node:([\w.-]+)/i.exec(hit.text)?.[1];
    if (tag === undefined) continue;
    const numeric = /^(\d+(?:\.\d+)*)/.exec(tag)?.[1];
    facts.push({
      kind: "node-version",
      value: numeric ?? tag,
      confidence: "medium",
      detail: `base image node:${tag}`,
      evidence: [ref(hit.file, hit.line)],
    });
  }
  const workflows = snapshot.filesMatching(/^\.github\/workflows\/.+\.ya?ml$/);
  const ciHits = await snapshot.grep(/node-version:\s*['"]?([\d.x]+)/i, {
    files: workflows,
    limit: 20,
  });
  for (const hit of ciHits) {
    const version = /node-version:\s*['"]?([\d.x]+)/i.exec(hit.text)?.[1];
    if (version === undefined) continue;
    facts.push({
      kind: "node-version",
      value: version,
      confidence: "medium",
      detail: "CI setup-node",
      evidence: [ref(hit.file, hit.line)],
    });
  }
  return facts;
}

async function detectModuleSystem(context: DetectionContext): Promise<DetectedFact[]> {
  const { snapshot, manifests } = context;
  const root = rootManifest(manifests);
  if (root === undefined) return [];
  const declared = root.data.type;
  if (declared !== undefined) {
    return [
      {
        kind: "module-system",
        value: declared === "module" ? "esm" : "commonjs",
        confidence: "high",
        detail: `package.json "type": "${declared}"`,
        evidence: [ref(root.path, lineOfJsonKey(root.lines, "type") ?? 1)],
      },
    ];
  }
  const facts: DetectedFact[] = [
    {
      kind: "module-system",
      value: "commonjs",
      confidence: "low",
      // Stated at low confidence because it is Node's default rather than
      // anything the repository actually says; a bundler may override it.
      detail: 'no "type" field; Node defaults to CommonJS',
      evidence: [ref(root.path, 1)],
    },
  ];
  const tsconfigs = snapshot.filesMatching(/(^|\/)tsconfig(\.\w+)?\.json$/);
  const hits = await snapshot.grep(/"module"\s*:\s*"commonjs"/i, { files: tsconfigs, limit: 5 });
  for (const hit of hits) {
    facts.push({
      kind: "module-system",
      value: "commonjs",
      confidence: "medium",
      detail: "tsconfig module: commonjs",
      evidence: [ref(hit.file, hit.line)],
    });
  }
  return facts;
}

function detectLanguage(context: DetectionContext): DetectedFact[] {
  const { snapshot, manifests } = context;
  const facts: DetectedFact[] = [];
  const tsFiles = snapshot.filesMatching(/\.(ts|tsx|mts|cts)$/);
  const jsFiles = snapshot.filesMatching(/\.(js|jsx|mjs|cjs)$/);
  const tsconfigs = snapshot.filesMatching(/(^|\/)tsconfig(\.\w+)?\.json$/);
  const first = tsFiles[0] ?? tsconfigs[0];
  if (first !== undefined) {
    const typescriptDep = manifests
      .flatMap((manifest) => [manifest.data.devDependencies, manifest.data.dependencies])
      .find((section) => section?.typescript !== undefined)?.typescript;
    facts.push({
      kind: "language",
      value: "typescript",
      confidence: "high",
      detail:
        typescriptDep === undefined
          ? `${tsFiles.length} TypeScript file(s)`
          : `typescript@${typescriptDep}, ${tsFiles.length} TypeScript file(s)`,
      evidence: [ref(first, 1)],
    });
  }
  const firstJs = jsFiles[0];
  // A stray `eslint.config.js` in a TypeScript repo is not "a JavaScript
  // codebase"; require either no TypeScript at all or a real JS population.
  if (firstJs !== undefined && (tsFiles.length === 0 || jsFiles.length >= 5)) {
    facts.push({
      kind: "language",
      value: "javascript",
      confidence: tsFiles.length === 0 ? "high" : "medium",
      detail: `${jsFiles.length} JavaScript file(s)`,
      evidence: [ref(firstJs, 1)],
    });
  }
  for (const tsconfig of tsconfigs.slice(0, 10)) {
    facts.push({
      kind: "tsconfig",
      value: tsconfig,
      confidence: "high",
      evidence: [ref(tsconfig, 1)],
    });
  }
  return facts;
}

/**
 * True when a `pnpm-workspace.yaml` actually declares member packages. pnpm 10
 * writes this file for settings like `ignoredBuiltDependencies` alone, so its
 * mere presence says nothing about the repository being a monorepo.
 */
function declaresWorkspacePackages(yaml: string | undefined): boolean {
  if (yaml === undefined) return false;
  const lines = yaml.split(/\r?\n/);
  const start = lines.findIndex((line) => /^packages\s*:/.test(line));
  if (start === -1) return false;
  // Either an inline flow list (`packages: ["apps/*"]`) or a block list whose
  // first non-blank continuation line is an item.
  const inline = lines[start]?.slice(lines[start]?.indexOf(":") + 1).trim() ?? "";
  if (inline.length > 0) return inline !== "[]";
  for (const line of lines.slice(start + 1)) {
    if (line.trim().length === 0) continue;
    return /^\s+-\s*\S/.test(line);
  }
  return false;
}

async function detectLayout(context: DetectionContext): Promise<DetectedFact[]> {
  const { snapshot, manifests } = context;
  const facts: DetectedFact[] = [];
  const root = rootManifest(manifests);
  const nonRoot = manifests.filter((manifest) => manifest.path !== "package.json");
  const workspaceEvidence: CodeRef[] = [];
  const declaredWorkspaces = root?.data.workspaces;
  const hasWorkspaceField = Array.isArray(declaredWorkspaces)
    ? declaredWorkspaces.length > 0
    : declaredWorkspaces !== undefined;
  if (root !== undefined && hasWorkspaceField) {
    workspaceEvidence.push(ref(root.path, lineOfJsonKey(root.lines, "workspaces") ?? 1));
  }
  if (snapshot.has("pnpm-workspace.yaml")) {
    const yaml = await snapshot.read("pnpm-workspace.yaml");
    if (declaresWorkspacePackages(yaml)) {
      workspaceEvidence.push(ref("pnpm-workspace.yaml", 1));
    }
  }
  for (const tool of MONOREPO_TOOLS) {
    if (!snapshot.has(tool.file)) continue;
    facts.push({
      kind: "monorepo-tool",
      value: tool.value,
      confidence: "high",
      evidence: [ref(tool.file, 1)],
    });
  }
  const monorepo = workspaceEvidence.length > 0 || nonRoot.length > 0;
  if (monorepo) {
    const evidence =
      workspaceEvidence.length > 0
        ? workspaceEvidence
        : [ref(nonRoot[0]?.path ?? "package.json", 1)];
    facts.push({
      kind: "repo-layout",
      value: "monorepo",
      confidence: workspaceEvidence.length > 0 ? "high" : "medium",
      detail:
        nonRoot.length > 0
          ? `${nonRoot.length} package(s) beside the root manifest`
          : "workspaces are declared, but no member package was found",
      evidence,
    });
  } else if (root !== undefined) {
    facts.push({
      kind: "repo-layout",
      value: "single-package",
      confidence: "high",
      detail: "one package.json, no workspaces declaration",
      evidence: [ref(root.path, 1)],
    });
  }
  for (const manifest of nonRoot) {
    facts.push({
      kind: "workspace-package",
      value: manifest.directory,
      confidence: "high",
      ...(manifest.data.name === undefined ? {} : { detail: manifest.data.name }),
      evidence: [ref(manifest.path, lineOfJsonKey(manifest.lines, "name") ?? 1)],
    });
  }
  return facts;
}

async function detectBuildTools(context: DetectionContext): Promise<DetectedFact[]> {
  const { snapshot, manifests } = context;
  const facts = factsFromDependencies(manifests, "build-tool", BUILD_TOOL_DEPENDENCIES);
  for (const file of snapshot.files) {
    const base = file.includes("/") ? file.slice(file.lastIndexOf("/") + 1) : file;
    for (const candidate of BUILD_TOOL_FILES) {
      if (!candidate.pattern.test(base)) continue;
      facts.push({
        kind: "build-tool",
        value: candidate.value,
        confidence: "high",
        detail: file,
        evidence: [ref(file, 1)],
      });
    }
  }
  const root = rootManifest(manifests);
  const buildScript = root?.data.scripts?.build;
  if (root !== undefined && buildScript !== undefined && /\btsc\b/.test(buildScript)) {
    facts.push({
      kind: "build-tool",
      value: "tsc",
      confidence: "high",
      detail: "build script runs tsc",
      evidence: [ref(root.path, lineOf(root.lines, /"build"\s*:/) ?? 1)],
    });
  }
  return facts;
}

/** Detects package manager, repository layout, language, module system, Node version and build tooling. */
export async function detectPackaging(context: DetectionContext): Promise<DetectionResult> {
  const warnings: string[] = [];
  const facts: DetectedFact[] = [
    ...(await detectPackageManager(context)),
    ...(await detectNodeVersion(context)),
    ...(await detectModuleSystem(context)),
    ...detectLanguage(context),
    ...(await detectLayout(context)),
    ...(await detectBuildTools(context)),
  ];

  const managers = new Set(facts.filter((f) => f.kind === "package-manager").map((f) => f.value));
  if (managers.size > 1) {
    warnings.push(
      `More than one package manager is evidenced (${[...managers].sort().join(", ")}); lockfile integrity is in question.`,
    );
  }
  if (rootManifest(context.manifests) === undefined) {
    warnings.push("No package.json at the repository root; this may not be a Node.js project.");
  }

  const probes: Probe[] = [
    {
      kind: "package-manager",
      searched: [...LOCKFILES.map((l) => l.file), "package.json#packageManager"],
    },
    { kind: "node-version", searched: ["package.json#engines.node", ...NODE_VERSION_FILES] },
    { kind: "language", searched: ["*.ts", "*.tsx", "*.js", "tsconfig.json"] },
    { kind: "module-system", searched: ["package.json#type"] },
    {
      kind: "build-tool",
      searched: [...signalLabels(BUILD_TOOL_DEPENDENCIES), "next.config.*", "vite.config.*"],
    },
    { kind: "monorepo-tool", searched: MONOREPO_TOOLS.map((t) => t.file) },
  ];

  return { facts, probes, warnings };
}
