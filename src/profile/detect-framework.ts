import type { DetectedFact } from "../contracts/profile.ts";
import type { DetectionContext } from "./detector.ts";
import { type DetectionResult, type Probe, ref } from "./fact-builder.ts";
import {
  type DependencySignal,
  factsFromDependencies,
  findDependency,
  signalLabels,
} from "./manifest.ts";
import type { GrepHit, RepoSnapshot } from "./repo-snapshot.ts";
import { importPattern } from "./text.ts";

/**
 * Backend frameworks, proven by a declared dependency.
 *
 * Next.js is missing on purpose: it is both a frontend and, only when route
 * handlers or server actions exist, a backend — see `detectNext`.
 */
export const BACKEND_FRAMEWORK_SIGNALS: readonly DependencySignal[] = [
  { value: "express", packages: ["express"] },
  { value: "fastify", packages: ["fastify"] },
  { value: "nestjs", packages: ["@nestjs/core"] },
  { value: "hono", packages: ["hono"] },
  { value: "koa", packages: ["koa"] },
  { value: "trpc", packages: ["@trpc/server"] },
];

/** Route-registration patterns per framework; a route dir must contain one of these. */
const ROUTE_PATTERNS: Readonly<Record<string, RegExp>> = {
  express: /\.(get|post|put|patch|delete|all|use|route)\s*\(\s*['"`]/,
  koa: /\.(get|post|put|patch|delete|all|use)\s*\(\s*['"`]/,
  fastify: /\.(get|post|put|patch|delete|route|register)\s*\(\s*[['"`{]/,
  hono: /\.(get|post|put|patch|delete|on|route)\s*\(\s*['"`]/,
  nestjs: /@Controller\s*\(/,
  trpc: /\b(?:router|createTRPCRouter|t\.router)\s*\(\s*\{/,
};

/** Packages whose import proves a file belongs to a framework. */
const FRAMEWORK_PACKAGES: Readonly<Record<string, readonly string[]>> = {
  express: ["express"],
  koa: ["koa", "@koa/router"],
  fastify: ["fastify"],
  hono: ["hono"],
  nestjs: ["@nestjs/common", "@nestjs/core"],
  trpc: ["@trpc/server"],
};

const MAX_ROUTE_DIRS = 15;

function directoryOf(file: string): string {
  const index = file.lastIndexOf("/");
  return index === -1 ? "." : file.slice(0, index);
}

async function filesImporting(
  snapshot: RepoSnapshot,
  packages: readonly string[],
): Promise<string[]> {
  const files = new Set<string>();
  for (const packageName of packages) {
    const hits = await snapshot.grep(importPattern(packageName), { limit: 500 });
    for (const hit of hits) files.add(hit.file);
  }
  return [...files].sort();
}

/** Collects one `route-dir` fact per directory holding a file that registers routes. */
async function routeDirsFor(snapshot: RepoSnapshot, framework: string): Promise<DetectedFact[]> {
  const packages = FRAMEWORK_PACKAGES[framework];
  const pattern = ROUTE_PATTERNS[framework];
  if (packages === undefined || pattern === undefined) return [];
  const candidates = await filesImporting(snapshot, packages);
  if (candidates.length === 0) return [];
  const hits = await snapshot.grep(pattern, { files: candidates, limit: 400 });
  const firstHitPerDirectory = new Map<string, GrepHit>();
  for (const hit of hits) {
    const directory = directoryOf(hit.file);
    if (!firstHitPerDirectory.has(directory)) firstHitPerDirectory.set(directory, hit);
  }
  return [...firstHitPerDirectory.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .slice(0, MAX_ROUTE_DIRS)
    .map(([directory, hit]) => ({
      kind: "route-dir" as const,
      value: directory,
      confidence: "high" as const,
      detail: `${framework} route registration`,
      evidence: [ref(hit.file, hit.line)],
    }));
}

const NEXT_APP_FILE =
  /^(?:src\/)?app\/(?:.*\/)?(page|layout|route|template|default|error|loading|not-found)\.(tsx|ts|jsx|js)$/;
const NEXT_PAGES_FILE = /^(?:src\/)?pages\/.+\.(tsx|ts|jsx|js)$/;
const NEXT_APP_ROUTE_HANDLER = /^(?:src\/)?app\/(?:.*\/)?route\.(tsx|ts|jsx|js)$/;
const NEXT_PAGES_API = /^(?:src\/)?pages\/api\/.+\.(tsx|ts|jsx|js)$/;

/**
 * Next.js, which only counts as a backend framework when it actually serves
 * server code: a route handler, a `pages/api` file, or a server action.
 */
async function detectNext(context: DetectionContext): Promise<DetectedFact[]> {
  const { snapshot, manifests } = context;
  const nextDependency = findDependency(manifests, "next");
  if (nextDependency === undefined) return [];
  const facts: DetectedFact[] = [];
  const appFiles = snapshot.filesMatching(NEXT_APP_FILE);
  const pagesFiles = snapshot.filesMatching(NEXT_PAGES_FILE);
  const firstApp = appFiles[0];
  if (firstApp !== undefined) {
    facts.push({
      kind: "next-router",
      value: "app",
      confidence: "high",
      detail: `${appFiles.length} app-router file(s)`,
      evidence: [ref(firstApp, 1)],
    });
  }
  const firstPage = pagesFiles[0];
  if (firstPage !== undefined) {
    facts.push({
      kind: "next-router",
      value: "pages",
      confidence: "high",
      detail: `${pagesFiles.length} pages-router file(s)`,
      evidence: [ref(firstPage, 1)],
    });
  }

  const handlers = snapshot.filesMatching(NEXT_APP_ROUTE_HANDLER);
  const apiPages = snapshot.filesMatching(NEXT_PAGES_API);
  const serverActions = await snapshot.grep(/^\s*['"`]use server['"`]/, { limit: 20 });
  const serverEvidence = [
    ...handlers.slice(0, 5).map((file) => ref(file, 1, "route handler")),
    ...apiPages.slice(0, 5).map((file) => ref(file, 1, "pages API route")),
    ...serverActions.slice(0, 5).map((hit) => ref(hit.file, hit.line, "server action")),
  ];
  if (serverEvidence.length > 0) {
    facts.push({
      kind: "backend-framework",
      value: "next",
      confidence: "high",
      detail: `${handlers.length} route handler(s), ${apiPages.length} pages API route(s), ${serverActions.length} server action file(s)`,
      evidence: serverEvidence,
    });
  }

  const appApi = handlers.filter((file) => /^(?:src\/)?app\/api\//.test(file));
  const firstAppApi = appApi[0];
  if (firstAppApi !== undefined) {
    facts.push({
      kind: "route-dir",
      value: firstAppApi.startsWith("src/") ? "src/app/api" : "app/api",
      confidence: "high",
      detail: `${appApi.length} route handler(s)`,
      evidence: appApi.slice(0, 10).map((file) => ref(file, 1)),
    });
  }
  const firstApiPage = apiPages[0];
  if (firstApiPage !== undefined) {
    facts.push({
      kind: "route-dir",
      value: firstApiPage.startsWith("src/") ? "src/pages/api" : "pages/api",
      confidence: "high",
      detail: `${apiPages.length} API route(s)`,
      evidence: apiPages.slice(0, 10).map((file) => ref(file, 1)),
    });
  }
  // Route handlers outside `api/` are real endpoints too (webhooks, OG images).
  const looseHandlers = handlers.filter((file) => !/^(?:src\/)?app\/api\//.test(file));
  for (const file of looseHandlers.slice(0, 5)) {
    facts.push({
      kind: "route-dir",
      value: directoryOf(file),
      confidence: "high",
      detail: "next route handler outside app/api",
      evidence: [ref(file, 1)],
    });
  }
  return facts;
}

/** Detects the backend framework, the Next.js router flavour, and the directories holding routes. */
export async function detectFramework(context: DetectionContext): Promise<DetectionResult> {
  const { manifests, snapshot } = context;
  const frameworkFacts = factsFromDependencies(
    manifests,
    "backend-framework",
    BACKEND_FRAMEWORK_SIGNALS,
  );
  const facts: DetectedFact[] = [...frameworkFacts];
  for (const framework of new Set(frameworkFacts.map((f) => f.value))) {
    facts.push(...(await routeDirsFor(snapshot, framework)));
  }
  facts.push(...(await detectNext(context)));

  const warnings: string[] = [];
  const detected = new Set(facts.filter((f) => f.kind === "backend-framework").map((f) => f.value));
  const withoutRoutes = [...detected].filter(
    (framework) =>
      framework !== "next" &&
      !facts.some((f) => f.kind === "route-dir" && f.detail?.startsWith(framework) === true),
  );
  if (withoutRoutes.length > 0) {
    warnings.push(
      `Declared but no route registration was found for: ${withoutRoutes.sort().join(", ")}. The inventory phase may find nothing to audit.`,
    );
  }

  const probes: Probe[] = [
    {
      kind: "backend-framework",
      searched: [...signalLabels(BACKEND_FRAMEWORK_SIGNALS), "next"],
      note: "Detected from declared dependencies only; a file name never implies a framework.",
    },
    {
      kind: "route-dir",
      searched: ["app/**/route.*", "pages/api/**", "*.get()/.post() on a framework router"],
    },
    { kind: "next-router", searched: ["app/**", "pages/**"] },
  ];

  return { facts, probes, warnings };
}
