import type { DetectedFact } from "../contracts/profile.ts";
import type { DetectionContext } from "./detector.ts";
import { type DetectionResult, type Probe, ref } from "./fact-builder.ts";
import { allDependencies } from "./manifest.ts";

/**
 * A frontend, proven by a dependency *and* by view files.
 *
 * Both halves are required. A stray `react` dependency in an API-only service
 * must not make Sentinel claim there is a UI, because "no frontend" is what
 * lets the report say the role-gate and XSS categories are not applicable
 * rather than silently unchecked.
 */
interface FrontendCandidate {
  readonly value: string;
  readonly packages: readonly string[];
  readonly prefixes?: readonly string[];
  /** Paths that count as views for this framework. */
  readonly views: RegExp;
  readonly viewLabel: string;
}

const NEXT_VIEW_FILE =
  /^(?:src\/)?(?:app\/(?:.*\/)?(?:page|layout|template|default)\.(?:tsx|ts|jsx|js)|pages\/(?!api\/).+\.(?:tsx|jsx))$/;

/** The frontend frameworks phase 0 recognises. */
export const FRONTEND_CANDIDATES: readonly FrontendCandidate[] = [
  {
    value: "next",
    packages: ["next"],
    views: NEXT_VIEW_FILE,
    viewLabel: "app/ or pages/ view files",
  },
  { value: "react", packages: ["react"], views: /\.(tsx|jsx)$/, viewLabel: "*.tsx / *.jsx" },
  {
    value: "react-native",
    packages: ["react-native"],
    views: /\.(tsx|jsx)$/,
    viewLabel: "*.tsx / *.jsx",
  },
  {
    value: "expo",
    packages: ["expo"],
    views: /^(?:app\.(?:json|config\.(?:m|c)?(?:j|t)s)|app\/.+\.(?:tsx|jsx))$/,
    viewLabel: "app.json / expo router screens",
  },
  { value: "vue", packages: ["vue", "nuxt"], views: /\.vue$/, viewLabel: "*.vue" },
  {
    value: "svelte",
    packages: ["svelte", "@sveltejs/kit"],
    views: /\.svelte$/,
    viewLabel: "*.svelte",
  },
  {
    value: "angular",
    packages: [],
    prefixes: ["@angular/"],
    views: /\.component\.ts$/,
    viewLabel: "*.component.ts",
  },
  { value: "solid", packages: ["solid-js"], views: /\.(tsx|jsx)$/, viewLabel: "*.tsx / *.jsx" },
  { value: "astro", packages: ["astro"], views: /\.astro$/, viewLabel: "*.astro" },
  {
    value: "remix",
    packages: ["@remix-run/react"],
    views: /\.(tsx|jsx)$/,
    viewLabel: "*.tsx / *.jsx",
  },
];

/** Detects whether the repository ships a user interface at all, and of what kind. */
export async function detectFrontend(context: DetectionContext): Promise<DetectionResult> {
  const { manifests, snapshot } = context;
  const dependencies = allDependencies(manifests);
  const facts: DetectedFact[] = [];
  const warnings: string[] = [];

  for (const candidate of FRONTEND_CANDIDATES) {
    const hit = dependencies.find(
      (dependency) =>
        candidate.packages.includes(dependency.name) ||
        candidate.prefixes?.some((prefix) => dependency.name.startsWith(prefix)) === true,
    );
    if (hit === undefined) continue;
    const views = snapshot.filesMatching(candidate.views);
    const firstView = views[0];
    if (firstView === undefined) {
      warnings.push(
        `${hit.name} is declared in ${hit.manifest.path} but no ${candidate.viewLabel} file was found; no frontend fact was emitted for ${candidate.value}.`,
      );
      continue;
    }
    facts.push({
      kind: "frontend",
      value: candidate.value,
      confidence: "high",
      detail: `${hit.name}@${hit.range}, ${views.length} file(s) matching ${candidate.viewLabel}`,
      evidence: [ref(firstView, 1, candidate.viewLabel)],
    });
  }

  const probes: Probe[] = [
    {
      kind: "frontend",
      searched: [
        ...FRONTEND_CANDIDATES.flatMap((candidate) => [
          ...candidate.packages,
          ...(candidate.prefixes ?? []).map((prefix) => `${prefix}*`),
        ]),
        "*.tsx",
        "*.vue",
        "*.svelte",
        "*.astro",
      ].sort(),
      note: "No user interface: role-gate and view-layer XSS checks are not applicable to this repository.",
    },
  ];

  return { facts, probes, warnings };
}
