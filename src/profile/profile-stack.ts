import { SCHEMA_VERSION } from "../contracts/findings.ts";
import {
  type DetectedFact,
  type FactKind,
  FactKindSchema,
  type StackProfile,
  StackProfileSchema,
} from "../contracts/profile.ts";
import { detectAuth } from "./detect-auth.ts";
import { detectConfig } from "./detect-config.ts";
import { detectDataLayer } from "./detect-data-layer.ts";
import { detectDelivery } from "./detect-delivery.ts";
import { detectFramework } from "./detect-framework.ts";
import { detectFrontend } from "./detect-frontend.ts";
import { detectPackaging } from "./detect-packaging.ts";
import { detectServerless } from "./detect-serverless.ts";
import type { DetectionContext, Detector } from "./detector.ts";
import { type Probe, absencesFrom, mergeFacts } from "./fact-builder.ts";
import type { ProfileFileSystem } from "./file-system-port.ts";
import { loadManifests } from "./manifest.ts";
import { RepoSnapshot, type SnapshotLimits } from "./repo-snapshot.ts";

/** Every detector phase 0 runs, in report order. */
export const DEFAULT_DETECTORS: readonly Detector[] = [
  detectPackaging,
  detectFramework,
  detectDataLayer,
  detectAuth,
  detectFrontend,
  detectServerless,
  detectDelivery,
  detectConfig,
];

/** Options for `profileStack`. */
export interface ProfileOptions {
  readonly ignoreDirectories?: readonly string[];
  readonly limits?: Partial<SnapshotLimits>;
  /** Overrides the detector set; used by tests to isolate one area. */
  readonly detectors?: readonly Detector[];
  /**
   * `--path`: the subtrees the *run* analyses.
   *
   * It does not narrow the profile — phase 0 walks and reads the whole
   * repository either way, because the stack is a property of the repository
   * and in a workspace layout the manifests that prove it sit above the
   * analysed subtree. It is recorded, with the file counts on both sides of
   * the boundary, so `stack-profile.json` can never be read as a claim that
   * the run covered everything the profile saw.
   */
  readonly analysisScope?: readonly string[] | undefined;
  /**
   * A listing to profile from instead of walking the repository again.
   *
   * The caller that resolves `--path` needs the same walk — to tell a
   * directory from a typo, and to count the files on each side of the scope
   * boundary — and walking a 3,000-file monorepo twice to answer the same
   * questions is a second of nothing.
   */
  readonly snapshot?: RepoSnapshot | undefined;
}

/**
 * Record on `profile` which subtree the analysis covered.
 *
 * Separate from {@link profileStack} because the scope usually cannot be
 * resolved until the profile exists: `--path api` may name a workspace
 * package, and the packages are a thing phase 0 proves. The counts come from
 * the same listing the profile was built from, so the two documents cannot
 * disagree about how big this repository is.
 */
export function withAnalysisScope(
  profile: StackProfile,
  snapshot: RepoSnapshot,
  paths: readonly string[],
): StackProfile {
  const scope = paths.filter((entry) => entry.trim() !== "");
  if (scope.length === 0) return profile;
  return StackProfileSchema.parse({
    ...profile,
    analysis: {
      paths: [...scope],
      filesInScope: snapshot.filesWithin(scope).length,
      filesTotal: snapshot.allFiles.length,
    },
  } satisfies StackProfile);
}

const KIND_ORDER = new Map<FactKind, number>(
  FactKindSchema.options.map((kind, index) => [kind, index]),
);

function kindIndex(kind: FactKind): number {
  return KIND_ORDER.get(kind) ?? Number.MAX_SAFE_INTEGER;
}

function sortFacts(facts: readonly DetectedFact[]): DetectedFact[] {
  return [...facts].sort(
    (a, b) => kindIndex(a.kind) - kindIndex(b.kind) || a.value.localeCompare(b.value),
  );
}

/**
 * Phase 0: detects the stack of `root`, deterministically, with evidence.
 *
 * Runs the detectors over one shared snapshot so the repository is walked once
 * and every file is read at most once, then merges duplicate facts, derives the
 * absences from what each detector looked for, and validates the artifact
 * before returning it — nothing downstream ever sees an unvalidated profile.
 */
export async function profileStack(
  fileSystem: ProfileFileSystem,
  root: string,
  options: ProfileOptions = {},
): Promise<StackProfile> {
  const snapshot =
    options.snapshot ??
    (await RepoSnapshot.create(fileSystem, root, {
      ...(options.ignoreDirectories === undefined
        ? {}
        : { ignoreDirectories: options.ignoreDirectories }),
      ...(options.limits === undefined ? {} : { limits: options.limits }),
    }));
  const { manifests, warnings: manifestWarnings } = await loadManifests(snapshot);
  const context: DetectionContext = { snapshot, manifests };

  const facts: DetectedFact[] = [];
  const probes: Probe[] = [];
  const warnings: string[] = [...manifestWarnings];
  for (const detector of options.detectors ?? DEFAULT_DETECTORS) {
    const result = await detector(context);
    facts.push(...result.facts);
    probes.push(...result.probes);
    warnings.push(...result.warnings);
  }

  const merged = sortFacts(mergeFacts(facts));
  const absences = absencesFrom(probes, merged).sort(
    (a, b) => kindIndex(a.kind) - kindIndex(b.kind),
  );

  const analysisScope = (options.analysisScope ?? []).filter((entry) => entry.trim() !== "");
  return StackProfileSchema.parse({
    schemaVersion: SCHEMA_VERSION,
    target: root,
    facts: merged,
    absences,
    warnings: [...new Set(warnings)],
    scan: snapshot.stats(),
    ...(analysisScope.length === 0
      ? {}
      : {
          analysis: {
            paths: [...analysisScope],
            filesInScope: snapshot.filesWithin(analysisScope).length,
            filesTotal: snapshot.allFiles.length,
          },
        }),
  } satisfies StackProfile);
}
