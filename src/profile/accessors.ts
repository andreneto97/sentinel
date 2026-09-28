import type { Confidence } from "../contracts/findings.ts";
import type { Absence, DetectedFact, FactKind, StackProfile } from "../contracts/profile.ts";

const CONFIDENCE_RANK: Record<Confidence, number> = { low: 0, medium: 1, high: 2 };

/** Every fact of one kind, in the order they were detected. */
export function factsOf(profile: StackProfile, kind: FactKind): DetectedFact[] {
  return profile.facts.filter((detected) => detected.kind === kind);
}

/** The values of every fact of one kind, deduplicated and sorted. */
export function valuesOf(profile: StackProfile, kind: FactKind): string[] {
  return [...new Set(factsOf(profile, kind).map((detected) => detected.value))].sort();
}

/** The fact for `(kind, value)`, if it was proven. */
export function findFact(
  profile: StackProfile,
  kind: FactKind,
  value: string,
): DetectedFact | undefined {
  return profile.facts.find((detected) => detected.kind === kind && detected.value === value);
}

/** True when `(kind, value)` was proven. */
export function hasFact(profile: StackProfile, kind: FactKind, value: string): boolean {
  return findFact(profile, kind, value) !== undefined;
}

/** The most strongly evidenced fact of one kind, or `undefined` when there is none. */
export function bestFact(profile: StackProfile, kind: FactKind): DetectedFact | undefined {
  let best: DetectedFact | undefined;
  for (const detected of factsOf(profile, kind)) {
    if (best === undefined) {
      best = detected;
      continue;
    }
    const better =
      CONFIDENCE_RANK[detected.confidence] > CONFIDENCE_RANK[best.confidence] ||
      (CONFIDENCE_RANK[detected.confidence] === CONFIDENCE_RANK[best.confidence] &&
        detected.evidence.length > best.evidence.length);
    if (better) best = detected;
  }
  return best;
}

/** True when the kind was looked for and nothing was found. */
export function isAbsent(profile: StackProfile, kind: FactKind): boolean {
  return profile.absences.some((absence) => absence.kind === kind);
}

/** The absence record for a kind, with the list of what was inspected. */
export function absenceOf(profile: StackProfile, kind: FactKind): Absence | undefined {
  return profile.absences.find((absence) => absence.kind === kind);
}

/** Every file cited as evidence for a kind (optionally for one value), deduplicated. */
export function evidenceFiles(profile: StackProfile, kind: FactKind, value?: string): string[] {
  const facts = factsOf(profile, kind).filter(
    (detected) => value === undefined || detected.value === value,
  );
  return [
    ...new Set(facts.flatMap((detected) => detected.evidence.map((item) => item.file))),
  ].sort();
}

/** The package manager, when exactly one is evidenced. */
export function packageManager(profile: StackProfile): string | undefined {
  const managers = valuesOf(profile, "package-manager");
  return managers.length === 1 ? managers[0] : bestFact(profile, "package-manager")?.value;
}

/** Every backend framework in use. */
export function backendFrameworks(profile: StackProfile): string[] {
  return valuesOf(profile, "backend-framework");
}

/** Every ORM, query builder or driver in use. */
export function dataLayers(profile: StackProfile): string[] {
  return valuesOf(profile, "data-layer");
}

/** Every proven database engine. */
export function databaseEngines(profile: StackProfile): string[] {
  return valuesOf(profile, "database-engine");
}

/** Every proven authentication provider. */
export function authProviders(profile: StackProfile): string[] {
  return valuesOf(profile, "auth-provider");
}

/** Files that contain an authentication check, which the appsec phase compares handlers against. */
export function authHelperFiles(profile: StackProfile): string[] {
  return valuesOf(profile, "auth-helper");
}

/** True when the repository ships a user interface. */
export function hasFrontend(profile: StackProfile): boolean {
  return factsOf(profile, "frontend").length > 0;
}

/** True when the repository is a backend with no user interface of its own. */
export function isPureApi(profile: StackProfile): boolean {
  return !hasFrontend(profile);
}

/** True when the repository holds more than one package. */
export function isMonorepo(profile: StackProfile): boolean {
  return hasFact(profile, "repo-layout", "monorepo");
}

/** Directories of the workspace packages, excluding the root. */
export function workspacePackages(profile: StackProfile): string[] {
  return valuesOf(profile, "workspace-package");
}

/** The best-evidenced Node version constraint. */
export function nodeVersion(profile: StackProfile): string | undefined {
  return bestFact(profile, "node-version")?.value;
}

/** The module system, `esm` or `commonjs`. */
export function moduleSystem(profile: StackProfile): string | undefined {
  return bestFact(profile, "module-system")?.value;
}

/** Directories where route handlers live. */
export function routeDirs(profile: StackProfile): string[] {
  return valuesOf(profile, "route-dir");
}

/** Environment variable names the repository declares or reads; never their values. */
export function envVarNames(profile: StackProfile): string[] {
  return valuesOf(profile, "env-var");
}

/** True when the repository validates its environment with a schema at startup. */
export function validatesConfig(profile: StackProfile): boolean {
  return factsOf(profile, "config-validation").length > 0;
}

/** True when any serverless platform, queue or scheduled job was detected. */
export function hasAsyncWorkloads(profile: StackProfile): boolean {
  return (["serverless-platform", "queue", "scheduler", "scheduled-job"] as const).some(
    (kind) => factsOf(profile, kind).length > 0,
  );
}
