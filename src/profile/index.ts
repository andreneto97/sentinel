/**
 * Phase 0 — stack detection.
 *
 * `profileStack` is the entry point; everything else is exported so the scope
 * proposal, the inventory phase and the report can read the profile without
 * re-deriving it.
 */
export {
  absenceOf,
  authHelperFiles,
  authProviders,
  backendFrameworks,
  bestFact,
  databaseEngines,
  dataLayers,
  envVarNames,
  evidenceFiles,
  factsOf,
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
export { detectAuth } from "./detect-auth.ts";
export { detectConfig } from "./detect-config.ts";
export { composeFiles, detectDataLayer, envFiles } from "./detect-data-layer.ts";
export { detectDelivery } from "./detect-delivery.ts";
export { detectFramework } from "./detect-framework.ts";
export { detectFrontend } from "./detect-frontend.ts";
export { detectPackaging } from "./detect-packaging.ts";
export { detectServerless } from "./detect-serverless.ts";
export type { DetectionContext, Detector } from "./detector.ts";
export {
  absencesFrom,
  type DetectionResult,
  fact,
  type FactInput,
  mergeFacts,
  type Probe,
  ref,
  strongerConfidence,
} from "./fact-builder.ts";
export type { ProfileDirEntry, ProfileFileSystem } from "./file-system-port.ts";
export {
  allDependencies,
  type DependencyHit,
  type DependencySignal,
  dependencyRef,
  factsFromDependencies,
  findDependency,
  hasDependency,
  loadManifests,
  type PackageJson,
  PackageJsonSchema,
  type PackageManifest,
  rootManifest,
  signalLabels,
} from "./manifest.ts";
export {
  DEFAULT_DETECTORS,
  type ProfileOptions,
  profileStack,
  withAnalysisScope,
} from "./profile-stack.ts";
export {
  DEFAULT_IGNORED_DIRECTORIES,
  DEFAULT_LIMITS,
  type GrepHit,
  RepoSnapshot,
  type SnapshotLimits,
  type SnapshotOptions,
  SOURCE_EXTENSIONS,
} from "./repo-snapshot.ts";
export { escapeRegExp, importPattern, lineOf, lineOfJsonKey, toLines } from "./text.ts";
