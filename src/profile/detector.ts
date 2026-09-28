import type { DetectionResult } from "./fact-builder.ts";
import type { PackageManifest } from "./manifest.ts";
import type { RepoSnapshot } from "./repo-snapshot.ts";

/** Everything a detector is given: the shared file listing and the parsed manifests. */
export interface DetectionContext {
  readonly snapshot: RepoSnapshot;
  readonly manifests: readonly PackageManifest[];
}

/** One area of stack detection, e.g. the data layer or the delivery pipeline. */
export type Detector = (context: DetectionContext) => Promise<DetectionResult>;
