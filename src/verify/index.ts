/**
 * Citation verification: nothing a model writes about code reaches the report
 * unless this module can prove it points at real code, and every snippet in the
 * report is extracted here from disk.
 */

export {
  DROP_REASONS,
  VERIFY_DEFAULTS,
  type DropReason,
  type RefHints,
  type VerifyContext,
  type VerifyFileSystem,
  type VerifySettings,
  settingsOf,
} from "./context.ts";
export { type RepoPath, type PathResolution, isInside, resolveRepoPath, toPosix } from "./paths.ts";
export { type Relocation, type RelocateRequest, buildNeedles, fuzzyRelocate } from "./relocate.ts";
export { type SnippetRequest, extractSnippet } from "./snippet.ts";
export {
  type CodeRefVerification,
  type UnverifiedRef,
  type VerifiedRef,
  type LoadedFile,
  type VerifyCache,
  createVerifyCache,
  verifyCodeRef,
} from "./verify-code-ref.ts";
export {
  type DroppedFinding,
  type FindingVerification,
  type RejectedFinding,
  type VerifiedFinding,
  type VerifyFindingsResult,
  verifyFinding,
  verifyFindings,
} from "./verify-findings.ts";
