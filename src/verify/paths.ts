import path from "node:path";
import type { DropReason } from "./context.ts";

/** A cited path proven to live inside the target repo, in both forms the report needs. */
export interface RepoPath {
  /** Repo-relative POSIX path — what every artifact stores. */
  readonly relative: string;
  /** Absolute path on this machine — what the filesystem port is called with. */
  readonly absolute: string;
}

/** The outcome of resolving a cited path against the target repo. */
export type PathResolution =
  | { readonly ok: true; readonly value: RepoPath }
  | { readonly ok: false; readonly reason: DropReason; readonly detail: string };

/** Rewrites Windows separators so an emitted path is always POSIX. */
export function toPosix(value: string): string {
  return value.split(path.sep).join("/");
}

/**
 * Strips the decoration models wrap paths in — quotes, backticks, a `file://`
 * scheme, leading `./` — without touching the path itself.
 */
export function normaliseCitedPath(raw: string): string {
  let value = raw.trim();
  value = value
    .replace(/^[`'"]+/, "")
    .replace(/[`'"]+$/, "")
    .trim();
  if (value.startsWith("file://")) value = value.slice("file://".length);
  while (value.startsWith("./")) value = value.slice(2);
  return value.replace(/\/+$/, "");
}

/** True when `childAbs` is a strict descendant of `parentAbs`. */
export function isInside(parentAbs: string, childAbs: string): boolean {
  const rel = path.relative(parentAbs, childAbs);
  if (rel === "" || path.isAbsolute(rel)) return false;
  return rel !== ".." && !rel.startsWith(`..${path.sep}`);
}

/**
 * Resolves a cited path to a repo-relative POSIX path, refusing anything that
 * escapes the target directory. Lexical only — symlinks are checked later,
 * against the filesystem.
 */
export function resolveRepoPath(rawPath: string, targetDir: string): PathResolution {
  const cleaned = normaliseCitedPath(rawPath);
  if (cleaned === "") {
    return { ok: false, reason: "file-not-found", detail: "empty path" };
  }
  if (cleaned.includes("\0")) {
    return { ok: false, reason: "path-escape", detail: "path contains a NUL byte" };
  }
  const root = path.resolve(targetDir);
  const absolute = path.isAbsolute(cleaned) ? path.resolve(cleaned) : path.resolve(root, cleaned);
  if (!isInside(root, absolute)) {
    return { ok: false, reason: "path-escape", detail: `${cleaned} resolves outside the target` };
  }
  return { ok: true, value: { absolute, relative: toPosix(path.relative(root, absolute)) } };
}
