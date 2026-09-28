/**
 * Test harness for the phase 2 enumerators.
 *
 * Reads go through the real filesystem port against the fixture repositories in
 * this directory, so every line number an assertion checks was read from a file
 * that actually exists; writes are captured in memory, so a test run never
 * leaves an `inventory.json` behind.
 *
 * Two ways to drive a structural search:
 *
 * - {@link stubSearch} hands the enumerator a fixed list of matches, which is
 *   how the attribute extraction is tested without a binary.
 * - {@link realSearch} drives the pinned ast-grep over a fixture, which is how
 *   the *rules* are tested — a pattern that does not match real code is a bug
 *   no stub can catch. Tests that use it skip when the tool is not installed.
 */

import { join } from "node:path";
import { createFileSystem } from "../../ports/file-system.ts";
import { createProcessExecutor } from "../../ports/process-executor.ts";
import { RepoSnapshot } from "../../profile/repo-snapshot.ts";
import { readToolsLock } from "../../tools/installer.ts";
import { createToolResolver } from "../../tools/resolve.ts";
import {
  AST_GREP_TOOL,
  type StructuralMatch,
  type StructuralSearch,
  createAstGrepSearch,
} from "../_ast-grep.ts";
import type {
  EnumerationContext,
  InventoryContext,
  InventoryFileSystem,
} from "../_unit-support.ts";

/** The fixture repositories this directory holds for phase 2. */
export type FixtureName = "alias-target" | "async-target" | "client-target" | "data-layer-target";

/** Absolute path of one of the fixture repositories. */
export function fixtureRepo(name: FixtureName): string {
  return join(import.meta.dir, name);
}

/** One captured write, so a test can assert what the phase produced. */
export interface RecordedWrite {
  readonly path: string;
  readonly content: string;
}

/** A filesystem whose reads are real and whose writes go nowhere. */
export interface HarnessFileSystem extends InventoryFileSystem {
  readonly writes: RecordedWrite[];
}

/** Builds the capturing filesystem; the return type keeps the port slice honest. */
export function harnessFileSystem(): HarnessFileSystem {
  const real = createFileSystem();
  const writes: RecordedWrite[] = [];
  return {
    writes,
    readFile: (path) => real.readFile(path),
    readFileBytes: (path) => real.readFileBytes(path),
    readDir: (path) => real.readDir(path),
    exists: (path) => real.exists(path),
    realpath: (path) => real.realpath(path),
    async writeFile(path: string, data: string | Uint8Array): Promise<void> {
      writes.push({
        path,
        content: typeof data === "string" ? data : new TextDecoder().decode(data),
      });
    },
  };
}

/** A structural search that returns exactly what a test says it does. */
export function stubSearch(
  matches: readonly StructuralMatch[],
  ok = true,
  reason?: string,
): StructuralSearch {
  return {
    async search() {
      return { ok, matches, ...(reason === undefined ? {} : { reason }) };
    },
  };
}

/** Builds one match; every field a rule does not bind has a harmless default. */
export function match(partial: Partial<StructuralMatch> & { ruleId: string }): StructuralMatch {
  const line = partial.line ?? 1;
  return {
    ruleId: partial.ruleId,
    file: partial.file ?? "src/index.ts",
    line,
    endLine: partial.endLine ?? line,
    text: partial.text ?? "",
    vars: partial.vars ?? {},
    lists: partial.lists ?? {},
  };
}

/** Absolute path of the pinned ast-grep, or null when it is not installed. */
export async function astGrepPath(): Promise<string | null> {
  const resolver = createToolResolver({ lock: await readToolsLock(), fs: createFileSystem() });
  return resolver.resolve(AST_GREP_TOOL);
}

/** The real structural search over a fixture repository. */
export async function realSearch(targetDir: string): Promise<StructuralSearch> {
  const resolver = createToolResolver({ lock: await readToolsLock(), fs: createFileSystem() });
  return createAstGrepSearch({
    exec: createProcessExecutor(),
    tools: resolver,
    targetDir,
    timeoutMs: 60_000,
  });
}

/** The inventory context for a fixture; writes are captured, reads are real. */
export function inventoryContext(
  targetDir: string,
  overrides: Partial<InventoryContext> = {},
): InventoryContext & { fs: HarnessFileSystem } {
  const { fs, ...rest } = overrides;
  return {
    exec: createProcessExecutor(),
    tools: { resolve: async () => null },
    targetDir,
    runDir: "/tmp/sentinel-inventory-test",
    runId: "test-run",
    ...rest,
    fs: (fs as HarnessFileSystem | undefined) ?? harnessFileSystem(),
  };
}

/** The enumeration context for a fixture, with the snapshot and search filled in. */
export async function enumerationContext(
  targetDir: string,
  search: StructuralSearch,
  overrides: Partial<InventoryContext> = {},
): Promise<EnumerationContext> {
  const base = inventoryContext(targetDir, overrides);
  const snapshot = await RepoSnapshot.create(base.fs, targetDir);
  return { ...base, snapshot, search };
}
