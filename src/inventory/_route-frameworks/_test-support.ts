/**
 * Shared setup for the route-enumerator tests.
 *
 * The enumeration is run **once**, against the real fixture repository, with
 * the real pinned ast-grep: these tests are the only proof that the rules
 * actually match the code they claim to, so a stubbed parser would test
 * nothing worth testing. The result is memoised, so twenty assertions cost one
 * process.
 */

import { join } from "node:path";
import type { StackProfile } from "../../contracts/profile.ts";
import { createFileSystem } from "../../ports/file-system.ts";
import { createProcessExecutor } from "../../ports/process-executor.ts";
import { RepoSnapshot } from "../../profile/repo-snapshot.ts";
import { resolveTool } from "../../tools/resolve.ts";
import { AST_GREP_TOOL, createAstGrepSearch } from "../_ast-grep.ts";
import type { DraftUnit, EnumerationContext, EnumerationOutcome } from "../_unit-support.ts";
import { enumerateRoutes } from "../routes.ts";

/** Absolute path of the multi-framework fixture repository. */
export function routeTarget(): string {
  return join(import.meta.dir, "..", "__fixtures__", "route-target");
}

/** The pinned ast-grep, or null when the tool cache has not been populated. */
export async function astGrepBinary(): Promise<string | null> {
  return await resolveTool(AST_GREP_TOOL);
}

let memoised: Promise<EnumerationOutcome> | undefined;

/** Runs the real enumeration over the fixture repository, once per process. */
export function enumerateFixture(profile?: StackProfile): Promise<EnumerationOutcome> {
  if (profile === undefined && memoised !== undefined) return memoised;
  const target = routeTarget();
  const fs = createFileSystem();
  const exec = createProcessExecutor();
  const tools = { resolve: (name: string) => resolveTool(name) };
  const run = (async (): Promise<EnumerationOutcome> => {
    const snapshot = await RepoSnapshot.create(fs, target);
    const context: EnumerationContext = {
      fs,
      exec,
      tools,
      targetDir: target,
      runDir: join(target, "out"),
      runId: "test",
      snapshot,
      search: createAstGrepSearch({ exec, tools, targetDir: target }),
      ...(profile === undefined ? {} : { profile }),
    };
    return await enumerateRoutes(context);
  })();
  if (profile === undefined) memoised = run;
  return run;
}

/** The unit with this label, or `undefined` when the enumeration missed it. */
export function unitLabelled(outcome: EnumerationOutcome, label: string): DraftUnit | undefined {
  return outcome.units.find((unit) => unit.label === label);
}

/** Every unit label the enumeration produced, sorted. */
export function labelsOf(outcome: EnumerationOutcome): string[] {
  return outcome.units.map((unit) => unit.label).sort();
}

/** Units from one file, in source order. */
export function unitsIn(outcome: EnumerationOutcome, file: string): DraftUnit[] {
  return outcome.units.filter((unit) => unit.file === file);
}
