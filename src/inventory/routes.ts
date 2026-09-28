/**
 * Phase 2 — the route inventory.
 *
 * Every HTTP entry point in the target, enumerated rather than sampled,
 * because `N of N handlers audited` is the claim the whole report rests on
 * and one unlisted route makes it false. Next.js app-router handlers and
 * server actions, pages-router API routes, Express/Fastify/Koa/Hono
 * registrations, NestJS controllers and tRPC procedures all become the same
 * thing: an `AuditUnit` of kind `route` with a `file:line` that phase 3 can
 * slice out of disk and paste into the audit prompt.
 *
 * Two rules shape everything here:
 *
 * - **A route that cannot be resolved is still a unit.** A path built from a
 *   variable, a router mounted through a value Sentinel cannot follow, a
 *   handler defined in another module — each is reported with
 *   `path: "unresolved"` and a note saying why. An unlisted route is a
 *   coverage lie; an honestly unresolved one is a question for the reader.
 * - **Structure comes from ast-grep, composition from TypeScript.** One search
 *   answers every framework's queries in a single process; the mounting,
 *   prefixing and decorator arithmetic that turns matches into paths happens
 *   here, where it can be read and tested.
 */

import type { AuditUnitKind } from "../contracts/inventory.ts";
import type { StackProfile } from "../contracts/profile.ts";
import { backendFrameworks } from "../profile/accessors.ts";
import type { StructuralRule } from "./_ast-grep.ts";
import {
  type RouteContext,
  type RouteDraft,
  UNRESOLVED_PATH,
  createRouteContext,
} from "./_route-frameworks/_shared.ts";
import { NEST_RULES, collectNestRoutes } from "./_route-frameworks/nest.ts";
import { NEXT_RULES, collectNextRoutes } from "./_route-frameworks/next.ts";
import { NODE_ROUTER_RULES, collectNodeRoutes } from "./_route-frameworks/node-routers.ts";
import { TRPC_RULES, collectTrpcRoutes } from "./_route-frameworks/trpc.ts";
import {
  type EnumerationContext,
  type EnumerationOutcome,
  type InventoryEnumerator,
  degraded,
  enumerated,
  joinReasons,
  notApplicable,
} from "./_unit-support.ts";

/** The kinds this enumerator owns. */
export const ROUTE_KINDS: readonly AuditUnitKind[] = ["route"];

/** Every structural query the route collectors need, answered by one search. */
export const ROUTE_RULES: readonly StructuralRule[] = [
  ...NEXT_RULES,
  ...NODE_ROUTER_RULES,
  ...NEST_RULES,
  ...TRPC_RULES,
];

/** One framework's collector, named so a failure can say which one failed. */
interface Collector {
  readonly name: string;
  collect(ctx: RouteContext): Promise<RouteDraft[]>;
}

/** The collectors, in the order their units are numbered. */
export const ROUTE_COLLECTORS: readonly Collector[] = [
  { name: "next", collect: collectNextRoutes },
  { name: "node-routers", collect: collectNodeRoutes },
  { name: "nestjs", collect: collectNestRoutes },
  { name: "trpc", collect: collectTrpcRoutes },
];

/**
 * Frameworks phase 0 proved are in use but that produced no unit here.
 *
 * Reported rather than ignored: "Fastify is a dependency and Sentinel
 * enumerated no Fastify route" is either a repository that declares what it
 * does not use, or an enumerator that missed something — and the reader is
 * entitled to know which of the two they are looking at.
 */
export function unenumeratedFrameworks(
  profile: StackProfile | undefined,
  drafts: readonly RouteDraft[],
): string[] {
  if (profile === undefined) return [];
  const found = new Set(
    drafts
      .map((draft) => draft.attributes.framework)
      .filter((name): name is string => name !== undefined),
  );
  return backendFrameworks(profile).filter(
    (framework) =>
      ![...found].some((name) => name === framework || name.startsWith(`${framework}-`)),
  );
}

/** Sorts drafts into the order two runs over unchanged code both produce. */
export function sortDrafts(drafts: readonly RouteDraft[]): RouteDraft[] {
  return [...drafts].sort(
    (left, right) =>
      left.file.localeCompare(right.file) ||
      left.line - right.line ||
      left.symbol.localeCompare(right.symbol),
  );
}

/**
 * Enumerates every HTTP entry point in the target.
 *
 * Never throws: a collector that fails costs its framework's routes and one
 * sentence in the enumerator report, not the phase.
 */
export async function enumerateRoutes(ctx: EnumerationContext): Promise<EnumerationOutcome> {
  if (ctx.snapshot.sourceFiles().length === 0) {
    return notApplicable("the repository contains no JavaScript or TypeScript source");
  }

  // The seam is not supposed to throw, but an enumerator that lets one escape
  // would cost the phase a kind; the contract here is "never throws".
  const found = await ctx.search.search(ROUTE_RULES).catch((error: unknown) => ({
    ok: false as const,
    matches: [],
    reason: `the structural search failed: ${
      error instanceof Error ? error.message : String(error)
    }`,
  }));
  if (!found.ok) {
    return degraded(
      [],
      found.reason ?? "the structural search did not run, so no route could be enumerated",
    );
  }

  const warnings: string[] = [];
  const routeContext = createRouteContext({
    snapshot: ctx.snapshot,
    matches: found.matches,
    ...(ctx.profile === undefined ? {} : { profile: ctx.profile }),
    warnings,
  });

  const drafts: RouteDraft[] = [];
  const failures: string[] = [];
  for (const collector of ROUTE_COLLECTORS) {
    try {
      drafts.push(...(await collector.collect(routeContext)));
    } catch (error) {
      failures.push(
        `${collector.name} routes could not be enumerated: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }

  const units = sortDrafts(drafts);
  const unresolved = units.filter((unit) => unit.attributes.path === UNRESOLVED_PATH).length;
  const missed = unenumeratedFrameworks(ctx.profile, units);
  const reason = joinReasons([
    ...failures,
    missed.length === 0
      ? undefined
      : `phase 0 detected ${missed.join(", ")} but no route of that framework was enumerated`,
    unresolved === 0
      ? undefined
      : `${unresolved} of ${units.length} route(s) could not be resolved to a path`,
    ...warnings,
  ]);

  if (failures.length > 0) {
    return degraded(units, reason ?? "one or more route collectors failed");
  }
  return enumerated(units, reason);
}

/** The phase 2 enumerator that owns route units. */
export const ROUTE_ENUMERATOR: InventoryEnumerator = {
  name: "routes",
  kinds: ROUTE_KINDS,
  enumerate: enumerateRoutes,
};

/** Registered by the aggregator; an array so it composes with the other groups. */
export const ROUTE_ENUMERATORS: readonly InventoryEnumerator[] = [ROUTE_ENUMERATOR];
