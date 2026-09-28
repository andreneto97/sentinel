/**
 * Phase 2 — what the browser decides, and where untrusted input can land (D2).
 *
 * Two kinds of unit live here, and they exist for the same reason: an audit
 * can only prove something about code it was handed.
 *
 * - **Role gates.** Every place the frontend decides what a user may do — an
 *   `isAdmin` flag, `role === "admin"`, `permissions.includes(...)`, a
 *   `<RequireRole>` wrapper. On their own they are not findings; a hidden
 *   button is a UX decision. They become findings when the endpoint behind
 *   them performs no check of its own, which is the single most common
 *   authorization bug in a React/Next codebase. Enumerating them, with the
 *   endpoint each gated action calls, is what turns "authorization decided in
 *   the browser" from a sentence in a report into something phase 4 can check
 *   handler by handler.
 * - **Sinks.** Where a string becomes markup, SQL, a shell command or code.
 *   Each one is recorded with the symbol that encloses it, so the audit can
 *   ask whether user input reaches it rather than guessing from a grep.
 *
 * Sinks are enumerated across the whole repository — SQL and command sinks are
 * backend code — while role gates are only looked for on the client surface,
 * because a role check inside a route handler is server-side authorization and
 * belongs to the route inventory instead.
 */

import { basename } from "node:path";
import { ATTRIBUTE } from "../contracts/inventory.ts";
import { hasFrontend } from "../profile/accessors.ts";
import { importPattern } from "../profile/text.ts";
import type { StructuralMatch, StructuralRule } from "./_ast-grep.ts";
import {
  type DraftUnit,
  type EnumerationContext,
  type EnumerationOutcome,
  type InventoryEnumerator,
  MAX_UNITS_PER_ENUMERATOR,
  brief,
  contentSymbol,
  enclosingSymbol,
  finishOutcome,
  literalOf,
  notApplicable,
} from "./_unit-support.ts";

/** How far below a gate an action is still considered part of it. */
const ACTION_WINDOW = 40;

/** How far below a gate a UI element still counts as the thing it hides. */
const ELEMENT_WINDOW = 12;

/** Rule ids for the structural queries this file runs. */
const RULE = {
  roleCompare: "role-compare",
  roleCall: "role-call",
  roleFlag: "role-flag",
  roleWrapper: "role-wrapper",
  sinkJsxHtml: "sink-jsx-html",
  sinkDomHtml: "sink-dom-html",
  sinkEval: "sink-eval",
  sinkSqlUnsafe: "sink-sql-unsafe",
  sinkSqlQuery: "sink-sql-query",
  sinkCommand: "sink-command",
  sinkRedirect: "sink-redirect",
} as const;

// ---------------------------------------------------------------------------
// Client surface
// ---------------------------------------------------------------------------

/** Directories whose contents are rendered in a browser or a native client. */
const CLIENT_DIRECTORIES =
  /(^|\/)(components?|ui|views?|screens?|containers?|features?|pages|app|src\/app|web|client|mobile|frontend)(\/|$)/;

/** Server code that can sit in the same tree, and is never the client surface. */
const SERVER_PATH =
  /(^|\/)(api|server|routes?|handlers?|services?|lib\/server)(\/|$)|\.server\.[cm]?[jt]sx?$/;

/** A file the browser runs: by extension, by directive, or by where it sits. */
export function isClientFile(file: string, source: string): boolean {
  if (SERVER_PATH.test(file) && !/\.(tsx|jsx|vue|svelte)$/.test(file)) return false;
  if (/\.(tsx|jsx|vue|svelte)$/.test(file)) return true;
  if (/^\s*["']use client["']/m.test(source)) return true;
  return CLIENT_DIRECTORIES.test(file);
}

/** Role and permission checks, as the shapes they take in real components. */
const ROLE_RULES: readonly StructuralRule[] = [
  {
    id: RULE.roleCompare,
    rule: {
      any: [
        { pattern: "$A.role === $B" },
        { pattern: "$A.role !== $B" },
        { pattern: "$A.role == $B" },
        { pattern: "$A.role != $B" },
        { pattern: "$A.roles === $B" },
        { pattern: "$A.type === $B" },
        { pattern: "$A.userRole === $B" },
      ],
    },
  },
  {
    id: RULE.roleCall,
    rule: {
      any: [
        { pattern: "$A.permissions.includes($B)" },
        { pattern: "$A.roles.includes($B)" },
        { pattern: "$A.scopes.includes($B)" },
        { pattern: "$A.hasRole($$$B)" },
        { pattern: "$A.hasPermission($$$B)" },
        { pattern: "$A.can($$$B)" },
        { pattern: "hasRole($$$B)" },
        { pattern: "hasPermission($$$B)" },
        { pattern: "isAdmin($$$B)" },
        { pattern: "useRole($$$B)" },
        { pattern: "usePermission($$$B)" },
      ],
    },
  },
  {
    id: RULE.roleFlag,
    rule: {
      kind: "variable_declarator",
      has: { field: "name", regex: "^(is|can|has|allow|may)[A-Z]" },
    },
  },
  {
    id: RULE.roleWrapper,
    languages: ["Tsx", "JavaScript"],
    rule: {
      kind: "jsx_opening_element",
      has: {
        field: "name",
        regex:
          "^(RequireRole|RequirePermission|ProtectedRoute|RoleGuard|PermissionGuard|AdminOnly|Authorized|Restricted|IfAllowed|Can|Gate|Protected)$",
      },
    },
  },
];

/** Names that mark a flag as an authorization decision rather than a UI state. */
const ROLE_FLAG_SUBJECT =
  /\b(admin|owner|editor|manager|staff|superuser|moderator|role|permission|access|edit|delete|approve|publish|manage|write|create|update)\b/i;

/** A call that reaches the backend, with the path it reaches. */
const ACTION_CALL =
  /(?:fetch|axios(?:\.\w+)?|api(?:\.\w+)?|client(?:\.\w+)?|\$fetch|useSWR|mutate)\s*\(\s*[`'"]([^`'"]*)[`'"]/;

/** A JSX element opening, so a gate can name what it hides. */
const JSX_ELEMENT = /<([A-Za-z][\w.]*)\b/;

/** Layout elements that are the page around a gate rather than the thing it hides. */
const LAYOUT_ELEMENT =
  /^(div|span|section|article|main|aside|header|footer|nav|ul|ol|li|p|br|hr|table|tbody|tr|td|th|Fragment)$/;

/** The first backend call below a gate, which is the action the gate protects. */
export function nearbyEndpoint(lines: readonly string[], line: number): string | undefined {
  for (let index = line - 1; index < Math.min(lines.length, line + ACTION_WINDOW); index += 1) {
    const text = lines[index];
    if (text === undefined) continue;
    const path = ACTION_CALL.exec(text)?.[1];
    if (path === undefined) continue;
    if (path.startsWith("/")) return path;
  }
  return undefined;
}

/** The first element below a gate, which is what the gate shows or hides. */
export function nearbyElement(lines: readonly string[], line: number): string | undefined {
  let layout: string | undefined;
  for (let index = line - 1; index < Math.min(lines.length, line + ELEMENT_WINDOW); index += 1) {
    const text = lines[index];
    if (text === undefined) continue;
    const element = JSX_ELEMENT.exec(text)?.[1];
    if (element === undefined) continue;
    if (!LAYOUT_ELEMENT.test(element)) return element;
    layout ??= element;
  }
  return layout;
}

/**
 * One gate per line, the widest expression winning.
 *
 * `const canEdit = user.role === "admin"` matches two rules — the declaration
 * and the comparison inside it — and they are one decision, not two. Counting
 * both would inflate the coverage denominator with duplicates, so the longer
 * match is kept: it is the one that also carries the name the rest of the
 * component reads.
 */
export function widestPerLine(matches: readonly StructuralMatch[]): StructuralMatch[] {
  const widest = new Map<string, StructuralMatch>();
  for (const match of matches) {
    const key = `${match.file}:${match.line}`;
    const current = widest.get(key);
    if (current === undefined || match.text.length > current.text.length) widest.set(key, match);
  }
  return [...widest.values()];
}

/** The role or permission a gate tests, when it is written as a literal. */
function subjectOf(match: StructuralMatch): string | undefined {
  const direct = literalOf(match.vars.B);
  if (direct !== undefined) return direct;
  const quoted = /['"`]([^'"`]{1,60})['"`]/.exec(match.text);
  return quoted?.[1];
}

/** Enumerates every authorization decision the browser makes. */
export const roleGateEnumerator: InventoryEnumerator = {
  name: "role-gates",
  kinds: ["role-gate"],
  async enumerate(ctx: EnumerationContext): Promise<EnumerationOutcome> {
    if (ctx.profile !== undefined && !hasFrontend(ctx.profile)) {
      return notApplicable("phase 0 found no frontend, so there is no client-side gate to check");
    }
    const found = await ctx.search.search(ROLE_RULES);
    const notes: string[] = [];
    if (!found.ok && found.reason !== undefined) notes.push(found.reason);

    const units: DraftUnit[] = [];
    for (const match of widestPerLine(found.matches)) {
      const source = await ctx.snapshot.read(match.file);
      if (source === undefined) continue;
      if (!isClientFile(match.file, source)) continue;
      if (match.ruleId === RULE.roleFlag && !ROLE_FLAG_SUBJECT.test(match.text)) continue;

      const lines = (await ctx.snapshot.lines(match.file)) ?? [];
      const symbol = enclosingSymbol(lines, match.line);
      const expression = brief(match.text, 120);
      const subject = subjectOf(match);

      units.push({
        kind: "role-gate",
        label: `${symbol ?? basename(match.file)}: ${brief(match.text, 60)}`,
        file: match.file,
        line: match.line,
        endLine: match.endLine,
        symbol: `gate:${contentSymbol("g", `${symbol ?? ""}:${expression}`)}`,
        attributes: {
          expression,
          check: match.ruleId,
          subject,
          [ATTRIBUTE.symbol]: symbol,
          uiElement: nearbyElement(lines, match.line),
          endpoint: nearbyEndpoint(lines, match.line),
          [ATTRIBUTE.path]: nearbyEndpoint(lines, match.line),
        },
      });
    }

    return finishOutcome(units, {
      notes,
      searchOk: found.ok,
      emptyReason: "the client surface makes no role or permission check",
    });
  },
};

// ---------------------------------------------------------------------------
// Sinks
// ---------------------------------------------------------------------------

/** What a sink does with the string it is handed. */
type SinkType = "xss" | "eval" | "sql" | "command" | "redirect";

/** One sink rule, and what a match of it means. */
interface SinkSignal {
  readonly ruleId: string;
  readonly type: SinkType;
  /** Packages the file must import for the match to be believed. */
  readonly packages?: readonly string[] | undefined;
  /** Only record the sink when its argument is not a literal. */
  readonly dynamicOnly?: boolean | undefined;
}

const SINK_RULES: readonly StructuralRule[] = [
  {
    id: RULE.sinkJsxHtml,
    languages: ["Tsx", "JavaScript"],
    rule: {
      pattern: {
        context: "<div dangerouslySetInnerHTML={$VALUE} />",
        selector: "jsx_attribute",
      },
    },
  },
  {
    id: RULE.sinkDomHtml,
    rule: {
      any: [
        { pattern: "$X.innerHTML = $VALUE" },
        { pattern: "$X.outerHTML = $VALUE" },
        { pattern: "$X.insertAdjacentHTML($$$ARGS)" },
        { pattern: "document.write($$$ARGS)" },
        { pattern: "$X.html($VALUE)" },
      ],
    },
  },
  {
    id: RULE.sinkEval,
    rule: { any: [{ pattern: "eval($$$ARGS)" }, { pattern: "new Function($$$ARGS)" }] },
  },
  {
    id: RULE.sinkSqlUnsafe,
    rule: {
      any: [
        { pattern: "$X.$queryRawUnsafe($$$ARGS)" },
        { pattern: "$X.$executeRawUnsafe($$$ARGS)" },
        { pattern: "$X.raw($$$ARGS)" },
      ],
    },
  },
  {
    id: RULE.sinkSqlQuery,
    rule: {
      any: [
        { pattern: "$X.query($$$ARGS)" },
        { pattern: "$X.execute($$$ARGS)" },
        { pattern: "$X.$queryRaw($$$ARGS)" },
      ],
    },
  },
  {
    id: RULE.sinkCommand,
    rule: {
      any: [
        { pattern: "exec($$$ARGS)" },
        { pattern: "execSync($$$ARGS)" },
        { pattern: "execFile($$$ARGS)" },
        { pattern: "spawn($$$ARGS)" },
        { pattern: "spawnSync($$$ARGS)" },
        { pattern: "$X.exec($$$ARGS)" },
        { pattern: "$X.execSync($$$ARGS)" },
      ],
    },
  },
  {
    id: RULE.sinkRedirect,
    rule: {
      any: [{ pattern: "$X.redirect($$$ARGS)" }, { pattern: "redirect($$$ARGS)" }],
    },
  },
];

const SINK_SIGNALS: readonly SinkSignal[] = [
  { ruleId: RULE.sinkJsxHtml, type: "xss" },
  { ruleId: RULE.sinkDomHtml, type: "xss" },
  { ruleId: RULE.sinkEval, type: "eval" },
  { ruleId: RULE.sinkSqlUnsafe, type: "sql" },
  { ruleId: RULE.sinkSqlQuery, type: "sql", dynamicOnly: true },
  {
    ruleId: RULE.sinkCommand,
    type: "command",
    packages: ["child_process", "node:child_process", "execa", "shelljs"],
  },
  { ruleId: RULE.sinkRedirect, type: "redirect", dynamicOnly: true },
];

/** `v-html` and Svelte's `{@html}`, in templates no JS parser reads. */
const TEMPLATE_SINK = /\bv-html\b|\{@html\s/;

/** The API a matched sink calls, for the attribute a reader scans first. */
function apiOf(match: StructuralMatch): string {
  const attribute = /^([A-Za-z_$][\w$]*)=/.exec(match.text.trim())?.[1];
  if (attribute !== undefined) return attribute;
  const call = /([\w$.]+)\s*\(/.exec(match.text)?.[1];
  if (call !== undefined) return call.split(".").slice(-2).join(".");
  const assignment = /\.(\w+)\s*=/.exec(match.text)?.[1];
  if (assignment !== undefined) return assignment;
  return match.ruleId;
}

/** The argument a sink is handed: the value assigned, or the first call argument. */
function argumentOf(match: StructuralMatch): string | undefined {
  return match.vars.VALUE ?? match.lists.ARGS?.[0];
}

/**
 * True when the sink is handed something other than a fixed string.
 *
 * This is the whole reason the sink is in the inventory: a literal cannot
 * carry user input, so a dynamic argument is what phase 4 has to trace.
 */
export function isDynamic(argument: string | undefined): boolean {
  if (argument === undefined) return true;
  if (literalOf(argument) !== undefined) return false;
  return true;
}

/** Enumerates every place a string becomes markup, SQL, a command or code. */
export const sinkEnumerator: InventoryEnumerator = {
  name: "sinks",
  kinds: ["sink"],
  async enumerate(ctx: EnumerationContext): Promise<EnumerationOutcome> {
    const found = await ctx.search.search(SINK_RULES);
    const notes: string[] = [];
    if (!found.ok && found.reason !== undefined) notes.push(found.reason);
    const byRule = new Map(SINK_SIGNALS.map((signal) => [signal.ruleId, signal]));
    const units: DraftUnit[] = [];

    for (const match of found.matches) {
      const signal = byRule.get(match.ruleId);
      if (signal === undefined) continue;
      const argument = argumentOf(match);
      const dynamic = isDynamic(argument);
      if (signal.dynamicOnly === true && !dynamic) continue;
      if (signal.packages !== undefined) {
        const source = await ctx.snapshot.read(match.file);
        if (source === undefined) continue;
        if (!signal.packages.some((name) => importPattern(name).test(source))) continue;
      }
      const lines = (await ctx.snapshot.lines(match.file)) ?? [];
      const symbol = enclosingSymbol(lines, match.line);
      const api = apiOf(match);

      units.push({
        kind: "sink",
        label: `${api} in ${symbol ?? basename(match.file)}`,
        file: match.file,
        line: match.line,
        endLine: match.endLine,
        symbol: `sink:${contentSymbol("k", `${symbol ?? ""}:${match.text}`)}`,
        attributes: {
          sinkType: signal.type,
          api,
          [ATTRIBUTE.symbol]: symbol,
          dynamic: dynamic ? "yes" : "no",
          argument: argument === undefined ? undefined : brief(argument, 120),
          expression: brief(match.text, 160),
        },
      });
    }

    for (const hit of await ctx.snapshot.grep(TEMPLATE_SINK, {
      files: ctx.snapshot.filesMatching(/\.(vue|svelte)$/),
      limit: MAX_UNITS_PER_ENUMERATOR,
    })) {
      units.push({
        kind: "sink",
        label: `template html in ${basename(hit.file)}`,
        file: hit.file,
        line: hit.line,
        symbol: `sink:${contentSymbol("k", hit.text)}`,
        attributes: {
          sinkType: "xss",
          api: hit.text.includes("v-html") ? "v-html" : "{@html}",
          dynamic: "yes",
          expression: brief(hit.text, 160),
        },
      });
    }

    return finishOutcome(units, {
      notes,
      searchOk: found.ok,
      emptyReason: "no injection or XSS sink was found",
    });
  },
};

/** Every client-surface enumerator, in the order the aggregator registers them. */
export const CLIENT_SURFACE_ENUMERATORS: readonly InventoryEnumerator[] = [
  roleGateEnumerator,
  sinkEnumerator,
];
