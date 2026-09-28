/**
 * The structural-search seam the inventory enumerators share.
 *
 * Every enumerator that has to find a *shape* in JS/TS — `new Worker(...)`,
 * `export const runtime = "edge"`, a `dangerouslySetInnerHTML` attribute —
 * expresses it as an ast-grep rule instead of a regular expression, because a
 * regex cannot tell a call from the same words inside a comment, and the
 * inventory is a coverage claim rather than a grep.
 *
 * Three things make this a seam rather than a helper:
 *
 * - **Rules are data.** A rule's body is a plain object serialised as JSON,
 *   which is valid YAML, so ast-grep reads it without this module ever
 *   generating indentation-sensitive text.
 * - **Output is untrusted.** ast-grep's JSON is parsed through a Zod schema;
 *   a match that does not fit the shape is dropped rather than trusted.
 * - **A missing tool degrades, it does not throw.** `search` reports
 *   `ok: false` with a sentence, and the enumerator turns that into a
 *   `degraded` outcome that the coverage table prints.
 */

import { z } from "zod";
import { DEFAULT_EXCLUDES } from "../scan/runners/opengrep.ts";

/** The name the tool lockfile knows this analyzer by. */
export const AST_GREP_TOOL = "ast-grep";

/** A structural search over a repository is seconds, not minutes. */
export const AST_GREP_DEFAULT_TIMEOUT_MS = 180_000;

/**
 * The ast-grep languages the inventory queries.
 *
 * They are separate parsers, not aliases: a rule declared for `TypeScript` is
 * never applied to a `.tsx` file, and JSX only parses under `Tsx` (for `.tsx`)
 * and `JavaScript` (for `.jsx`). A rule that should hold everywhere therefore
 * has to be emitted once per language, which {@link buildRuleDocument} does.
 */
export const AST_GREP_LANGUAGES = ["TypeScript", "Tsx", "JavaScript"] as const;
/** One of the ast-grep languages the inventory queries. */
export type AstGrepLanguage = (typeof AST_GREP_LANGUAGES)[number];

/** A value inside an ast-grep rule body. */
export type RuleValue = string | number | boolean | RuleObject | readonly RuleValue[];

/** An ast-grep rule body: `{ pattern: ... }`, `{ kind, has }`, `{ any: [...] }`. */
export interface RuleObject {
  readonly [key: string]: RuleValue;
}

/** One query: an id the caller recognises its matches by, and the rule itself. */
export interface StructuralRule {
  /** Returned on every match as `ruleId`; unique within one search. */
  readonly id: string;
  /** Languages to run it against. Defaults to every language in {@link AST_GREP_LANGUAGES}. */
  readonly languages?: readonly AstGrepLanguage[] | undefined;
  /** The rule body, exactly as ast-grep's rule schema defines it. */
  readonly rule: RuleObject;
}

/** One hit, normalised to the 1-based line numbers every `CodeRef` uses. */
export interface StructuralMatch {
  /** The `id` of the rule that matched. */
  readonly ruleId: string;
  /** Repo-relative POSIX path. */
  readonly file: string;
  /** 1-based first line of the matched node. */
  readonly line: number;
  /** 1-based last line of the matched node; equal to `line` for a single-line match. */
  readonly endLine: number;
  /** The matched source text, as written. */
  readonly text: string;
  /** Single meta variables: `$NAME` to the text it captured. */
  readonly vars: Readonly<Record<string, string>>;
  /** Multi meta variables: `$$$ARGS` to its captures, with separators removed. */
  readonly lists: Readonly<Record<string, readonly string[]>>;
}

/** What a search returns: the matches, or the reason there are none to trust. */
export interface StructuralSearchResult {
  /** False when the search could not run; `matches` is then empty. */
  readonly ok: boolean;
  /** Every match, sorted by file, line, column and rule id. */
  readonly matches: readonly StructuralMatch[];
  /** Why the search did not run, or what was lost when it did. */
  readonly reason?: string | undefined;
}

/** The structural search an enumerator is handed; faked wholesale in unit tests. */
export interface StructuralSearch {
  /** Runs the rules over the target repository; never throws. */
  search(rules: readonly StructuralRule[]): Promise<StructuralSearchResult>;
}

/** The slice of `src/ports/process-executor.ts` this driver depends on. */
export interface AstGrepProcessExecutor {
  run(
    command: string,
    args?: readonly string[],
    options?: {
      readonly cwd?: string;
      readonly timeoutMs?: number;
      readonly maxOutputBytes?: number;
      readonly signal?: AbortSignal;
    },
  ): Promise<{
    readonly exitCode: number;
    readonly stdout: string;
    readonly stderr: string;
    readonly timedOut: boolean;
    readonly truncated: boolean;
    readonly notFound: boolean;
  }>;
}

/** The slice of `src/tools/resolve.ts#ToolResolver` this driver depends on. */
export interface AstGrepToolResolver {
  resolve(name: string, options?: { allowPath?: boolean }): Promise<string | null>;
}

/** Everything {@link createAstGrepSearch} needs. */
export interface AstGrepSearchDeps {
  readonly exec: AstGrepProcessExecutor;
  readonly tools: AstGrepToolResolver;
  /** Absolute path of the repository under analysis; also the child's cwd. */
  readonly targetDir: string;
  /** Allow a tool found on PATH when the pinned build is not cached. Default false. */
  readonly allowPathTools?: boolean | undefined;
  readonly timeoutMs?: number | undefined;
  readonly signal?: AbortSignal | undefined;
}

// ---------------------------------------------------------------------------
// ast-grep's JSON, treated as the external payload it is
// ---------------------------------------------------------------------------

const PositionSchema = z.object({
  line: z.number().int().nonnegative(),
  column: z.number().int().nonnegative(),
});

const MetaVariableSchema = z.object({ text: z.string() });

/**
 * One element of `ast-grep scan --json`.
 *
 * `metaVariables` is absent for a rule that binds none (a `kind`-only rule),
 * and `ruleId` is absent for `ast-grep run`, which this driver never calls —
 * both are optional so a shape change degrades one match instead of the run.
 */
const AstGrepMatchSchema = z.object({
  text: z.string(),
  file: z.string(),
  range: z.object({ start: PositionSchema, end: PositionSchema }),
  ruleId: z.string().optional(),
  metaVariables: z
    .object({
      single: z.record(z.string(), MetaVariableSchema).optional(),
      multi: z.record(z.string(), z.array(MetaVariableSchema)).optional(),
    })
    .optional(),
});

const AstGrepOutputSchema = z.array(AstGrepMatchSchema);

// ---------------------------------------------------------------------------
// Building the invocation
// ---------------------------------------------------------------------------

/**
 * The rules as one `--inline-rules` document.
 *
 * Each rule becomes one YAML document per language, and every document is
 * written as JSON — which YAML accepts verbatim — so a pattern containing a
 * colon, a quote or a newline cannot corrupt the document.
 */
export function buildRuleDocument(rules: readonly StructuralRule[]): string {
  const documents: string[] = [];
  for (const rule of rules) {
    const languages = rule.languages ?? AST_GREP_LANGUAGES;
    for (const language of languages) {
      documents.push(JSON.stringify({ id: rule.id, language, rule: rule.rule }));
    }
  }
  return documents.join("\n---\n");
}

/**
 * Path globs that keep the search on first-party source.
 *
 * ast-grep honours `.gitignore`, but a repository that does not ignore its own
 * build output would otherwise have `dist/` enumerated as if a developer had
 * written it. The exclusions are phase 1's, so the two phases disagree about
 * what counts as the customer's code in exactly zero places.
 */
export function excludeGlobs(): string[] {
  return DEFAULT_EXCLUDES.map((entry) =>
    entry.includes("*") ? `!**/${entry}` : `!**/${entry}/**`,
  );
}

/** The argument list for one search; the target is `.` so match paths stay relative. */
export function astGrepArgs(ruleDocument: string): string[] {
  const args = ["scan", "--inline-rules", ruleDocument, "--json=compact", "--color", "never"];
  for (const glob of excludeGlobs()) args.push("--globs", glob);
  args.push(".");
  return args;
}

/** Drops the `,` separators ast-grep reports between `$$$` captures. */
function captures(list: ReadonlyArray<{ text: string }> | undefined): string[] {
  return (list ?? []).map((item) => item.text).filter((text) => text !== "," && text !== "");
}

/** Normalises one ast-grep match, or null when it carries no rule id. */
function toMatch(raw: z.infer<typeof AstGrepMatchSchema>): StructuralMatch | null {
  if (raw.ruleId === undefined) return null;
  const vars: Record<string, string> = {};
  for (const [name, value] of Object.entries(raw.metaVariables?.single ?? {})) {
    vars[name] = value.text;
  }
  const lists: Record<string, readonly string[]> = {};
  for (const [name, value] of Object.entries(raw.metaVariables?.multi ?? {})) {
    lists[name] = captures(value);
  }
  const line = raw.range.start.line + 1;
  return {
    ruleId: raw.ruleId,
    file: raw.file.replace(/^\.\//, ""),
    line,
    endLine: Math.max(line, raw.range.end.line + 1),
    text: raw.text,
    vars,
    lists,
  };
}

/** Sorts matches into an order two runs over unchanged code both produce. */
function sortMatches(matches: StructuralMatch[]): StructuralMatch[] {
  return matches.sort(
    (left, right) =>
      left.file.localeCompare(right.file) ||
      left.line - right.line ||
      left.ruleId.localeCompare(right.ruleId) ||
      left.text.localeCompare(right.text),
  );
}

/**
 * Parses one ast-grep payload. Exported because "the tool printed something we
 * do not recognise" is a case worth testing without spawning anything.
 */
export function parseAstGrepOutput(stdout: string): StructuralSearchResult {
  const trimmed = stdout.trim();
  if (trimmed === "") return { ok: true, matches: [] };
  let payload: unknown;
  try {
    payload = JSON.parse(trimmed);
  } catch {
    return { ok: false, matches: [], reason: "ast-grep output is not JSON" };
  }
  const parsed = AstGrepOutputSchema.safeParse(payload);
  if (!parsed.success) {
    return { ok: false, matches: [], reason: "ast-grep output did not match the expected shape" };
  }
  const matches: StructuralMatch[] = [];
  for (const raw of parsed.data) {
    const match = toMatch(raw);
    if (match !== null) matches.push(match);
  }
  return { ok: true, matches: sortMatches(matches) };
}

/**
 * Builds the structural search backed by the pinned ast-grep binary.
 *
 * One process per call, with every rule in it: the enumerators ask a handful of
 * questions each, and one scan of the repository answers all of them faster
 * than a process per pattern ever could.
 */
export function createAstGrepSearch(deps: AstGrepSearchDeps): StructuralSearch {
  return {
    async search(rules: readonly StructuralRule[]): Promise<StructuralSearchResult> {
      if (rules.length === 0) return { ok: true, matches: [] };

      const binary = await deps.tools.resolve(AST_GREP_TOOL, {
        allowPath: deps.allowPathTools ?? false,
      });
      if (binary === null) {
        return {
          ok: false,
          matches: [],
          reason: `${AST_GREP_TOOL} is not installed; run "sentinel setup" to enable structural enumeration`,
        };
      }

      const result = await deps.exec.run(binary, astGrepArgs(buildRuleDocument(rules)), {
        cwd: deps.targetDir,
        timeoutMs: deps.timeoutMs ?? AST_GREP_DEFAULT_TIMEOUT_MS,
        ...(deps.signal === undefined ? {} : { signal: deps.signal }),
      });

      if (result.notFound) {
        return { ok: false, matches: [], reason: `${AST_GREP_TOOL} could not be executed` };
      }
      if (result.timedOut) {
        return { ok: false, matches: [], reason: `${AST_GREP_TOOL} timed out` };
      }
      if (result.truncated) {
        return {
          ok: false,
          matches: [],
          reason: `${AST_GREP_TOOL} output exceeded the capture cap`,
        };
      }
      if (result.exitCode !== 0) {
        const detail = result.stderr.replace(/\s+/g, " ").trim().slice(0, 200);
        return {
          ok: false,
          matches: [],
          reason: `${AST_GREP_TOOL} exited ${result.exitCode}${detail === "" ? "" : `: ${detail}`}`,
        };
      }
      return parseAstGrepOutput(result.stdout);
    },
  };
}

/** A search that finds nothing, for a repository with no JS/TS to enumerate. */
export function emptySearch(reason: string): StructuralSearch {
  return { search: async () => ({ ok: false, matches: [], reason }) };
}
