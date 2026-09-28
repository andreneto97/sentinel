/**
 * ast-grep driver for the inventory phase.
 *
 * Every structural question the data-access and migration inventories ask is
 * expressed as an ast-grep rule and answered in one pass over the target: the
 * call sites themselves, and the ranges (functions, loops, transactions,
 * blocks) that give each call site its context. Nothing here matches source
 * text with a regular expression — the rules are the query language.
 *
 * Rules are emitted as JSON documents joined by `---`, which is valid YAML, so
 * a pattern containing quotes, backticks or `$` needs no escaping dance.
 */

import { z } from "zod";

/** The pinned analyzer this module drives; resolved through `src/tools/resolve.ts`. */
export const AST_GREP_TOOL = "ast-grep";

/**
 * The three grammars a JS/TS repository needs. ast-grep picks a grammar per
 * file extension, so the same rule is emitted once per language: `TypeScript`
 * cannot parse `.tsx` and `Tsx` is not applied to `.ts`.
 */
export const AST_LANGUAGES = ["TypeScript", "Tsx", "JavaScript"] as const;
/** One of the grammars the inventory queries; see {@link AST_LANGUAGES}. */
export type AstLanguage = (typeof AST_LANGUAGES)[number];

/** Directories that are never first-party source, excluded from every pass. */
export const DEFAULT_EXCLUDE_GLOBS: readonly string[] = [
  "!**/node_modules/**",
  "!**/dist/**",
  "!**/build/**",
  "!**/.next/**",
  "!**/.nuxt/**",
  "!**/.output/**",
  "!**/coverage/**",
  "!**/vendor/**",
  "!**/*.min.js",
  "!**/*.bundle.js",
];

/** A structural query: an ast-grep rule body plus the metavariable constraints it needs. */
export interface AstRule {
  /** Identifies the rule in the output; the extractor reads it back. */
  readonly id: string;
  /** The `rule:` body, exactly as ast-grep's YAML schema defines it. */
  readonly rule: Readonly<Record<string, unknown>>;
  /** The `constraints:` body, keyed by metavariable name. */
  readonly constraints?: Readonly<Record<string, unknown>> | undefined;
  /** Grammars this rule applies to. Defaults to all three. */
  readonly languages?: readonly AstLanguage[] | undefined;
}

/** Serialises the rule set into the `--inline-rules` document ast-grep expects. */
export function renderInlineRules(rules: readonly AstRule[]): string {
  const documents: string[] = [];
  for (const rule of rules) {
    for (const language of rule.languages ?? AST_LANGUAGES) {
      documents.push(
        JSON.stringify({
          id: rule.id,
          language,
          severity: "info",
          rule: rule.rule,
          ...(rule.constraints === undefined ? {} : { constraints: rule.constraints }),
        }),
      );
    }
  }
  return documents.join("\n---\n");
}

const PositionSchema = z.object({
  line: z.number().int().nonnegative(),
  column: z.number().int().nonnegative(),
});

const MetaVariableSchema = z.object({ text: z.string() });

/**
 * One `--json=stream` record. Only the fields the inventory reads are
 * declared; ast-grep's `labels`, `charCount` and `note` are ignored.
 */
const RawMatchSchema = z.object({
  ruleId: z.string(),
  file: z.string(),
  text: z.string(),
  range: z.object({
    byteOffset: z.object({
      start: z.number().int().nonnegative(),
      end: z.number().int().nonnegative(),
    }),
    start: PositionSchema,
    end: PositionSchema,
  }),
  metaVariables: z
    .object({
      single: z.record(z.string(), MetaVariableSchema).default({}),
      multi: z.record(z.string(), z.array(MetaVariableSchema)).default({}),
    })
    .optional(),
});

/**
 * A matched node, normalised.
 *
 * Lines are 1-based (ast-grep reports them 0-based) so they can go straight
 * into a `CodeRef`. Byte offsets are kept as ast-grep produced them and are
 * only ever compared with each other — they index UTF-8 bytes, not JS string
 * positions, so nothing slices source with them.
 */
export interface AstMatch {
  readonly ruleId: string;
  /** Repo-relative POSIX path, because the scan runs with the target as cwd. */
  readonly file: string;
  /** The matched node's source text, exactly as ast-grep extracted it. */
  readonly text: string;
  readonly startLine: number;
  readonly endLine: number;
  readonly startByte: number;
  readonly endByte: number;
  /** Single metavariables (`$TABLE`), by name without the `$`. */
  readonly meta: Readonly<Record<string, string>>;
  /** Multi metavariables (`$$$ARGS`), by name without the `$$$`. */
  readonly metaList: Readonly<Record<string, readonly string[]>>;
}

/** True when `inner` sits inside `outer`; equal ranges count as contained. */
export function contains(
  outer: { readonly startByte: number; readonly endByte: number },
  inner: { readonly startByte: number; readonly endByte: number },
): boolean {
  return outer.startByte <= inner.startByte && outer.endByte >= inner.endByte;
}

/** Byte width of a range, used to pick the innermost or widest of several. */
export function width(range: { readonly startByte: number; readonly endByte: number }): number {
  return range.endByte - range.startByte;
}

/** How an ast-grep pass ended; mirrors `StepStatus` so a caller can pass it on. */
export type AstGrepStatus = "ok" | "degraded" | "skipped" | "failed";

/** The outcome of one ast-grep pass: what matched, and what to disclose if not everything did. */
export interface AstGrepRun {
  readonly status: AstGrepStatus;
  /** Why the pass is not `ok`, or context worth disclosing when it is. */
  readonly reason?: string | undefined;
  readonly matches: readonly AstMatch[];
  /** Records the parser refused; a non-zero count means the pass is `degraded`. */
  readonly unparsedRecords: number;
}

/** The process port slice this driver needs. */
export interface AstProcessExecutor {
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

/** The tool resolver slice this driver needs. */
export interface AstToolResolver {
  resolve(name: string, options?: { allowPath?: boolean }): Promise<string | null>;
}

/** Everything an ast-grep pass is handed. Satisfied structurally by the scan context. */
export interface AstGrepContext {
  readonly exec: AstProcessExecutor;
  readonly tools: AstToolResolver;
  /** Absolute path of the repository under analysis; the pass runs with it as cwd. */
  readonly targetDir: string;
  /** Allow a tool found on PATH when the pinned build is not cached. Default false. */
  readonly allowPathTools?: boolean | undefined;
  /** Wall-clock budget for the ast-grep process. */
  readonly timeoutMs?: number | undefined;
  readonly signal?: AbortSignal | undefined;
}

/** A structural enumeration over a repository is seconds, not minutes. */
export const AST_GREP_DEFAULT_TIMEOUT_MS = 180_000;

/** Options for a single {@link runAstGrep} pass. */
export interface AstGrepOptions {
  /** Paths to scan, relative to the target. Defaults to the whole repository. */
  readonly paths?: readonly string[] | undefined;
  /** Extra globs, `!`-prefixed to exclude, on top of {@link DEFAULT_EXCLUDE_GLOBS}. */
  readonly globs?: readonly string[] | undefined;
}

/** Builds the ast-grep argument list for one pass. */
export function astGrepArgs(inlineRules: string, options: AstGrepOptions = {}): string[] {
  const args = ["scan", "--inline-rules", inlineRules, "--json=stream"];
  for (const glob of [...DEFAULT_EXCLUDE_GLOBS, ...(options.globs ?? [])]) {
    args.push("--globs", glob);
  }
  const paths = options.paths ?? [];
  args.push(...(paths.length === 0 ? ["."] : [...paths]));
  return args;
}

/** Parses one `--json=stream` line, returning null when the record is not usable. */
export function parseMatchLine(line: string): AstMatch | null {
  const trimmed = line.trim();
  if (trimmed === "") return null;
  let payload: unknown;
  try {
    payload = JSON.parse(trimmed);
  } catch {
    return null;
  }
  const parsed = RawMatchSchema.safeParse(payload);
  if (!parsed.success) return null;
  const raw = parsed.data;
  const meta: Record<string, string> = {};
  for (const [name, value] of Object.entries(raw.metaVariables?.single ?? {})) {
    meta[name] = value.text;
  }
  const metaList: Record<string, string[]> = {};
  for (const [name, values] of Object.entries(raw.metaVariables?.multi ?? {})) {
    metaList[name] = values.map((value) => value.text);
  }
  return {
    ruleId: raw.ruleId,
    file: raw.file.split("\\").join("/"),
    text: raw.text,
    // ast-grep counts lines from zero; every Sentinel artifact counts from one.
    startLine: raw.range.start.line + 1,
    endLine: raw.range.end.line + 1,
    startByte: raw.range.byteOffset.start,
    endByte: raw.range.byteOffset.end,
    meta,
    metaList,
  };
}

/** Parses a whole `--json=stream` body, counting the records it had to refuse. */
export function parseMatchStream(stdout: string): {
  matches: AstMatch[];
  unparsedRecords: number;
} {
  const matches: AstMatch[] = [];
  let unparsedRecords = 0;
  for (const line of stdout.split("\n")) {
    if (line.trim() === "") continue;
    const match = parseMatchLine(line);
    if (match === null) unparsedRecords += 1;
    else matches.push(match);
  }
  return { matches, unparsedRecords };
}

/** Trims a tool's stderr to something a single report line can hold. */
function briefly(text: string, limit = 240): string {
  const collapsed = text.replace(/\s+/g, " ").trim();
  return collapsed.length <= limit ? collapsed : `${collapsed.slice(0, limit - 1)}...`;
}

/**
 * Runs one ast-grep pass over the target and returns the matches it proved.
 *
 * It never throws: a missing binary, a timeout or a crash come back as a
 * status, because an inventory that cannot enumerate must say so rather than
 * report a short list as if it were complete.
 */
export async function runAstGrep(
  ctx: AstGrepContext,
  rules: readonly AstRule[],
  options: AstGrepOptions = {},
): Promise<AstGrepRun> {
  if (rules.length === 0) {
    return { status: "skipped", reason: "no rules to run", matches: [], unparsedRecords: 0 };
  }
  const binary = await ctx.tools.resolve(AST_GREP_TOOL, {
    allowPath: ctx.allowPathTools === true,
  });
  if (binary === null) {
    return {
      status: "skipped",
      reason: "ast-grep is not installed; structural enumeration cannot run",
      matches: [],
      unparsedRecords: 0,
    };
  }

  const result = await ctx.exec.run(binary, astGrepArgs(renderInlineRules(rules), options), {
    cwd: ctx.targetDir,
    timeoutMs: ctx.timeoutMs ?? AST_GREP_DEFAULT_TIMEOUT_MS,
    ...(ctx.signal === undefined ? {} : { signal: ctx.signal }),
  });

  if (result.notFound) {
    return {
      status: "skipped",
      reason: `ast-grep not executable at ${binary}`,
      matches: [],
      unparsedRecords: 0,
    };
  }
  if (result.timedOut) {
    return {
      status: "failed",
      reason: "ast-grep timed out; the enumeration would be partial",
      matches: [],
      unparsedRecords: 0,
    };
  }
  // ast-grep exits non-zero when a rule fails to compile, which would silently
  // shrink the inventory. An empty stdout with a bad exit code is never "no
  // matches", it is a broken query.
  if (result.exitCode !== 0 && result.stdout.trim() === "") {
    return {
      status: "failed",
      reason: `ast-grep exited ${result.exitCode}: ${briefly(result.stderr)}`,
      matches: [],
      unparsedRecords: 0,
    };
  }

  const { matches, unparsedRecords } = parseMatchStream(result.stdout);
  const notes: string[] = [];
  if (result.truncated) notes.push("ast-grep output was truncated; some call sites are missing");
  if (unparsedRecords > 0) notes.push(`${unparsedRecords} ast-grep record(s) could not be parsed`);
  if (result.exitCode !== 0) notes.push(`ast-grep exited ${result.exitCode}`);
  const degraded = result.truncated || unparsedRecords > 0;
  return {
    status: degraded ? "degraded" : "ok",
    ...(notes.length === 0 ? {} : { reason: notes.join("; ") }),
    matches,
    unparsedRecords,
  };
}
