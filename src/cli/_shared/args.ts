/**
 * A hand-written argument parser. Sentinel ships no CLI framework (commander,
 * yargs and cac are banned), and the surface is small enough that a readable
 * 200-line parser beats a dependency: it parses `--flag=value`, `--flag value`,
 * bundled short flags, `--no-<flag>` negation and the `--` terminator, and it
 * reports every mistake as a structured usage error instead of throwing.
 */

/** The value shapes a flag can carry. */
export type FlagKind = "boolean" | "string" | "number" | "list";

/** Declarative description of a single flag. */
export interface FlagSpec {
  readonly kind: FlagKind;
  readonly description: string;
  /** Single-character alias, usable inside a bundle such as `-vq`. */
  readonly short?: string;
  /** Boolean flags only: `--no-<name>` sets the flag to false. */
  readonly negatable?: boolean;
  /** Help label override, e.g. `--no-ai` for a negatable `ai` flag. */
  readonly helpName?: string;
  /** Value placeholder in help output: `dir` renders as `--out <dir>`. */
  readonly placeholder?: string;
}

/** Declarative description of a positional argument. */
export interface PositionalSpec {
  readonly name: string;
  readonly description: string;
  readonly required?: boolean;
  /** Absorbs every remaining positional token. */
  readonly variadic?: boolean;
}

/** Everything `parseArgs` and the help renderer need to know about a verb. */
export interface CommandSpec {
  readonly name: string;
  readonly summary: string;
  readonly positionals?: readonly PositionalSpec[];
  readonly flags: Readonly<Record<string, FlagSpec>>;
}

/** A parsed flag value; `list` flags accumulate across repetitions. */
export type FlagValue = boolean | string | number | readonly string[];

/** The result of a successful parse. */
export interface ParsedArgs {
  /** Only flags actually present on the command line; absent ones are not keyed. */
  readonly flags: ReadonlyMap<string, FlagValue>;
  readonly positionals: readonly string[];
  /** Tokens after the `--` terminator, passed through untouched. */
  readonly rest: readonly string[];
}

/** Why a command line was rejected; each maps to exit code 64. */
export type UsageErrorKind =
  | "unknown-command"
  | "unknown-flag"
  | "missing-value"
  | "invalid-value"
  | "missing-positional"
  | "unexpected-positional"
  | "conflicting-flags";

/** A rejected command line, carrying the verb whose help answers it. */
export interface UsageError {
  readonly kind: UsageErrorKind;
  readonly message: string;
  readonly command?: string;
}

/** Parse outcome; failures are values, not exceptions. */
export type ParseOutcome =
  | { readonly ok: true; readonly value: ParsedArgs }
  | { readonly ok: false; readonly error: UsageError };

/** `--help` is implicit on every verb, so no spec has to declare it. */
const HELP_FLAG: FlagSpec = {
  kind: "boolean",
  short: "h",
  description: "Show help for this command",
};

/** A value token may start with `-` only when it is a negative number. */
const NEGATIVE_NUMBER = /^-\d/;

/** The flags a command accepts, including the implicit `--help`. */
export function commandFlags(spec: CommandSpec): Readonly<Record<string, FlagSpec>> {
  return spec.flags.help === undefined ? { ...spec.flags, help: HELP_FLAG } : spec.flags;
}

/** True when the parse outcome carries a usage error. */
function isUsageError(value: unknown): value is UsageError {
  return typeof value === "object" && value !== null && "kind" in value && "message" in value;
}

/** Split a comma-separated list value, dropping empty entries. */
function splitList(raw: string): string[] {
  return raw
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

/** Parse `argv` (already stripped of the verb) against `spec`. */
export function parseArgs(spec: CommandSpec, argv: readonly string[]): ParseOutcome {
  const flags = commandFlags(spec);
  const shorts = new Map<string, string>();
  for (const [name, flag] of Object.entries(flags)) {
    if (flag.short !== undefined) shorts.set(flag.short, name);
  }

  const values = new Map<string, FlagValue>();
  const positionals: string[] = [];
  const rest: string[] = [];
  let index = 0;

  const fail = (kind: UsageErrorKind, message: string): ParseOutcome => ({
    ok: false,
    error: { kind, message, command: spec.name },
  });

  /** Take the next token as a value, or explain why there is none. */
  const consume = (label: string): string | UsageError => {
    const next = argv[index];
    if (
      next === undefined ||
      (next.startsWith("-") && next !== "-" && !NEGATIVE_NUMBER.test(next))
    ) {
      return { kind: "missing-value", message: `${label} expects a value`, command: spec.name };
    }
    index += 1;
    return next;
  };

  /** Coerce and store one flag value according to its declared kind. */
  const store = (
    name: string,
    flag: FlagSpec,
    raw: string,
    label: string,
  ): UsageError | undefined => {
    if (flag.kind === "number") {
      const parsed = Number(raw.trim());
      if (raw.trim().length === 0 || !Number.isInteger(parsed)) {
        return {
          kind: "invalid-value",
          message: `${label} expects an integer, got "${raw}"`,
          command: spec.name,
        };
      }
      values.set(name, parsed);
      return undefined;
    }
    if (flag.kind === "list") {
      const previous = values.get(name);
      const merged = Array.isArray(previous) ? [...(previous as readonly string[])] : [];
      merged.push(...splitList(raw));
      values.set(name, merged);
      return undefined;
    }
    if (flag.kind === "boolean") {
      if (raw !== "true" && raw !== "false") {
        return {
          kind: "invalid-value",
          message: `${label} is a switch; it takes no value`,
          command: spec.name,
        };
      }
      values.set(name, raw === "true");
      return undefined;
    }
    values.set(name, raw);
    return undefined;
  };

  while (index < argv.length) {
    const token = argv[index];
    if (token === undefined) break;
    index += 1;

    if (token === "--") {
      rest.push(...argv.slice(index));
      break;
    }

    if (token.startsWith("--")) {
      const body = token.slice(2);
      const eq = body.indexOf("=");
      const rawName = eq >= 0 ? body.slice(0, eq) : body;
      const inline = eq >= 0 ? body.slice(eq + 1) : undefined;

      if (rawName.length === 0) return fail("unknown-flag", `"${token}" is not a valid flag`);

      const negated = rawName.startsWith("no-");
      const baseName = negated ? rawName.slice(3) : rawName;
      const negatedSpec = negated ? flags[baseName] : undefined;
      if (negatedSpec?.kind === "boolean" && negatedSpec.negatable === true) {
        if (inline !== undefined) {
          return fail("invalid-value", `--no-${baseName} is a switch; it takes no value`);
        }
        values.set(baseName, false);
        continue;
      }

      const flag = flags[rawName];
      if (flag === undefined) return fail("unknown-flag", `unknown flag "--${rawName}"`);

      if (flag.kind === "boolean" && inline === undefined) {
        values.set(rawName, true);
        continue;
      }
      const raw = inline ?? consume(`--${rawName}`);
      if (isUsageError(raw)) return { ok: false, error: raw };
      const error = store(rawName, flag, raw, `--${rawName}`);
      if (error !== undefined) return { ok: false, error };
      continue;
    }

    if (token.startsWith("-") && token.length > 1) {
      const cluster = token.slice(1);
      let position = 0;
      while (position < cluster.length) {
        const letter = cluster.charAt(position);
        position += 1;
        const name = shorts.get(letter);
        const flag = name === undefined ? undefined : flags[name];
        if (name === undefined || flag === undefined) {
          return fail("unknown-flag", `unknown flag "-${letter}"`);
        }
        if (flag.kind === "boolean") {
          values.set(name, true);
          continue;
        }
        // A value-taking short flag ends the bundle: it eats the rest of the
        // token (`-otmp`) or, failing that, the next token (`-o tmp`).
        const tail = cluster.slice(position);
        const raw = tail.length > 0 ? tail : consume(`-${letter}`);
        if (isUsageError(raw)) return { ok: false, error: raw };
        const error = store(name, flag, raw, `-${letter}`);
        if (error !== undefined) return { ok: false, error };
        position = cluster.length;
      }
      continue;
    }

    positionals.push(token);
  }

  const declared = spec.positionals ?? [];
  const variadic = declared.some((entry) => entry.variadic === true);
  const required = declared.filter((entry) => entry.required === true);
  if (values.get("help") !== true) {
    if (positionals.length < required.length) {
      const missing = required[positionals.length];
      const label = missing === undefined ? "argument" : `<${missing.name}>`;
      return fail("missing-positional", `${spec.name} requires ${label}`);
    }
    if (!variadic && positionals.length > declared.length) {
      const extra = positionals[declared.length];
      return fail("unexpected-positional", `unexpected argument "${extra ?? ""}"`);
    }
  }

  return { ok: true, value: { flags: values, positionals, rest } };
}

/** True when the flag appeared on the command line at all. */
export function flagProvided(args: ParsedArgs, name: string): boolean {
  return args.flags.has(name);
}

/** Read a boolean flag, falling back when it was not provided. */
export function flagBoolean(args: ParsedArgs, name: string, fallback = false): boolean {
  const value = args.flags.get(name);
  return typeof value === "boolean" ? value : fallback;
}

/** Read a string flag, or `undefined` when it was not provided. */
export function flagString(args: ParsedArgs, name: string): string | undefined {
  const value = args.flags.get(name);
  return typeof value === "string" ? value : undefined;
}

/** Read an integer flag, or `undefined` when it was not provided. */
export function flagNumber(args: ParsedArgs, name: string): number | undefined {
  const value = args.flags.get(name);
  return typeof value === "number" ? value : undefined;
}

/** Read a list flag; an absent list flag reads as an empty list. */
export function flagList(args: ParsedArgs, name: string): readonly string[] {
  const value = args.flags.get(name);
  return Array.isArray(value) ? (value as readonly string[]) : [];
}

/** The label a flag shows in help, e.g. `-o, --out <dir>`. */
function flagLabel(name: string, flag: FlagSpec): string {
  const long = flag.helpName ?? `--${name}`;
  const head = flag.short === undefined ? `    ${long}` : `-${flag.short}, ${long}`;
  if (flag.kind === "boolean") return head;
  const placeholder = flag.placeholder ?? (flag.kind === "list" ? "list" : "value");
  return `${head} <${placeholder}>`;
}

/** Render one aligned `label  description` line per flag. */
export function renderFlagLines(
  flags: Readonly<Record<string, FlagSpec>>,
  indent = "  ",
): string[] {
  const entries = Object.entries(flags);
  const labels = entries.map(([name, flag]) => flagLabel(name, flag));
  const width = labels.reduce((max, label) => Math.max(max, label.length), 0);
  return entries.map(([, flag], position) => {
    const label = labels[position] ?? "";
    return `${indent}${label.padEnd(width)}  ${flag.description}`;
  });
}

/** The `<required>` / `[optional]` rendering of a positional argument. */
function positionalLabel(positional: PositionalSpec): string {
  const name = positional.variadic === true ? `${positional.name}...` : positional.name;
  return positional.required === true ? `<${name}>` : `[${name}]`;
}

/** Render the help page for one verb. */
export function renderCommandHelp(spec: CommandSpec, programName = "sentinel"): string {
  const declared = spec.positionals ?? [];
  const usage = [programName, spec.name, ...declared.map(positionalLabel), "[options]"].join(" ");
  const sections = [`Usage: ${usage}`, "", `  ${spec.summary}`];
  if (declared.length > 0) {
    const width = declared.reduce((max, entry) => Math.max(max, positionalLabel(entry).length), 0);
    sections.push("", "Arguments:");
    for (const entry of declared) {
      sections.push(`  ${positionalLabel(entry).padEnd(width)}  ${entry.description}`);
    }
  }
  sections.push("", "Options:", ...renderFlagLines(commandFlags(spec)));
  return `${sections.join("\n")}\n`;
}
