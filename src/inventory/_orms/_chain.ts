/**
 * Expression-level parsing for the data-access inventory.
 *
 * ast-grep decides *which* expression is a data-access call and hands over its
 * exact source text; this module reads the inside of that one expression — the
 * links of the chain, the arguments, the keys of an options object. The input
 * is always a single expression ast-grep already delimited, never a file, which
 * is why a scanner this small is enough.
 *
 * Everything structural runs over a *mask*: a same-length copy of the text in
 * which the body of every string, template literal, regular expression and
 * comment is blanked out. Indices therefore mean the same thing in both
 * strings, and a brace inside a SQL literal cannot unbalance a chain.
 */

/** Characters after which a `/` opens a regular expression rather than dividing. */
const REGEX_PRECEDING = new Set([
  "(",
  ",",
  "=",
  ":",
  "[",
  "!",
  "&",
  "|",
  "?",
  "{",
  "}",
  ";",
  "+",
  "-",
  "*",
  "%",
  "<",
  ">",
  "~",
  "^",
  "\n",
]);

const OPENERS: Readonly<Record<string, string>> = { "(": ")", "[": "]", "{": "}" };
const CLOSERS = new Set([")", "]", "}"]);

/**
 * Blanks out every literal and comment, keeping the text's length and every
 * structural character in place. This is the only place quoting is reasoned
 * about, so every other function here can be a plain index scan.
 */
export function maskLiterals(text: string): string {
  const out = text.split("");
  let index = 0;
  let lastCode = "\n";
  const blank = (from: number, to: number): void => {
    for (let i = from; i < to && i < out.length; i += 1) out[i] = " ";
  };
  while (index < text.length) {
    const char = text[index] ?? "";
    const next = text[index + 1] ?? "";
    if (char === "/" && next === "/") {
      const end = text.indexOf("\n", index);
      const stop = end === -1 ? text.length : end;
      blank(index, stop);
      index = stop;
      continue;
    }
    if (char === "/" && next === "*") {
      const end = text.indexOf("*/", index + 2);
      const stop = end === -1 ? text.length : end + 2;
      blank(index, stop);
      index = stop;
      continue;
    }
    if (char === '"' || char === "'" || char === "`") {
      let cursor = index + 1;
      while (cursor < text.length) {
        const current = text[cursor];
        if (current === "\\") {
          cursor += 2;
          continue;
        }
        if (current === char) break;
        cursor += 1;
      }
      const stop = Math.min(cursor + 1, text.length);
      // The delimiters go too: a lone backtick left behind would look like code.
      blank(index, stop);
      index = stop;
      lastCode = "x";
      continue;
    }
    if (char === "/" && REGEX_PRECEDING.has(lastCode)) {
      let cursor = index + 1;
      let inClass = false;
      let closed = false;
      while (cursor < text.length) {
        const current = text[cursor];
        if (current === "\\") {
          cursor += 2;
          continue;
        }
        if (current === "\n") break;
        if (current === "[") inClass = true;
        else if (current === "]") inClass = false;
        else if (current === "/" && !inClass) {
          closed = true;
          break;
        }
        cursor += 1;
      }
      if (closed) {
        const stop = Math.min(cursor + 1, text.length);
        blank(index, stop);
        index = stop;
        lastCode = "x";
        continue;
      }
    }
    if (!/\s/.test(char)) lastCode = char;
    index += 1;
  }
  return out.join("");
}

/** Index of the bracket closing the one at `open`, or -1 when it never closes. */
export function matchBracket(mask: string, open: number): number {
  const opener = mask[open];
  if (opener === undefined || OPENERS[opener] === undefined) return -1;
  let depth = 0;
  for (let i = open; i < mask.length; i += 1) {
    const char = mask[i] ?? "";
    if (OPENERS[char] !== undefined) depth += 1;
    else if (CLOSERS.has(char)) {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/** Splits on a separator that is not nested inside brackets; empty parts are dropped. */
export function splitTopLevel(text: string, separator = ","): string[] {
  const mask = maskLiterals(text);
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < mask.length; i += 1) {
    const char = mask[i] ?? "";
    if (OPENERS[char] !== undefined) depth += 1;
    else if (CLOSERS.has(char)) depth -= 1;
    else if (char === separator && depth === 0) {
      parts.push(text.slice(start, i).trim());
      start = i + 1;
    }
  }
  parts.push(text.slice(start).trim());
  return parts.filter((part) => part !== "");
}

/** Strips one layer of wrapping parentheses, plus `await`, `!` and `as T` noise. */
export function unwrap(text: string): string {
  let value = text.trim();
  for (;;) {
    const before = value;
    if (value.startsWith("await ")) value = value.slice(6).trim();
    if (value.startsWith("(")) {
      const mask = maskLiterals(value);
      if (matchBracket(mask, 0) === value.length - 1) value = value.slice(1, -1).trim();
    }
    if (value === before) return value;
  }
}

/** The content of a string literal, or null when the text is not one. */
export function stringLiteral(text: string): string | null {
  const value = text.trim();
  if (value.length < 2) return null;
  const quote = value[0];
  if (quote !== '"' && quote !== "'" && quote !== "`") return null;
  if (!value.endsWith(quote)) return null;
  const inner = value.slice(1, -1);
  // A template with an interpolation is not a literal name; it is an expression.
  if (quote === "`" && inner.includes("${")) return null;
  return inner.replace(/\\(["'`\\])/g, "$1");
}

/** One key/value pair of an object literal, as source text. */
export interface ObjectEntry {
  /** Property name, unquoted. `"..."` for a spread, `"[]"` for a computed key. */
  readonly key: string;
  /** The value's source text; for shorthand `{ id }` it is the key itself. */
  readonly value: string;
}

/** Reads the top-level entries of an object literal; anything else yields none. */
export function objectEntries(text: string): ObjectEntry[] {
  const value = unwrap(text);
  if (!value.startsWith("{") || !value.endsWith("}")) return [];
  const body = value.slice(1, -1);
  const entries: ObjectEntry[] = [];
  for (const part of splitTopLevel(body)) {
    if (part.startsWith("...")) {
      entries.push({ key: "...", value: part.slice(3).trim() });
      continue;
    }
    const mask = maskLiterals(part);
    let depth = 0;
    let colon = -1;
    for (let i = 0; i < mask.length; i += 1) {
      const char = mask[i] ?? "";
      if (OPENERS[char] !== undefined) depth += 1;
      else if (CLOSERS.has(char)) depth -= 1;
      else if (char === ":" && depth === 0) {
        colon = i;
        break;
      }
    }
    if (colon === -1) {
      // Shorthand (`{ id }`) or a method (`{ run() {} }`); a method has no value.
      const name = part.trim();
      if (/^[A-Za-z_$][\w$]*$/.test(name)) entries.push({ key: name, value: name });
      continue;
    }
    const rawKey = part.slice(0, colon).trim();
    const literal = stringLiteral(rawKey);
    const key = literal ?? (rawKey.startsWith("[") ? "[]" : rawKey);
    entries.push({ key, value: part.slice(colon + 1).trim() });
  }
  return entries;
}

/** The top-level keys of an object literal, in source order. */
export function objectKeys(text: string): string[] {
  return objectEntries(text).map((entry) => entry.key);
}

/** The value of one top-level key of an object literal, as source text. */
export function objectValue(text: string, key: string): string | undefined {
  return objectEntries(text).find((entry) => entry.key === key)?.value;
}

/** One `.name(args)` link of a call chain. */
export interface ChainSegment {
  /** The method name; empty when the chain opens with a bare call (`knex("t")`). */
  readonly name: string;
  /** Top-level arguments, as source text. */
  readonly args: readonly string[];
  /** Everything between the parentheses, or the template body for a tagged call. */
  readonly argsText: string;
  /** True when the arguments were a tagged template rather than a parameter list. */
  readonly tagged: boolean;
}

/** A call chain split into its receiver and its links. */
export interface ParsedChain {
  /** The receiver the chain hangs off: `db`, `this.repo`, `prisma.booking`. */
  readonly base: string;
  readonly segments: readonly ChainSegment[];
  /** A trailing property access that is not a call, e.g. `.rows` or `.length`. */
  readonly tail: string;
  /** The text that was parsed, with `await` and wrapping parentheses removed. */
  readonly text: string;
}

const IDENTIFIER_PATH = /^[A-Za-z_$][\w$]*(?:\s*\??\.\s*[A-Za-z_$#][\w$]*)*/;

/** Skips a balanced `<...>` type-argument list, returning the index after it. */
function skipTypeArguments(mask: string, at: number): number {
  if (mask[at] !== "<") return at;
  let depth = 0;
  for (let i = at; i < mask.length; i += 1) {
    const char = mask[i];
    if (char === "<") depth += 1;
    else if (char === ">") {
      depth -= 1;
      if (depth === 0) return i + 1;
    } else if (char === "(" || char === ";") return at;
  }
  return at;
}

/**
 * Splits one call chain into its receiver and its links.
 *
 * `db.select().from(bookings).where(eq(a, b)).limit(10)` becomes base `db` and
 * the segments `select`, `from`, `where`, `limit` — which is the shape every
 * ORM extractor reads its attributes out of.
 */
export function parseChain(rawText: string): ParsedChain {
  const text = unwrap(rawText);
  const mask = maskLiterals(text);
  const segments: ChainSegment[] = [];
  let base = "";
  let tail = "";
  let cursor = 0;

  const headMatch = IDENTIFIER_PATH.exec(text);
  if (headMatch === null) return { base: text, segments, tail, text };
  const headPath = headMatch[0].replace(/\s+/g, "");
  cursor = headMatch[0].length;

  /** Records a call link; the first one also settles what the chain hangs off. */
  const pushCall = (receiver: string, name: string, argsText: string, tagged: boolean): void => {
    if (segments.length === 0) base = receiver;
    segments.push({ name, args: splitTopLevel(argsText), argsText, tagged });
  };

  const headParts = headPath.split(".");
  let receiver = headParts.length > 1 ? headParts.slice(0, -1).join(".") : headPath;
  let name = headParts.length > 1 ? (headParts[headParts.length - 1] ?? "") : "";
  for (;;) {
    while (cursor < text.length && /\s/.test(text[cursor] ?? "")) cursor += 1;
    cursor = skipTypeArguments(mask, cursor);
    const char = text[cursor];
    if (char === "(") {
      const close = matchBracket(mask, cursor);
      if (close === -1) break;
      pushCall(receiver, name, text.slice(cursor + 1, close), false);
      cursor = close + 1;
    } else if (char === "`") {
      // A tagged template (`prisma.$queryRaw`SELECT ...``) is a call too.
      let end = cursor + 1;
      while (end < text.length) {
        if (text[end] === "\\") {
          end += 2;
          continue;
        }
        if (text[end] === "`") break;
        end += 1;
      }
      pushCall(receiver, name, text.slice(cursor + 1, Math.min(end, text.length)), true);
      cursor = Math.min(end + 1, text.length);
    } else break;

    while (cursor < text.length && /\s/.test(text[cursor] ?? "")) cursor += 1;
    if (text[cursor] === "!") cursor += 1;
    const rest = text.slice(cursor);
    const nextMatch = /^\s*\??\.\s*([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)/.exec(rest);
    if (nextMatch === null) break;
    const nextPath = (nextMatch[1] ?? "").replace(/\s+/g, "");
    cursor += nextMatch[0].length;
    // `.rows` with no call after it is a property read, not a link.
    let peek = cursor;
    while (peek < text.length && /\s/.test(text[peek] ?? "")) peek += 1;
    const after = skipTypeArguments(mask, peek);
    if (text[after] !== "(" && text[after] !== "`") {
      tail = nextPath;
      break;
    }
    cursor = peek;
    const nextParts = nextPath.split(".");
    receiver = "";
    name = nextParts[nextParts.length - 1] ?? "";
  }

  if (segments.length === 0) base = headPath;
  return { base, segments, tail, text };
}

/** The first segment whose name is one of `names`. */
export function findSegment(
  chain: ParsedChain,
  ...names: readonly string[]
): ChainSegment | undefined {
  const wanted = new Set(names);
  return chain.segments.find((segment) => wanted.has(segment.name));
}

/** True when the chain calls any of `names`. */
export function hasSegment(chain: ParsedChain, ...names: readonly string[]): boolean {
  return findSegment(chain, ...names) !== undefined;
}

/** Every segment name in the chain, in call order. */
export function segmentNames(chain: ParsedChain): string[] {
  return chain.segments.map((segment) => segment.name);
}

/** The last identifier of a dotted receiver: `this.usersRepo` → `usersRepo`. */
export function lastIdentifier(path: string): string {
  const parts = path.split(".");
  return parts[parts.length - 1] ?? path;
}
