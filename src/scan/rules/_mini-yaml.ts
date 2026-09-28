/**
 * A very small, dependency-free YAML reader for the two shapes the delivery
 * rules need: GitHub Actions workflows and docker-compose files.
 *
 * It is deliberately not a YAML implementation. It covers block mappings,
 * block sequences, single-line flow collections, quoted scalars and `|`/`>`
 * block scalars — and it records, for every node and for every line of a
 * multi-line scalar, the file line it came from, because a delivery finding is
 * worthless without an exact anchor. Anything it cannot read becomes an entry
 * in `errors`; it never throws.
 *
 * Two deliberate simplifications: only the first document of a multi-document
 * file is read, and a folded (`>`) scalar is kept line-by-line rather than
 * folded, so that a match inside it still maps back to a real file line.
 */

/** A scalar value, with the file line (or lines) it was read from. */
export interface YamlScalar {
  readonly kind: "scalar";
  /** 1-based file line where the scalar starts. */
  readonly line: number;
  /** 1-based column where the scalar starts. */
  readonly column: number;
  readonly value: string;
  readonly style: "plain" | "single" | "double" | "literal" | "folded" | "empty";
  /** The file line of each line of `value`; a single-line scalar has one entry. */
  readonly lines: readonly number[];
}

/** One `key: value` pair, anchored at the key. */
export interface YamlEntry {
  readonly key: string;
  /** 1-based file line of the key. */
  readonly line: number;
  /** 1-based column of the key. */
  readonly column: number;
  readonly value: YamlNode;
}

/** A block or flow mapping. */
export interface YamlMapping {
  readonly kind: "mapping";
  readonly line: number;
  readonly entries: readonly YamlEntry[];
}

/** A block or flow sequence. */
export interface YamlSequence {
  readonly kind: "sequence";
  readonly line: number;
  readonly items: readonly YamlNode[];
}

/** Any node the reader can produce. */
export type YamlNode = YamlScalar | YamlMapping | YamlSequence;

/** The result of reading a file: the first document, plus whatever could not be read. */
export interface YamlDocument {
  readonly root: YamlNode | null;
  readonly errors: readonly string[];
}

/** One physical line, split into its indentation and its content. */
interface SourceLine {
  readonly number: number;
  /** Count of leading spaces; a tab counts as one and is reported as an error. */
  readonly indent: number;
  /** Content after the indentation, trailing whitespace removed. */
  readonly text: string;
}

interface ParserState {
  readonly lines: SourceLine[];
  index: number;
  readonly errors: string[];
  depth: number;
}

/** Guards against a pathological file driving the recursive descent off a cliff. */
const MAX_DEPTH = 40;

/** Splits the text into lines, measuring indentation and flagging tab indents. */
function toSourceLines(text: string, errors: string[]): SourceLine[] {
  const lines: SourceLine[] = [];
  let sawTab = false;
  const raw = text.split("\n");
  for (let index = 0; index < raw.length; index += 1) {
    const body = (raw[index] ?? "").replace(/\r$/, "");
    let indent = 0;
    while (indent < body.length) {
      const char = body[indent];
      if (char === " ") {
        indent += 1;
        continue;
      }
      if (char === "\t") {
        sawTab = true;
        indent += 1;
        continue;
      }
      break;
    }
    lines.push({ number: index + 1, indent, text: body.slice(indent).trimEnd() });
  }
  if (sawTab)
    errors.push("tab used for indentation; YAML forbids it and the structure may be wrong");
  return lines;
}

/** True when a line carries structure rather than being blank or a comment. */
function isStructural(line: SourceLine): boolean {
  return line.text !== "" && !line.text.startsWith("#");
}

/** True when the line opens a block sequence item. */
function isDashLine(line: SourceLine): boolean {
  return line.text === "-" || /^-[\s]/.test(line.text);
}

/** Advances past blank and comment-only lines. */
function skipBlanks(state: ParserState): void {
  while (state.index < state.lines.length) {
    const line = state.lines[state.index];
    if (line === undefined || isStructural(line)) break;
    state.index += 1;
  }
}

/** The next structural line, or null at end of file or end of the first document. */
function peek(state: ParserState): SourceLine | null {
  skipBlanks(state);
  const line = state.lines[state.index];
  if (line === undefined) return null;
  if (line.indent === 0 && (line.text === "---" || line.text === "...")) return null;
  return line;
}

/** Drops a comment that starts outside quotes; `#` inside a quoted value is content. */
export function stripComment(text: string): string {
  let quote: string | null = null;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quote !== null) {
      if (char === "\\" && quote === '"') {
        index += 1;
        continue;
      }
      if (char === quote) quote = null;
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }
    if (char === "#") {
      const before = index === 0 ? " " : (text[index - 1] ?? " ");
      if (before === " " || before === "\t") return text.slice(0, index).trimEnd();
    }
  }
  return text.trimEnd();
}

/** An empty value, so a key with nothing after it still has a node to point at. */
function emptyScalar(line: number, column: number): YamlScalar {
  return { kind: "scalar", line, column, value: "", style: "empty", lines: [line] };
}

/** Unescapes a double-quoted scalar; only the escapes these files actually use. */
function unescapeDouble(body: string): string {
  return body.replace(/\\(["\\/nrt])/g, (_match, char: string) => {
    switch (char) {
      case "n":
        return "\n";
      case "r":
        return "\r";
      case "t":
        return "\t";
      default:
        return char;
    }
  });
}

/** Reads a quoted scalar starting at `start`, returning its text and end index. */
function readQuoted(
  text: string,
  start: number,
): { value: string; end: number; style: "single" | "double" } | null {
  const quote = text[start];
  if (quote !== '"' && quote !== "'") return null;
  let index = start + 1;
  let body = "";
  while (index < text.length) {
    const char = text[index];
    if (char === undefined) break;
    if (quote === '"' && char === "\\") {
      body += char + (text[index + 1] ?? "");
      index += 2;
      continue;
    }
    if (char === quote) {
      // In single quotes, '' is a literal quote rather than the end.
      if (quote === "'" && text[index + 1] === "'") {
        body += "'";
        index += 2;
        continue;
      }
      return {
        value: quote === '"' ? unescapeDouble(body) : body,
        end: index + 1,
        style: quote === '"' ? "double" : "single",
      };
    }
    body += char;
    index += 1;
  }
  return null;
}

/** A key found at the start of a line, with whatever followed the colon. */
interface KeySplit {
  readonly key: string;
  readonly rest: string;
  /** Column the value starts at, 1-based; used when the value is on the same line. */
  readonly valueColumn: number;
}

/**
 * Splits `key: value` at the colon that terminates the key. A colon only ends
 * a key when it is followed by a space or the end of the line, which is what
 * keeps `image: postgres:15` and `run: echo a:b` intact.
 */
export function splitKey(text: string, indent: number): KeySplit | null {
  if (text.startsWith("[") || text.startsWith("{") || text.startsWith("- ")) return null;
  let keyEnd = -1;
  let key = "";
  if (text.startsWith('"') || text.startsWith("'")) {
    const quoted = readQuoted(text, 0);
    if (quoted === null) return null;
    let after = quoted.end;
    while (text[after] === " ") after += 1;
    if (text[after] !== ":") return null;
    key = quoted.value;
    keyEnd = after;
  } else {
    for (let index = 0; index < text.length; index += 1) {
      if (text[index] !== ":") continue;
      const next = text[index + 1];
      if (next !== undefined && next !== " ") continue;
      keyEnd = index;
      key = text.slice(0, index).trimEnd();
      break;
    }
    if (keyEnd === -1 || key === "" || key.includes(" #")) return null;
  }
  const afterColon = text.slice(keyEnd + 1);
  const rest = stripComment(afterColon).trim();
  const offset = afterColon.length - afterColon.trimStart().length;
  return { key, rest, valueColumn: indent + keyEnd + 2 + offset };
}

/** A cursor over a single line, used for flow collections. */
interface FlowCursor {
  readonly text: string;
  index: number;
}

/** Skips the whitespace between flow items. */
function skipFlowSpace(cursor: FlowCursor): void {
  while (cursor.index < cursor.text.length) {
    const char = cursor.text[cursor.index];
    if (char === " " || char === "\t") cursor.index += 1;
    else break;
  }
}

/**
 * True when the character at `index` ends a flow scalar: a collection
 * delimiter, or a `:` acting as a key separator (`{a: b}`) rather than a
 * character inside a value (`127.0.0.1:5432`).
 */
function endsFlowScalar(text: string, index: number): boolean {
  const char = text[index];
  if (char === "," || char === "]" || char === "}") return true;
  if (char !== ":") return false;
  const next = text[index + 1];
  return next === undefined || next === " " || next === "," || next === "]" || next === "}";
}

/** Parses one flow node: `[...]`, `{...}` or a scalar up to the next delimiter. */
function parseFlowNode(
  cursor: FlowCursor,
  line: number,
  errors: string[],
  depth: number,
): YamlNode {
  skipFlowSpace(cursor);
  const column = cursor.index + 1;
  const char = cursor.text[cursor.index];
  if (depth > MAX_DEPTH) {
    errors.push(`line ${line}: flow collection nested too deeply`);
    return emptyScalar(line, column);
  }
  if (char === "[") {
    cursor.index += 1;
    const items: YamlNode[] = [];
    for (;;) {
      skipFlowSpace(cursor);
      if (cursor.index >= cursor.text.length) {
        errors.push(`line ${line}: unterminated flow sequence`);
        break;
      }
      if (cursor.text[cursor.index] === "]") {
        cursor.index += 1;
        break;
      }
      if (cursor.text[cursor.index] === ",") {
        cursor.index += 1;
        continue;
      }
      const before = cursor.index;
      items.push(parseFlowNode(cursor, line, errors, depth + 1));
      if (cursor.index === before) {
        // A stray delimiter would otherwise spin here forever.
        errors.push(`line ${line}: unexpected "${cursor.text[before] ?? ""}" in flow sequence`);
        cursor.index += 1;
      }
    }
    return { kind: "sequence", line, items };
  }
  if (char === "{") {
    cursor.index += 1;
    const entries: YamlEntry[] = [];
    for (;;) {
      skipFlowSpace(cursor);
      if (cursor.index >= cursor.text.length) {
        errors.push(`line ${line}: unterminated flow mapping`);
        break;
      }
      if (cursor.text[cursor.index] === "}") {
        cursor.index += 1;
        break;
      }
      if (cursor.text[cursor.index] === ",") {
        cursor.index += 1;
        continue;
      }
      const keyColumn = cursor.index + 1;
      const before = cursor.index;
      const keyNode = parseFlowNode(cursor, line, errors, depth + 1);
      skipFlowSpace(cursor);
      let value: YamlNode = emptyScalar(line, cursor.index + 1);
      if (cursor.text[cursor.index] === ":") {
        cursor.index += 1;
        value = parseFlowNode(cursor, line, errors, depth + 1);
      }
      if (cursor.index === before) {
        errors.push(`line ${line}: unexpected "${cursor.text[before] ?? ""}" in flow mapping`);
        cursor.index += 1;
        continue;
      }
      entries.push({
        key: keyNode.kind === "scalar" ? keyNode.value : "",
        line,
        column: keyColumn,
        value,
      });
    }
    return { kind: "mapping", line, entries };
  }
  if (char === '"' || char === "'") {
    const quoted = readQuoted(cursor.text, cursor.index);
    if (quoted !== null) {
      cursor.index = quoted.end;
      return {
        kind: "scalar",
        line,
        column,
        value: quoted.value,
        style: quoted.style,
        lines: [line],
      };
    }
  }
  let end = cursor.index;
  while (end < cursor.text.length) {
    if (endsFlowScalar(cursor.text, end)) break;
    end += 1;
  }
  const value = cursor.text.slice(cursor.index, end).trim();
  cursor.index = end;
  return { kind: "scalar", line, column, value, style: "plain", lines: [line] };
}

/** Strips a leading anchor (`&name`) or tag (`!tag`); neither changes what a rule reads. */
function stripDecorations(rest: string): string {
  let value = rest;
  for (;;) {
    const match = /^([&!][^\s]*)\s+/.exec(value);
    if (match === null) break;
    value = value.slice(match[0].length);
  }
  return value;
}

/** Parses a value that sits on the same line as its key. */
function parseInlineValue(rest: string, line: number, column: number, errors: string[]): YamlNode {
  const value = stripDecorations(rest);
  if (value === "") return emptyScalar(line, column);
  if (value.startsWith("[") || value.startsWith("{")) {
    const cursor: FlowCursor = { text: value, index: 0 };
    const node = parseFlowNode(cursor, line, errors, 0);
    return node;
  }
  if (value.startsWith('"') || value.startsWith("'")) {
    const quoted = readQuoted(value, 0);
    if (quoted !== null) {
      return {
        kind: "scalar",
        line,
        column,
        value: quoted.value,
        style: quoted.style,
        lines: [line],
      };
    }
  }
  return { kind: "scalar", line, column, value, style: "plain", lines: [line] };
}

/** Header of a block scalar: the style, the chomping indicator and an explicit indent. */
interface BlockHeader {
  readonly style: "literal" | "folded";
  readonly explicitIndent: number | null;
}

/** Reads `|`, `>`, `|-`, `>2+` and friends; returns null when `rest` is not a block header. */
function blockHeader(rest: string): BlockHeader | null {
  const match = /^([|>])([+-]?)(\d*)([+-]?)\s*$/.exec(rest);
  if (match === null) return null;
  const digits = match[3] ?? "";
  return {
    style: match[1] === "|" ? "literal" : "folded",
    explicitIndent: digits === "" ? null : Number.parseInt(digits, 10),
  };
}

/**
 * Reads a `|` / `>` block scalar. Every line keeps its own file number so a
 * rule that matches inside a `run:` script can cite the offending line rather
 * than the `run:` key.
 */
function parseBlockScalar(
  state: ParserState,
  header: BlockHeader,
  keyIndent: number,
  keyLine: number,
  column: number,
): YamlScalar {
  const body: string[] = [];
  const numbers: number[] = [];
  let contentIndent = header.explicitIndent === null ? -1 : keyIndent + header.explicitIndent;

  while (state.index < state.lines.length) {
    const line = state.lines[state.index];
    if (line === undefined) break;
    const blank = line.text === "";
    if (!blank && line.indent <= keyIndent) break;
    if (!blank && contentIndent === -1) contentIndent = line.indent;
    state.index += 1;
    if (blank) {
      body.push("");
      numbers.push(line.number);
      continue;
    }
    const width = contentIndent === -1 ? line.indent : contentIndent;
    // The original line is reconstructed so a rule sees the script as written.
    const padding = Math.max(0, line.indent - width);
    body.push(`${" ".repeat(padding)}${line.text}`);
    numbers.push(line.number);
  }

  while (body.length > 0 && body[body.length - 1] === "") {
    body.pop();
    numbers.pop();
  }

  return {
    kind: "scalar",
    line: keyLine,
    column,
    value: body.join("\n"),
    style: header.style,
    lines: numbers.length === 0 ? [keyLine] : numbers,
  };
}

/** Reads consecutive lines at one indent as a value that is not a mapping. */
function parsePlainScalarBlock(state: ParserState, indent: number): YamlNode {
  const body: string[] = [];
  const numbers: number[] = [];
  let startLine = 0;
  for (;;) {
    const line = peek(state);
    if (line === null || line.indent !== indent || isDashLine(line)) break;
    if (splitKey(line.text, line.indent) !== null) break;
    if (startLine === 0) startLine = line.number;
    body.push(stripComment(line.text));
    numbers.push(line.number);
    state.index += 1;
  }
  if (startLine === 0) return emptyScalar(1, indent + 1);
  // A single line may still be quoted or a flow collection, e.g. the
  // `- "5432:5432"` of a compose `ports:` list.
  const only = body[0];
  if (body.length === 1 && only !== undefined) {
    return parseInlineValue(only, startLine, indent + 1, state.errors);
  }
  return {
    kind: "scalar",
    line: startLine,
    column: indent + 1,
    value: body.join("\n"),
    style: "plain",
    lines: numbers,
  };
}

/** Folds the deeper continuation lines of a plain scalar into it. */
function absorbContinuation(state: ParserState, indent: number, scalar: YamlScalar): YamlScalar {
  const body = [scalar.value];
  const numbers = [...scalar.lines];
  for (;;) {
    const line = peek(state);
    if (line === null || line.indent <= indent) break;
    body.push(stripComment(line.text));
    numbers.push(line.number);
    state.index += 1;
  }
  if (numbers.length === scalar.lines.length) return scalar;
  return { ...scalar, value: body.join("\n"), lines: numbers };
}

/** Parses whatever block follows a `key:` with nothing after the colon. */
function parseValueBlock(state: ParserState, keyIndent: number, keyLine: number): YamlNode {
  const next = peek(state);
  if (next === null) return emptyScalar(keyLine, keyIndent + 1);
  // A block sequence may sit at the key's own indent, which block mappings may not.
  if (isDashLine(next) && next.indent >= keyIndent) return parseBlock(state, next.indent);
  if (next.indent > keyIndent) return parseBlock(state, next.indent);
  return emptyScalar(keyLine, keyIndent + 1);
}

/** Parses a block mapping whose keys all sit at `indent`. */
function parseMapping(state: ParserState, indent: number): YamlNode {
  const entries: YamlEntry[] = [];
  let startLine = 0;
  for (;;) {
    const line = peek(state);
    if (line === null || line.indent !== indent || isDashLine(line)) break;
    const split = splitKey(line.text, line.indent);
    if (split === null) {
      if (entries.length === 0) return parsePlainScalarBlock(state, indent);
      // Not a key and not ours: consume it so the walk always makes progress.
      state.errors.push(
        `line ${line.number}: expected "key: value", found ${line.text.slice(0, 40)}`,
      );
      state.index += 1;
      continue;
    }
    if (startLine === 0) startLine = line.number;
    state.index += 1;

    const header = blockHeader(split.rest);
    let value: YamlNode;
    if (header !== null) {
      value = parseBlockScalar(state, header, indent, line.number, split.valueColumn);
    } else if (split.rest === "") {
      value = parseValueBlock(state, indent, line.number);
    } else {
      const inline = parseInlineValue(split.rest, line.number, split.valueColumn, state.errors);
      value =
        inline.kind === "scalar" && inline.style === "plain"
          ? absorbContinuation(state, indent, inline)
          : inline;
    }
    entries.push({ key: split.key, line: line.number, column: indent + 1, value });
  }
  return { kind: "mapping", line: startLine === 0 ? 1 : startLine, entries };
}

/** Parses a block sequence whose dashes all sit at `indent`. */
function parseSequence(state: ParserState, indent: number): YamlNode {
  const items: YamlNode[] = [];
  let startLine = 0;
  for (;;) {
    const line = peek(state);
    if (line === null || line.indent !== indent || !isDashLine(line)) break;
    if (startLine === 0) startLine = line.number;
    state.index += 1;
    const spacing = /^-(\s*)/.exec(line.text)?.[1] ?? "";
    const dashLength = 1 + spacing.length;
    const rest = line.text.slice(dashLength);

    if (rest === "" || rest.startsWith("#")) {
      const next = peek(state);
      items.push(
        next !== null && next.indent > indent
          ? parseBlock(state, next.indent)
          : emptyScalar(line.number, indent + 1),
      );
      continue;
    }
    const column = line.indent + dashLength;
    const header = blockHeader(rest);
    if (header !== null) {
      items.push(parseBlockScalar(state, header, line.indent, line.number, column + 1));
      continue;
    }
    // Re-enter at the column the item's content starts at, so a mapping opened
    // on the dash line continues correctly on the lines beneath it.
    state.lines[state.index - 1] = { number: line.number, indent: column, text: rest };
    state.index -= 1;
    items.push(parseBlock(state, column));
  }
  return { kind: "sequence", line: startLine === 0 ? 1 : startLine, items };
}

/** Dispatches to the mapping, sequence or scalar parser for a block at `indent`. */
function parseBlock(state: ParserState, indent: number): YamlNode {
  state.depth += 1;
  try {
    if (state.depth > MAX_DEPTH) {
      state.errors.push("document nested too deeply; the rest was not read");
      return emptyScalar(1, 1);
    }
    const line = peek(state);
    if (line === null || line.indent < indent) return emptyScalar(line?.number ?? 1, indent + 1);
    if (isDashLine(line)) return parseSequence(state, line.indent);
    return parseMapping(state, line.indent);
  } finally {
    state.depth -= 1;
  }
}

/** Reads the first document of a YAML file; never throws, never returns partial nonsense silently. */
export function parseYaml(text: string): YamlDocument {
  const errors: string[] = [];
  const lines = toSourceLines(text, errors);
  const state: ParserState = { lines, index: 0, errors, depth: 0 };

  // A leading `---` opens the first document and is not part of it.
  skipBlanks(state);
  const first = state.lines[state.index];
  if (first !== undefined && first.indent === 0 && first.text === "---") state.index += 1;

  const start = peek(state);
  if (start === null) {
    return { root: null, errors };
  }
  const root = parseBlock(state, start.indent);

  skipBlanks(state);
  if (state.index < state.lines.length) {
    const remaining = state.lines[state.index];
    if (remaining !== undefined && (remaining.text === "---" || remaining.text === "...")) {
      errors.push("file holds more than one YAML document; only the first was analysed");
    }
  }
  return { root, errors };
}

/** The node as a mapping, or null when it is something else. */
export function asMapping(node: YamlNode | null | undefined): YamlMapping | null {
  return node !== null && node !== undefined && node.kind === "mapping" ? node : null;
}

/** The node as a sequence, or null when it is something else. */
export function asSequence(node: YamlNode | null | undefined): YamlSequence | null {
  return node !== null && node !== undefined && node.kind === "sequence" ? node : null;
}

/** The node as a scalar, or null when it is something else. */
export function asScalar(node: YamlNode | null | undefined): YamlScalar | null {
  return node !== null && node !== undefined && node.kind === "scalar" ? node : null;
}

/** The mapping entry for `key`, or null. Keys are matched exactly, as GitHub does. */
export function entryOf(node: YamlNode | null | undefined, key: string): YamlEntry | null {
  const mapping = asMapping(node);
  if (mapping === null) return null;
  return mapping.entries.find((candidate) => candidate.key === key) ?? null;
}

/** The value node under `key`, or null. */
export function childOf(node: YamlNode | null | undefined, key: string): YamlNode | null {
  return entryOf(node, key)?.value ?? null;
}

/** A mapping's entries, or an empty list for anything else. */
export function entriesOf(node: YamlNode | null | undefined): readonly YamlEntry[] {
  return asMapping(node)?.entries ?? [];
}

/**
 * A node read as a list: a sequence yields its items, a single scalar or
 * mapping yields itself. YAML lets `on: push` and `on: [push]` mean the same
 * thing, and so does GitHub.
 */
export function itemsOf(node: YamlNode | null | undefined): readonly YamlNode[] {
  if (node === null || node === undefined) return [];
  if (node.kind === "sequence") return node.items;
  if (node.kind === "scalar" && node.style === "empty") return [];
  return [node];
}

/** A scalar's text, or null when the node is not a non-empty scalar. */
export function textOf(node: YamlNode | null | undefined): string | null {
  const scalar = asScalar(node);
  if (scalar === null || scalar.style === "empty") return null;
  return scalar.value;
}

/** True for the YAML 1.1 spellings of true that compose and Actions both accept. */
export function isTrue(node: YamlNode | null | undefined): boolean {
  const value = textOf(node);
  return value !== null && ["true", "yes", "on", "y"].includes(value.trim().toLowerCase());
}

/** The file line of the first line of a scalar that matches, or the scalar's own line. */
export function lineOfMatch(node: YamlNode | null | undefined, pattern: RegExp): number | null {
  const scalar = asScalar(node);
  if (scalar === null) return null;
  const parts = scalar.value.split("\n");
  for (let index = 0; index < parts.length; index += 1) {
    if (pattern.test(parts[index] ?? "")) return scalar.lines[index] ?? scalar.line;
  }
  return null;
}

/** Every line of a scalar that matches, as `{ line, text }` pairs. */
export function linesMatching(
  node: YamlNode | null | undefined,
  pattern: RegExp,
): Array<{ line: number; text: string }> {
  const scalar = asScalar(node);
  if (scalar === null) return [];
  const hits: Array<{ line: number; text: string }> = [];
  const parts = scalar.value.split("\n");
  for (let index = 0; index < parts.length; index += 1) {
    const text = parts[index] ?? "";
    if (pattern.test(text)) hits.push({ line: scalar.lines[index] ?? scalar.line, text });
  }
  return hits;
}

/** The line a node starts on, for anchoring a finding. */
export function lineOf(node: YamlNode | null | undefined): number | null {
  return node === null || node === undefined ? null : node.line;
}
