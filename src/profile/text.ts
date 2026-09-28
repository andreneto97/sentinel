/** Escapes a string so it can be embedded in a `RegExp` literally. */
export function escapeRegExp(literal: string): string {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Splits text into lines, tolerating CRLF, so line numbers match what an editor shows. */
export function toLines(text: string): string[] {
  return text.split(/\r?\n/);
}

/** 1-based line number of the first line matching `pattern`, or `undefined`. */
export function lineOf(lines: readonly string[], pattern: RegExp | string): number | undefined {
  const test = typeof pattern === "string" ? new RegExp(escapeRegExp(pattern)) : pattern;
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (line !== undefined && test.test(line)) return i + 1;
  }
  return undefined;
}

/** 1-based line number of a JSON object key (`"name":`) at any nesting depth. */
export function lineOfJsonKey(lines: readonly string[], key: string): number | undefined {
  return lineOf(lines, new RegExp(`"${escapeRegExp(key)}"\\s*:`));
}

/**
 * Matches an ES import, a bare `import "pkg"`, or a `require()` of `pkg`
 * (including deep paths such as `next/server`).
 *
 * Import statements are the only evidence Sentinel accepts that a package is
 * actually used in a file — a file *named* like a framework proves nothing.
 */
export function importPattern(packageName: string): RegExp {
  const pkg = escapeRegExp(packageName);
  const spec = `${pkg}(?:/[^'"\`]*)?`;
  return new RegExp(
    `(?:from\\s*['"\`]${spec}['"\`]|require\\(\\s*['"\`]${spec}['"\`]|import\\s*\\(\\s*['"\`]${spec}['"\`]|^\\s*import\\s*['"\`]${spec}['"\`])`,
  );
}
