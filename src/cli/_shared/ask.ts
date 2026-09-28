/**
 * The one place Sentinel reads from the operator.
 *
 * Phase 0.5 exists to ask before ignoring: it lists what the repository
 * contains that the current scope will not check, and the answer has to come
 * from a human. The reader is a plain async iterable of chunks, so the CLI
 * passes `process.stdin` at the composition root and a test passes an array —
 * nothing here touches the process.
 */

/** Reads one line at a time from a byte or text stream. */
export interface LineReader {
  /** The next line without its newline, or `null` at end of input. */
  read(): Promise<string | null>;
}

/** Asks one yes/no question; `fallback` is the answer when input ends. */
export type Asker = (question: string, fallback: boolean) => Promise<boolean>;

/** `y`/`yes` and `n`/`no`, case-insensitive; anything else keeps the default. */
export function parseAnswer(raw: string, fallback: boolean): boolean {
  const answer = raw.trim().toLowerCase();
  if (answer === "y" || answer === "yes") return true;
  if (answer === "n" || answer === "no") return false;
  return fallback;
}

/** `[Y/n]` or `[y/N]`, so the prompt shows what pressing enter does. */
export function answerHint(fallback: boolean): string {
  return fallback ? "[Y/n]" : "[y/N]";
}

/** Splits an async stream of chunks into lines, buffering partial ones. */
export function createLineReader(stream: AsyncIterable<Uint8Array | string>): LineReader {
  const iterator = stream[Symbol.asyncIterator]();
  const decoder = new TextDecoder();
  let buffer = "";
  let done = false;

  /** Pops a complete line off the buffer, or null when it holds none. */
  function takeLine(): string | null {
    const index = buffer.indexOf("\n");
    if (index < 0) return null;
    const line = buffer.slice(0, index);
    buffer = buffer.slice(index + 1);
    return line.endsWith("\r") ? line.slice(0, -1) : line;
  }

  return {
    async read(): Promise<string | null> {
      for (;;) {
        const line = takeLine();
        if (line !== null) return line;
        if (done) {
          if (buffer.length === 0) return null;
          const rest = buffer;
          buffer = "";
          return rest;
        }
        const next = await iterator.next();
        if (next.done === true) {
          done = true;
          continue;
        }
        buffer +=
          typeof next.value === "string"
            ? next.value
            : decoder.decode(next.value, { stream: true });
      }
    },
  };
}

/**
 * An asker over a line reader. End of input answers with the default rather
 * than blocking, so a piped run behaves like an operator who pressed enter.
 */
export function createAsker(reader: LineReader, write: (text: string) => void): Asker {
  return async (question: string, fallback: boolean): Promise<boolean> => {
    write(`${question} ${answerHint(fallback)} `);
    const line = await reader.read();
    if (line === null) {
      write("\n");
      return fallback;
    }
    return parseAnswer(line, fallback);
  };
}
