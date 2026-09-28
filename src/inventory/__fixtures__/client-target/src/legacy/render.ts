/** The one DOM member this fixture touches; the repo's tsconfig has no DOM lib. */
interface HTMLElement {
  innerHTML: string;
}

/** Writes untrusted markup into the document. */
export function renderBanner(target: HTMLElement, html: string): void {
  target.innerHTML = html;
}

/** Evaluates a string the server sent. */
export function runRecipe(source: string): unknown {
  // biome-ignore lint/security/noGlobalEval: the fixture exists to be enumerated as an eval sink.
  return eval(source);
}
