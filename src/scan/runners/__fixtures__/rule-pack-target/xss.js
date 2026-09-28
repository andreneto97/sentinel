// Intentionally vulnerable corpus for the Sentinel opengrep rule pack.
// Each block is annotated with the rule id it must trigger; `SAFE:` blocks must
// stay clean, which is what keeps the rules from being written too broadly.

/** appsec.xss.inner-html-assignment */
export function renderComment(el, comment) {
  el.innerHTML = comment.body;
}

/** appsec.xss.inner-html-assignment */
export function appendRow(el, row) {
  el.insertAdjacentHTML("beforeend", row.html);
}

/** SAFE: a literal has nothing user-controlled in it. */
export function clear(el) {
  el.innerHTML = "";
}

/** SAFE: textContent is not parsed as markup. */
export function renderName(el, name) {
  el.textContent = name;
}

/** appsec.xss.document-write */
export function printBanner(message) {
  document.write(message);
}

/** appsec.xss.javascript-url-from-variable */
export function buildAction(handlerName) {
  return `javascript:${handlerName}()`;
}

/** appsec.xss.eval-on-non-literal */
export function applyFormula(expression) {
  // biome-ignore lint/security/noGlobalEval: intentionally vulnerable fixture
  return eval(expression);
}

/** appsec.xss.eval-on-non-literal */
export function compileTemplate(source) {
  return new Function("data", source);
}

/** appsec.xss.unescaped-html-response */
export function searchHandler(req, res) {
  res.send(`<h1>Results for ${req.query.term}</h1>`);
}

/** SAFE: the response is JSON, and the value is not spliced into markup. */
export function searchJsonHandler(req, res) {
  res.json({ term: req.query.term });
}

/** appsec.xss.angular-bypass-security-trust */
export function trustNotice(sanitizer, notice) {
  return sanitizer.bypassSecurityTrustHtml(notice.body);
}
