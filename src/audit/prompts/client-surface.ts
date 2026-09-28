/**
 * The client-surface prompts (D2): role gates and sinks.
 *
 * Both kinds exist for the same reason: a grep can find them and only an audit
 * can judge them.
 *
 * A **role gate** is not a finding on its own — hiding a button from a viewer is
 * a reasonable UX decision. It becomes the most common authorization bug in a
 * React or Next.js codebase when the endpoint behind the hidden button performs
 * no check of its own. So the gate's unit carries the endpoint the gated action
 * calls, and `src/audit/batch.ts` attaches that route's source as related
 * context: the model is asked to compare the two, not to speculate about one.
 *
 * A **sink** is a place where a string becomes markup, SQL, a shell command or
 * code. The question is always reachability: can a value that came from a request
 * or from a database row get here, and is it escaped on the way. A sink fed by a
 * literal is an assurance, and saying so is worth as much as the finding.
 */

import { type AuditCheck, type PromptSpec, createPromptBuilder } from "./_shared.ts";

/** The D2 questions asked of every client-side role gate. */
export const ROLE_GATE_CHECKS: readonly AuditCheck[] = [
  {
    name: "server-side-counterpart",
    statement: "every client-side role gate is backed by a server-side check",
    rule: "appsec.client-only-authorization",
    question:
      "is the rule this gate expresses also enforced by the server, in the handler the gated action calls?",
    fails:
      "the related handler you were shown performs no equivalent role or ownership check, so calling the endpoint directly bypasses the gate",
    ceiling: "critical",
    notApplicable:
      "the gate hides no action — it only changes wording or layout — or no related handler was provided and the facts name no endpoint",
  },
  {
    name: "gate-input-trust",
    statement: "role gates decide on values the client cannot change",
    rule: "appsec.weak-role-check",
    question: "does the gate decide on a value the client cannot change?",
    fails:
      "the decision reads a role from local storage, from a cookie the client writes, from an unverified token payload, or from a value the user supplies",
    ceiling: "high",
  },
  {
    name: "privileged-data-exposure",
    statement: "gated data is never sent to the client in the first place",
    rule: "appsec.client-side-secret",
    question:
      "does the code merely hide data the client already has, or does it avoid fetching it at all?",
    fails:
      "privileged data, a key or another user's fields are already in the payload the client received and the gate only stops them being rendered",
    ceiling: "high",
    notApplicable: "the gate controls an action rather than a display",
  },
  {
    name: "default-deny",
    statement: "role gates deny while the role is still unknown",
    rule: "appsec.gate-fails-open",
    question: "while the role is unknown — loading, undefined, an error — does the gate deny?",
    fails:
      "an undefined or still-loading role takes the permitted branch, so the privileged control is shown before the answer arrives",
    ceiling: "medium",
  },
];

/** How to read the facts the role-gate enumerator attaches to a unit. */
const ROLE_GATE_ATTRIBUTES: Readonly<Record<string, string>> = {
  expression: "the condition Sentinel matched, as written",
  check: "which pattern matched it: a comparison, a call, a flag, a wrapper component",
  subject: "the value being tested",
  uiElement: "the element the gate appears to control",
  endpoint: "the endpoint the gated action calls, when Sentinel could resolve one",
  path: "the same endpoint, in the shared vocabulary that joins it to a route unit",
  symbol: "the component or function the gate sits in",
};

/** The role-gate prompt spec. */
export const ROLE_GATE_PROMPT: PromptSpec = {
  kind: "role-gate",
  noun: "client-side role gate",
  mission:
    "You decide whether each authorization decision made in the browser is backed by the same decision on the server.",
  checks: ROLE_GATE_CHECKS,
  attributes: ROLE_GATE_ATTRIBUTES,
  guidance: [
    "A gate with no server-side counterpart is an authorization finding on the ENDPOINT, cited at the gate: the fix belongs in the handler. Cite both, with the handler as evidence.",
    "When a related handler was provided, your answer must be about that code. When none was, the check is `not-applicable` and the note names the endpoint whose handler you would have needed.",
    "Hiding a control is legitimate defence in depth once the server enforces the rule. In that case the check passes and the gate is an assurance, not a finding.",
    "Do not report the gate itself as 'authorization in the client' without naming what it protects and what the server does instead.",
  ],
};

/** The D2 questions asked of every injection or XSS sink. */
export const SINK_CHECKS: readonly AuditCheck[] = [
  {
    name: "input-reachability",
    statement: "no untrusted value reaches the sink",
    rule: "appsec.unsanitised-sink",
    question:
      "can a value that originates in a request, a URL, a database row or a third-party response reach this sink?",
    fails:
      "the argument is, or is built from, a value that is not a constant in the code you were shown",
    ceiling: "critical",
    notApplicable:
      "the argument is a literal or a constant defined in the code shown, with no interpolation",
  },
  {
    name: "sanitisation",
    statement: "dynamic values are escaped or parameterised for the sink they enter",
    rule: "appsec.missing-sanitisation",
    question:
      "is the dynamic part escaped, parameterised or validated for the sink it enters — HTML escaping or a sanitiser for markup, a bound parameter for SQL, an argument array for a command, a parsed value for an interpreter?",
    fails:
      "the value enters the sink unescaped, unparameterised or sanitised for the wrong context",
    ceiling: "critical",
    notApplicable: "nothing dynamic reaches the sink",
  },
  {
    name: "sink-necessity",
    statement: "the dangerous API is the only way to do the job",
    rule: "appsec.avoidable-sink",
    question: "is the dangerous API needed at all, or would a safe construction do the same job?",
    fails:
      "the same result is available without the sink — text assignment instead of HTML, a parameterised query instead of a raw string, a spawn with an argument array instead of a shell",
    ceiling: "medium",
  },
];

/** How to read the facts the sink enumerator attaches to a unit. */
const SINK_ATTRIBUTES: Readonly<Record<string, string>> = {
  sinkType: "the class of sink: `xss`, `sql`, `command`, `code`",
  api: "the API that is the sink, as written",
  dynamic: "`yes` when the argument is not a literal",
  argument: "the argument Sentinel matched",
  expression: "the whole matched expression",
  symbol: "the function or component the sink sits in",
};

/** The sink prompt spec. */
export const SINK_PROMPT: PromptSpec = {
  kind: "sink",
  noun: "injection or XSS sink",
  mission:
    "You decide whether untrusted input can reach each dangerous API, and whether it is neutralised for the context it enters.",
  checks: SINK_CHECKS,
  attributes: SINK_ATTRIBUTES,
  guidance: [
    "Trace the argument inside the slice you were given. If it comes from a parameter of the enclosing function, say so and describe the caller you would need to see: that is a `medium` confidence finding, not a `high` one.",
    "Escaping is context-sensitive. A value escaped for HTML and then placed in an attribute, a URL or a script block is still a finding.",
    "A sanitiser with an allow-list that permits `href`, `src` or event handlers is not a sanitiser for this purpose.",
    "`dynamic: no` usually means the sink is fed a literal. Confirm it in the slice, then record the checks as passing — a sink that cannot be reached is an assurance worth publishing.",
    "A database row is untrusted input. Stored markup rendered into a page is stored XSS.",
  ],
};

/** The role-gate prompt builder. */
export const roleGatePromptBuilder = createPromptBuilder(ROLE_GATE_PROMPT);

/** The sink prompt builder. */
export const sinkPromptBuilder = createPromptBuilder(SINK_PROMPT);
