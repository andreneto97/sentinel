/**
 * What a file under a webhook-shaped path actually **is**.
 *
 * Its own module because the question is harder than the enumerator that asks
 * it, and getting it wrong is expensive in both directions. Treating every file
 * whose path contains `webhooks/` as an inbound receiver inflates the D5
 * denominator with units the model then rejects as misclassified — the domain
 * reports a fraction of its checks as having run over a repository that has
 * nothing of the kind to check. Worse than the coverage lie, each of those
 * units is one
 * `signatureVerified: "no"` away from a `critical` finding on a route that has
 * no third-party signature to verify.
 *
 * Three different things live behind that directory name, and they belong to
 * three different domains:
 *
 * - A **receiver** is an endpoint a third party POSTs to. It has no session to
 *   read, because the sender is not a user; it must prove who sent it, over
 *   the bytes that were actually sent, and refuse a replay. That is D5.
 * - A **management endpoint** is where *your* users register, list and delete
 *   their subscriptions. It reads the caller's own principal and writes a
 *   subscription row — an ordinary authenticated CRUD route, which the route
 *   inventory already enumerates, and which belongs to D2/D6.
 * - **Outbound delivery** is your code calling somebody else's URL. Its risks
 *   are the timeout, the retry policy and the SSRF reachable through a
 *   user-supplied endpoint. That is D7.
 *
 * So the discriminator is not "does it verify a signature" — an unverified
 * receiver is precisely the finding D5 exists for, and demanding verification
 * evidence would filter out every unit worth reporting. It is **whose identity
 * the code uses**: a receiver acts on an incoming payload, a management
 * endpoint acts on the caller's session, and an outbound sender acts on a
 * stored URL. Each of those leaves a shape in the source, and each shape is
 * named here so the disclosure can quote it.
 */

import { groupThousands } from "../contracts/inventory.ts";
import { classifyFile } from "../scan/_file-kind.ts";
import { AUTH_CALLS, AUTH_LIBRARY, AUTH_NULLARY } from "./_route-frameworks/_auth-patterns.ts";

/** What a file under a webhook-shaped path turns out to be. */
export type WebhookRole = "receiver" | "management" | "outbound" | "inert";

/** One named shape, worded as the report cites it. */
interface Signal {
  /** What a reader sees quoted as the evidence. */
  readonly token: string;
  readonly pattern: RegExp;
}

/** A signal that matched, and where. */
export interface Located {
  readonly token: string;
  /** 1-based line of the match. */
  readonly line: number;
}

/** A provider verification call ast-grep matched in the file. */
export interface ProviderCall {
  /** The provider the matched rule belongs to, e.g. `stripe`. */
  readonly provider: string;
  /** 1-based line of the call. */
  readonly line: number;
  /** The call as written, for the evidence sentence. */
  readonly call: string;
}

/** Everything the classifier is given about one candidate file. */
export interface WebhookCandidate {
  /** Repo-relative POSIX path. */
  readonly file: string;
  /** The whole file, as written. */
  readonly text: string;
  /** A confirmed provider verification call in this file, when there was one. */
  readonly providerCall?: ProviderCall | undefined;
}

/** What the classifier decided, and what proves it. */
export interface WebhookShape {
  readonly role: WebhookRole;
  /** The shape that decided the role, in the words the disclosure prints. */
  readonly evidence: string;
  /** 1-based line the deciding shape sits on; 1 when nothing in the file located it. */
  readonly line: number;
  /**
   * 1-based line of the handler boundary, when the file has one.
   *
   * Separate from {@link line} because the two answer different questions.
   * `line` is the citation — the verification call is what a reader wants to
   * look at. The *symbol* has to come from the boundary, because it is part of
   * the unit's identity: taking it from the verification line named a Stripe
   * receiver after the `const event` it assigns to, which would be a different
   * unit the moment somebody renamed the variable.
   */
  readonly boundaryLine: number | undefined;
  /** The verification facts, filled in only for a receiver. */
  readonly facts: WebhookFacts | undefined;
}

/** The facts the D5 prompt and the risk score read off a receiver. */
export interface WebhookFacts {
  /** `yes` only when a call that *compares* an incoming signature was found. */
  readonly signatureVerified: "yes" | "no";
  readonly usesRawBody: "yes" | "no";
  readonly replayProtection: "yes" | "no";
  /** The verifying call, or `none`. */
  readonly verification: string;
  /** What makes this a receiver rather than a route that shares its directory. */
  readonly receiverEvidence: string;
}

// ---------------------------------------------------------------------------
// Which files are even candidates
// ---------------------------------------------------------------------------

/** A path whose own name says it receives somebody else's deliveries. */
const WEBHOOK_PATH = /(^|\/)web-?hooks?(\/|\.|$)/i;

/**
 * `hooks/` and `callback/` mean an inbound endpoint only inside an HTTP tree.
 *
 * `src/hooks/useCart.ts` is a React hook, and a frontend has hundreds of them.
 * The first version of this pattern accepted bare `hooks`, which on a
 * client-heavy repository would have put every one of those files through the
 * classifier and then reported them as examined — a true sentence about the
 * wrong files.
 */
const AMBIGUOUS_PATH = /(^|\/)(?:hooks?|callbacks?)(\/|\.|$)/i;

/** Directory names that mean the file sits on the HTTP surface. */
const HTTP_TREE =
  /(^|\/)(?:api|http|routes?|endpoints?|server|functions|controllers?|handlers?|pages|app)(\/|$)/i;

/** True when a path is worth classifying at all. */
export function isWebhookCandidatePath(file: string): boolean {
  if (WEBHOOK_PATH.test(file)) return true;
  return AMBIGUOUS_PATH.test(file) && HTTP_TREE.test(file);
}

// ---------------------------------------------------------------------------
// The shapes
// ---------------------------------------------------------------------------

/**
 * A request boundary: code some caller outside the process reaches directly.
 *
 * Every pattern here was written against a shape in one of this module's fixture
 * workspaces. The route registration deliberately requires a *quoted path* as
 * the first argument and a router-ish object name: a marker that accepted a bare
 * `.get(` matches `strategies.get(key)` in a domain module, and `Map.get` is not
 * an HTTP entry point.
 */
const ENTRY_SIGNALS: readonly Signal[] = [
  {
    token: "an exported HTTP-method handler",
    pattern:
      /export\s+(?:async\s+)?(?:function|const|let)\s+(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/,
  },
  {
    token: "a (request, response) handler signature",
    pattern: /\(\s*_?(?:req|request)\b[^)]{0,160}?,\s*_?(?:res|response|reply)\b/,
  },
  {
    token: "a route registration with a literal path",
    pattern:
      /\b(?:app|api|router|routes?|server|fastify|hono|instance|elysia)\s*\.\s*(?:get|post|put|patch|delete|all|use|on)\s*\(\s*['"`]\//,
  },
  { token: "a Nest route decorator", pattern: /@(?:Get|Post|Put|Patch|Delete|All)\s*\(/ },
  {
    token: "a fetch event handler",
    pattern:
      /addEventListener\s*\(\s*['"]fetch['"]|export\s+default\s*\{\s*(?:async\s+)?fetch\s*[(:]/,
  },
];

/**
 * A router module: it mounts other people's handlers and defines none itself.
 *
 * A router module under `webhooks/` is a list of `api.<method>(path, handler)`
 * lines and nothing else. It is one unit per registration in the route
 * inventory, and zero receivers here.
 */
const ROUTER_SIGNAL: Signal = {
  token: "a router module that only mounts other handlers",
  pattern: /\b(?:express\s*\.\s*)?Router\s*\(/,
};

/**
 * The caller's own identity — the tell that separates a management endpoint
 * from a receiver.
 *
 * A third party delivering an event has no session on your system, so a
 * handler that reads one is serving *your* user. The `resolve*User*` shape is the
 * conventional helper a management handler calls — `resolveActingMemberId(req)`
 * and its siblings — and delivery code never calls one.
 */
const PRINCIPAL_SIGNALS: readonly Signal[] = [
  {
    token: "the caller's own session read off the request",
    pattern:
      /\b(?:req|request|ctx|context|locals|event)\s*\??\s*\.\s*(?:auth|user|session|principal|identity|actor|locals)\b/,
  },
  {
    token: "a helper that resolves the calling user",
    pattern:
      /\b(?:resolve|get|current|require|assert|ensure|load)[A-Za-z]*(?:User|Principal|Session|Actor|Caller|Viewer|Tenant|Account|Member)(?:Id|Ids)?\s*\(/,
  },
  {
    token: "a permission or role check on the caller",
    pattern: /\bhas[A-Za-z]*(?:Permission|Scope|Role|Access|Admin)s?\s*\(/,
  },
  { token: "an authentication guard", pattern: AUTH_CALLS },
  { token: "a nullary session accessor", pattern: AUTH_NULLARY },
  ...AUTH_LIBRARY.map((pattern) => ({ token: "a library authentication check", pattern })),
];

/**
 * Your code calling somebody else's URL.
 *
 * Delivery is usually split across levels: a sender that builds
 * `{ endpoint, payload, headers, timeoutMs }` and signs it, an HTTP client that
 * performs it, and sometimes a replay path that `fetch`es the stored URL
 * directly. All are D7 units and none has a signature to verify.
 */
const OUTBOUND_SIGNALS: readonly Signal[] = [
  {
    token: "an HTTP client call",
    pattern:
      /\b(?:axios|got|ky|superagent|undici|needle)\s*\.\s*(?:post|put|patch|request|delete)\s*\(/,
  },
  {
    token: "a request built around a stored endpoint",
    pattern:
      /\.\s*(?:post|put|patch|send|request|deliver|dispatch|fire)\s*\(\s*\{[^}]{0,400}?\b(?:endpoint|url|uri|callbackUrl|webhookUrl|targetUrl|httpsEndpoint)\s*:/,
  },
  {
    token: "a fetch to a stored URL",
    pattern:
      /\bfetch\s*\(\s*[A-Za-z_$][\w$.?]*\s*\.\s*(?:url|endpoint|uri|callbackUrl|webhookUrl|targetUrl|httpsEndpoint)\b/,
  },
  {
    token: "a signature computed for an outgoing request",
    pattern: /\b(?:compute|create|generate|make|build|sign)[A-Za-z]*Signature\s*\(/,
  },
];

/** Reading the untouched request body, which every signature scheme needs. */
const RAW_BODY_SIGNALS: readonly Signal[] = [
  { token: "rawBody", pattern: /\brawBody\b/ },
  { token: "express.raw()", pattern: /\bexpress\s*\.\s*raw\s*\(|\braw\s*\(\s*\{\s*type\s*:/ },
  { token: "bodyParser disabled", pattern: /bodyParser\s*:\s*false/ },
  {
    token: "getRawBody()",
    pattern: /\bgetRawBody\s*\(|\bbuffer\s*\(\s*(?:req|request)\b|\bmicro\s*\.\s*text\s*\(/,
  },
  {
    token: "the request body read as bytes",
    pattern: /\b(?:req|request)\s*\.\s*(?:text|arrayBuffer|blob)\s*\(\s*\)/,
  },
];

/**
 * A timestamp window or a delivery id, which is what stops a captured request
 * being replayed.
 *
 * Tighter than the first version, which accepted a bare `timestamp` and
 * `expiresAt` — both of which are ordinary column names, and both of which
 * reported `replayProtection: "yes"` on code that had none.
 */
const REPLAY_SIGNALS: readonly Signal[] = [
  { token: "a signature tolerance", pattern: /\btolerance\b|\btimestampTolerance\b|\bmaxAge\b/ },
  { token: "a timestamp header", pattern: /['"`][\w-]*timestamp['"`]/i },
  { token: "a freshness window", pattern: /Date\.now\s*\(\s*\)\s*-|\bwithinWindow\b|\bisFresh\b/ },
];

/**
 * Calls that *compare* an incoming signature.
 *
 * `createHmac` is deliberately absent: it computes a digest, which is what both
 * a verifier and a signer do, and in a repository that only sends deliveries
 * every `createHmac` call is a signer. It counts as verification further down,
 * and only in a file that also *reads* a signature header.
 */
const VERIFICATION_SIGNALS: readonly Signal[] = [
  { token: "timingSafeEqual()", pattern: /\btimingSafeEqual\s*\(/ },
  {
    token: "a verify call",
    pattern: /\bverify[A-Za-z]*(?:Signature|Webhook|Request|Payload|Header)s?\s*\(/,
  },
  { token: "constructEvent()", pattern: /\bconstructEvent(?:Async)?\s*\(/ },
  { token: "validateRequest()", pattern: /\bvalidateRequest\s*\(/ },
  { token: ".verify()", pattern: /\.\s*verify\s*\(/ },
];

/** A digest computed by hand; verification only when a signature header is read. */
const HAND_ROLLED_DIGEST: Signal = {
  token: "createHmac() compared against the signature header",
  pattern: /\bcreateHmac\s*\(/,
};

/** Header names a signature travels in. */
const SIGNATURE_HEADER =
  /(?:headers?|header|get|has)\s*(?:\[|\(\s*)\s*(['"`])([\w-]*(?:signature|hmac|signed)[\w-]*)\1\s*(?:\]|\))/gi;

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

/**
 * Blanks out comments and template-literal prose, keeping every offset.
 *
 * An OpenAPI registry documents the delivery format in a template literal —
 * *"verify against the raw request body"*, with `rawBody` spelled in a code
 * span — and a classifier that reads the whole file reads that sentence as a
 * raw-body read and calls a document a webhook receiver. Only the *prose* forms
 * go: single- and double-quoted
 * strings survive, because a signature header name is a quoted literal and
 * reading one is the strongest receiver evidence there is. Removed characters
 * become spaces and newlines are kept, so an offset in the result is the same
 * offset in the source and {@link lineAt} needs no adjustment.
 */
export function stripProse(text: string): string {
  const out = text.split("");
  /** Brace depth inside the innermost `${...}`; the stack holds the enclosing ones. */
  let braceDepth = 0;
  const enclosing: number[] = [];
  let state: "code" | "line-comment" | "block-comment" | "single" | "double" | "template" = "code";

  const blank = (index: number): void => {
    if (out[index] !== "\n") out[index] = " ";
  };

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    const next = text[index + 1];
    if (state === "line-comment") {
      if (char === "\n") state = "code";
      else blank(index);
      continue;
    }
    if (state === "block-comment") {
      blank(index);
      if (char === "*" && next === "/") {
        blank(index + 1);
        index += 1;
        state = "code";
      }
      continue;
    }
    if (state === "single" || state === "double") {
      if (char === "\\") index += 1;
      else if ((state === "single" && char === "'") || (state === "double" && char === '"')) {
        state = "code";
      }
      continue;
    }
    if (state === "template") {
      if (char === "\\") {
        blank(index);
        blank(index + 1);
        index += 1;
        continue;
      }
      if (char === "$" && next === "{") {
        enclosing.push(braceDepth);
        braceDepth = 0;
        state = "code";
        index += 1;
        continue;
      }
      if (char === "`") {
        state = "code";
        continue;
      }
      blank(index);
      continue;
    }
    // state === "code"
    if (char === "/" && next === "/") {
      state = "line-comment";
      blank(index);
      continue;
    }
    if (char === "/" && next === "*") {
      state = "block-comment";
      blank(index);
      continue;
    }
    if (char === "'") state = "single";
    else if (char === '"') state = "double";
    else if (char === "`") state = "template";
    else if (char === "{") braceDepth += 1;
    else if (char === "}") {
      if (braceDepth === 0 && enclosing.length > 0) {
        braceDepth = enclosing.pop() ?? 0;
        state = "template";
      } else if (braceDepth > 0) braceDepth -= 1;
    }
  }
  return out.join("");
}

/** The 1-based line a character offset falls on. */
export function lineAt(text: string, offset: number): number {
  let line = 1;
  const limit = Math.min(offset, text.length);
  for (let index = 0; index < limit; index += 1) {
    if (text.charCodeAt(index) === 10) line += 1;
  }
  return line;
}

/**
 * The earliest signal in the list that matches, and the line it matched on.
 *
 * Earliest by declaration order rather than by position, so the token a
 * disclosure quotes does not change when somebody reorders a file.
 */
export function firstSignal(text: string, signals: readonly Signal[]): Located | null {
  for (const signal of signals) {
    // A global pattern carries `lastIndex` between calls, and some of these are
    // imported from `_auth-patterns.ts`, where another caller owns them.
    const pattern = signal.pattern.global
      ? new RegExp(signal.pattern.source, signal.pattern.flags.replace("g", ""))
      : signal.pattern;
    const found = pattern.exec(text);
    if (found !== null) return { token: signal.token, line: lineAt(text, found.index) };
  }
  return null;
}

/**
 * Where a signature header is read, and where one is written.
 *
 * Both directions, because they are the same text and opposite meanings:
 * `headers['x-delivery-signature'] = computeDeliverySignature(...)` is an
 * outbound signer, and a check that only looked for the header name would report
 * it as a receiver that verifies.
 */
export function signatureHeaderUse(text: string): {
  readonly read: Located | null;
  readonly write: Located | null;
} {
  const finder = new RegExp(SIGNATURE_HEADER.source, "gi");
  let read: Located | null = null;
  let write: Located | null = null;
  let found = finder.exec(text);
  while (found !== null) {
    const name = found[2] ?? "header";
    const after = text.slice(found.index + found[0].length, found.index + found[0].length + 4);
    const located: Located = { token: `the ${name} header`, line: lineAt(text, found.index) };
    if (/^\s*=[^=]/.test(after)) write ??= located;
    else read ??= located;
    found = finder.exec(text);
  }
  return { read, write };
}

// ---------------------------------------------------------------------------
// The decision
// ---------------------------------------------------------------------------

/** The strongest proof that a file receives somebody else's deliveries. */
function receiverProof(candidate: WebhookCandidate): Located | null {
  const { text, providerCall } = candidate;
  if (providerCall !== undefined) {
    return {
      token: `a ${providerCall.provider} verification call, ${providerCall.call}`,
      line: providerCall.line,
    };
  }
  const header = signatureHeaderUse(text).read;
  if (header !== null) return { token: `${header.token}, read off the request`, line: header.line };
  return firstSignal(text, RAW_BODY_SIGNALS);
}

/** The verifying call, when the file compares an incoming signature. */
function verificationOf(text: string): Located | null {
  const direct = firstSignal(text, VERIFICATION_SIGNALS);
  if (direct !== null) return direct;
  if (signatureHeaderUse(text).read === null) return null;
  return firstSignal(text, [HAND_ROLLED_DIGEST]);
}

/** The facts a receiver carries into the audit prompt. */
function factsOf(text: string, receiverEvidence: string): WebhookFacts {
  const verification = verificationOf(text);
  return {
    signatureVerified: verification === null ? "no" : "yes",
    usesRawBody: firstSignal(text, RAW_BODY_SIGNALS) === null ? "no" : "yes",
    replayProtection: firstSignal(text, REPLAY_SIGNALS) === null ? "no" : "yes",
    verification: verification?.token ?? "none",
    receiverEvidence,
  };
}

/**
 * Decides what one candidate is, from the candidate's own source.
 *
 * The order is the argument:
 *
 * 1. **A confirmed provider verification call, a signature header read off the
 *    request, or a raw-body read is a receiver**, whatever else the file does.
 *    Nothing but a receiver has a reason to look at those.
 * 2. **A request boundary that reads the caller's own principal, or a router
 *    module, is management.** This is where the subscription CRUD handlers and
 *    the router that mounts them go, and it is the step a path-only filter
 *    skips entirely.
 * 3. **A request boundary that does not is a receiver** — with
 *    `signatureVerified: "no"`, which is the finding. An unverified receiver
 *    has no verification evidence by definition, so requiring some would drop
 *    exactly the units D5 exists to report.
 * 4. **Code that builds a request to a stored URL is outbound delivery**,
 *    whose risks are D7's.
 * 5. Everything else shares a directory name and nothing else.
 */
export function classifyWebhookCandidate(candidate: WebhookCandidate): WebhookShape {
  const text = stripProse(candidate.text);
  const entry = firstSignal(text, ENTRY_SIGNALS);

  const proof = receiverProof({ ...candidate, text });
  if (proof !== null) {
    return {
      role: "receiver",
      evidence: proof.token,
      line: proof.line,
      boundaryLine: entry?.line,
      facts: factsOf(text, proof.token),
    };
  }

  if (entry !== null) {
    const router = firstSignal(text, [ROUTER_SIGNAL]);
    if (router !== null) {
      return {
        role: "management",
        evidence: router.token,
        line: router.line,
        boundaryLine: entry.line,
        facts: undefined,
      };
    }
    const principal = firstSignal(text, PRINCIPAL_SIGNALS);
    if (principal !== null) {
      return {
        role: "management",
        evidence: `${entry.token}, and ${principal.token}`,
        line: principal.line,
        boundaryLine: entry.line,
        facts: undefined,
      };
    }
    return {
      role: "receiver",
      evidence: `${entry.token}, with no session of its own to read`,
      line: entry.line,
      boundaryLine: entry.line,
      facts: factsOf(text, entry.token),
    };
  }

  const outbound = firstSignal(text, OUTBOUND_SIGNALS);
  if (outbound !== null) {
    return {
      role: "outbound",
      evidence: outbound.token,
      line: outbound.line,
      boundaryLine: undefined,
      facts: undefined,
    };
  }

  return {
    role: "inert",
    evidence: "no request boundary and no outbound call",
    line: 1,
    boundaryLine: undefined,
    facts: undefined,
  };
}

// ---------------------------------------------------------------------------
// The disclosure
// ---------------------------------------------------------------------------

/** One classified candidate, kept so the run can say what became of it. */
export interface ClassifiedCandidate {
  readonly file: string;
  readonly shape: WebhookShape;
}

/** How many citations a reclassification clause names before it stops. */
export const MAX_NAMED_RECLASSIFICATIONS = 4;

/** `a.ts:3, b.ts:7 and 9 more` — the evidence a clause fits in a sentence. */
function citeAll(entries: readonly ClassifiedCandidate[]): string {
  const named = entries
    .slice(0, MAX_NAMED_RECLASSIFICATIONS)
    .map((entry) => `${entry.file}:${entry.shape.line}`);
  const rest = entries.length - named.length;
  const cited = named.join(", ");
  return rest === 0 ? cited : `${cited} and ${rest} more`;
}

/** One sentence in both numbers, because a coverage note is read, not parsed. */
interface Counted {
  readonly one: string;
  readonly many: string;
}

/** `1 file` / `60 files`. */
function plural(count: number, words: Counted): string {
  return `${groupThousands(count)} ${count === 1 ? words.one : words.many}`;
}

/** What each role is, and which inventory or domain owns it instead. */
const ROLE_CLAUSE: Readonly<Record<Exclude<WebhookRole, "receiver">, Counted>> = {
  management: {
    one: "is a webhook-subscription management endpoint, which reads the caller's own session and writes a subscription row: the route inventory enumerates it and it carries no third-party signature to verify",
    many: "are webhook-subscription management endpoints, which read the caller's own session and write a subscription row: the route inventory enumerates them and they carry no third-party signature to verify",
  },
  outbound: {
    one: "is outbound delivery code, which builds a request to a stored URL: its timeout, retry and SSRF risks belong to reliability rather than to a signature check",
    many: "are outbound delivery code, which builds a request to a stored URL: those timeout, retry and SSRF risks belong to reliability rather than to a signature check",
  },
  inert: {
    one: "is neither a request boundary nor an outbound call, so no unit of any kind describes it",
    many: "are neither a request boundary nor an outbound call, so no unit of any kind describes them",
  },
};

/** The roles a clause is written for, in the order the sentence lists them. */
const DISCLOSED_ROLES: ReadonlyArray<Exclude<WebhookRole, "receiver">> = [
  "management",
  "outbound",
  "inert",
];

/**
 * The sentence the coverage section prints about what the path heuristic turned
 * up and what it actually was.
 *
 * Only production candidates are tallied. Not because the others do not matter
 * — a receiver in a test file still becomes a draft, and the unit policy
 * excludes and discloses it in its own words — but because the classifier
 * counts *candidates*, and a tally that folded a suite's worth of supertest
 * files into "neither a request boundary nor an outbound call" would be a true
 * sentence nobody can act on. Their count is stated instead.
 *
 * Undefined when nothing was reclassified, so a repository whose every
 * candidate is a receiver says nothing rather than saying zero.
 */
export function reclassificationNote(
  classified: readonly ClassifiedCandidate[],
  nonProductionCandidates: number,
): string | undefined {
  const production = classified.filter((entry) => isProductionCandidate(entry.file));
  const others = production.filter((entry) => entry.shape.role !== "receiver");
  if (production.length === 0) {
    // Every candidate was test or documentation code. A receiver among them is
    // still drafted and still disclosed, by the unit policy in its own words;
    // this says what the classifier looked at and found nothing to classify.
    return nonProductionCandidates === 0
      ? undefined
      : `${plural(nonProductionCandidates, {
          one: "candidate under a webhook-shaped path is",
          many: "candidates under a webhook-shaped path are",
        })} outside production code, and no production file sits on one`;
  }
  if (others.length === 0) return undefined;

  const clauses: string[] = [];
  for (const role of DISCLOSED_ROLES) {
    const entries = others.filter((entry) => entry.shape.role === role);
    if (entries.length === 0) continue;
    const cited = role === "inert" ? "" : ` (${citeAll(entries)})`;
    const words = ROLE_CLAUSE[role];
    clauses.push(
      `${groupThousands(entries.length)} ${entries.length === 1 ? words.one : words.many}${cited}`,
    );
  }

  const receivers = production.length - others.length;
  const tail =
    nonProductionCandidates === 0
      ? ""
      : `; ${plural(nonProductionCandidates, {
          one: "further candidate is outside production code",
          many: "further candidates are outside production code",
        })}`;
  const counted = plural(production.length, {
    one: "file under a webhook-shaped path was classified from its own evidence",
    many: "files under a webhook-shaped path were classified from their own evidence",
  });
  const head = `${counted} rather than from the path: ${clauses.join("; ")}`;
  return receivers === 0
    ? `${head}; this repository has no inbound webhook receiver${tail}`
    : `${head}; ${plural(receivers, { one: "is an inbound receiver", many: "are inbound receivers" })}${tail}`;
}

/**
 * True when the file is production code.
 *
 * Asked here as well as by the unit policy because the two count different
 * things: the policy decides whether a *unit* is worth a verdict, this decides
 * whether a *candidate* belongs in the reclassification tally.
 */
export function isProductionCandidate(file: string): boolean {
  return classifyFile(file).kind === "production";
}
