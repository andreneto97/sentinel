/**
 * The shapes that say somebody else's codebase leaked into this one.
 *
 * Sentinel is pointed at other people's repositories. Everything it carries as
 * an example — a fixture, a docstring, a README sentence, a recorded transcript
 * — therefore has to be *invented here*, and the invention has to be visible to
 * a reader who has never seen the repository it was modelled on. Three
 * pre-publication reviews rejected this tree: once for real identifiers, once
 * for real knowledge in fixtures, once for real case histories in prose. Each
 * round found a new category, because nothing enforced the rule.
 *
 * This module is that enforcement. `no-real-world-data.test.ts` walks every file
 * in the repository and reports each match below with the file, the line, the
 * matched text and **why that shape is a leak**, so whoever trips it can fix the
 * data rather than reach for a suppression.
 *
 * ## How to read a shape
 *
 * Each {@link LeakShape} is a pattern plus three pieces of prose:
 *
 * - `why` — the sentence a reader gets when it fires. It says what the shape
 *   proves about the tree, never just "banned".
 * - `witness` — a string this shape **must** flag. The test asserts it, so a
 *   pattern that stops matching anything fails loudly instead of going quiet.
 * - `nearMiss` — the legitimate neighbour it must **not** flag. This is where a
 *   shape's narrowness is documented and tested: `.env.local` is not a machine
 *   name, a PEM header with no body is not a key.
 *
 * `allow` is the seam for the cases a pattern cannot tell apart on its own — a
 * credential the surrounding code builds out of pieces, a placeholder a vendor
 * publishes in its own documentation. It returns the *reason* the match is fine,
 * not a boolean, so the reason is written down at the point it is granted.
 *
 * ## How to extend the allowlist
 *
 * There are exactly three allowlists, all in this file, all one line per entry
 * with the reason on the same line:
 *
 * - {@link PUBLISHED_PLACEHOLDERS} — literals a vendor publishes as an example.
 * - {@link PLACEHOLDER_OWNERS} — the organisation names this tree may say.
 * - {@link EXEMPT_FILES} — files the walker skips, with the reason it can.
 *
 * Adding a row is a visible act in a diff. Adding a *category* of exception is
 * not possible without editing a shape, which is the point: the failure modes
 * above all began as "this one is fine".
 *
 * ## What this cannot do, so that nobody trusts it too far
 *
 * A pattern cannot recognise a proper noun it has never been told about, and a
 * denylist of the organisations earlier rounds removed would republish their
 * names here. So the proper-noun rule is enforced only where a name has to sit in
 * a *structural* position and can therefore be checked against a closed list:
 * {@link LEAK_SHAPES} `third-party-owner` requires the owner of every action and
 * every container image to be a documented placeholder or a named public vendor,
 * and `custom-header-prefix` asks the same of the prefix of a delivery header.
 * A company name dropped into a sentence, a variable or a domain noun is still on
 * the reviewer. Likewise {@link isIllustrativeCount} judges a count by its
 * roundness, so a round figure lifted off a real run passes.
 *
 * Both gaps are cheap to close for a *specific* leak once a review names it: add
 * the shape, add its witness, add the neighbour it must not flag.
 */

import { join } from "node:path";
import type { FileSystem } from "../ports/file-system.ts";

// ---------------------------------------------------------------------------
// The allowlists
// ---------------------------------------------------------------------------

/**
 * Literals that look like real-world data and are not, because the vendor that
 * owns the format publishes them as the example. One row, one reason.
 */
export const PUBLISHED_PLACEHOLDERS: ReadonlyArray<readonly [literal: string, reason: string]> = [
  ["111122223333", "AWS's own example account id, used throughout its documentation"],
  ["AKIAIOSFODNN7EXAMPLE", "AWS's own example access key id, published in its documentation"],
  ["sentinel", "this tool's own name, which every file in the tree is entitled to say"],
];

/** Fast lookup over {@link PUBLISHED_PLACEHOLDERS}. */
const PLACEHOLDER_REASON = new Map(PUBLISHED_PLACEHOLDERS);

/** The reason a literal is allowed, or null when it is not on the list. */
export function publishedPlaceholderReason(literal: string): string | null {
  return PLACEHOLDER_REASON.get(literal) ?? null;
}

/**
 * The only organisations this tree may name in an owner position — a GitHub
 * Actions `uses:`, a container image, a package scope, a custom HTTP header
 * prefix.
 *
 * Two kinds of row, and the distinction is the whole point of the list: an
 * invented placeholder, or a real vendor whose own published artifact a fixture
 * has to name to be realistic. Anything else in an owner position is the name of
 * whoever wrote the repository the fixture was modelled on.
 */
export const PLACEHOLDER_OWNERS: ReadonlyArray<readonly [owner: string, reason: string]> = [
  // Invented, and named so in the fixture READMEs.
  ["example-org", "the RFC 2606 style placeholder this tree standardised on"],
  ["some-org", "placeholder for a third-party organisation in the CI fixtures"],
  ["myorg", "placeholder owner in the container fixtures"],
  ["acme", "the universal placeholder company"],
  ["demo", "placeholder owner in the scan fixtures"],
  ["fleet", "the invented bike-share domain of the provenance and workspace fixtures"],
  ["dock", "the same invented bike-share domain"],
  ["x-fleet", "the one custom webhook header prefix those fixtures sign deliveries with"],
  ["nx-demo", "placeholder workspace name in the nx fixture"],
  ["scope", "literal placeholder in `@scope/pkg`"],
  ["shared", "generic workspace library name"],
  // Real, public, and named on purpose: these are the artifacts under test.
  ["actions", "GitHub's own actions, which the CI rules grade against"],
  ["aws-actions", "AWS's published actions, cited by the CI rules"],
  ["google-github-actions", "Google's published actions, cited by the CI prompt"],
  ["docker", "Docker's published actions and images"],
  ["oven-sh", "Bun's published setup action"],
  ["ghcr.io", "GitHub's registry host, not an owner"],
  ["localstack", "a public dev-only image the container rules recognise by name"],
  ["grafana", "a public dashboard image the container rules recognise by name"],
  ["opensearchproject", "a public dashboard image the container rules recognise by name"],
];

/** Fast lookup over {@link PLACEHOLDER_OWNERS}. */
const OWNER_REASON = new Map(PLACEHOLDER_OWNERS);

/**
 * Files the walker skips.
 *
 * One entry, and it has to be one: a module that defines credential shapes
 * necessarily contains one of each. It holds patterns and witnesses and no data,
 * which is what makes skipping it safe — and the witnesses here are assembled
 * from pieces rather than pasted, so even this file carries no complete
 * credential-shaped literal.
 */
export const EXEMPT_FILES: ReadonlyArray<readonly [file: string, reason: string]> = [
  [
    "src/meta/_leak-shapes.ts",
    "defines the shapes, so it must contain one of each; patterns and witnesses only, never data",
  ],
];

/** Directories the walk never descends into. */
export const SKIPPED_DIRECTORIES: readonly string[] = [
  ".git",
  "node_modules",
  "dist",
  // `sentinel/` and `sentinel-out/` are a run's output inside a *target*
  // repository; when a developer analyses this repo they land here too.
  "sentinel",
  "sentinel-out",
];

// ---------------------------------------------------------------------------
// The predicates a shape needs to tell a leak from its legitimate neighbour
// ---------------------------------------------------------------------------

/**
 * True when the line builds its credential-shaped value out of pieces rather
 * than holding one.
 *
 * `ghp_${"x".repeat(36)}` is a token's *length and prefix*, which is all a
 * severity test needs; it is not a token, and a secret scanner reading this
 * repository has nothing to match. The distinction is mechanical: an
 * interpolation, a `repeat`, a `padStart` or a concatenation inside the literal.
 */
export function buildsValueProgrammatically(line: string): boolean {
  return /\$\{|\.repeat\(|\.padStart\(|\.padEnd\(|String\.fromCharCode|"\s*\+\s*"/.test(line);
}

/**
 * True when a 12-digit id is *visibly* invented, so no reader has to wonder
 * whether it is somebody's AWS account.
 *
 * Three ways to be visibly invented, and a real account id is none of them:
 * three or fewer distinct digits (`111122223333`, `000000000000`), or a counting
 * sequence up or down (`123456789012`, `210987654321`).
 */
export function looksSyntheticDigits(digits: string): string | null {
  const distinct = new Set(digits).size;
  if (distinct <= 3) return `only ${distinct} distinct digit(s), so it reads as invented`;
  const steps = [...digits].slice(1).map((digit, index) => {
    const previous = Number(digits[index]);
    return (Number(digit) - previous + 10) % 10;
  });
  if (steps.every((step) => step === 1)) return "an ascending counting sequence";
  if (steps.every((step) => step === 9)) return "a descending counting sequence";
  return null;
}

/** Claims that name a person, an organisation or a tenant rather than a test subject. */
const IDENTITY_CLAIMS = new Set([
  "email",
  "name",
  "given_name",
  "family_name",
  "preferred_username",
  "iss",
  "aud",
  "azp",
  "org",
  "org_id",
  "tenant",
  "tenant_id",
  "account",
  "account_id",
  "client_id",
]);

/** Decodes one base64url segment, or null when it is not base64url JSON. */
function decodeSegment(segment: string): unknown {
  try {
    const padded = segment.replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(padded + "=".repeat((4 - (padded.length % 4)) % 4)));
  } catch {
    return null;
  }
}

/**
 * The reason a JWT literal is harmless, or null when it has to be reported.
 *
 * A JWT is only as safe as what it decodes to, so this decodes it. A payload of
 * `{"sub":"0"}` is a shape a test needs; a payload naming an issuer, an audience
 * or a mailbox is a token somebody minted against a real system, and a payload
 * that does not decode at all is opaque — which is exactly what a captured token
 * looks like.
 */
export function jwtPayloadIsInvented(payload: string): string | null {
  const decoded = decodeSegment(payload);
  if (decoded === null || typeof decoded !== "object") return null;
  for (const [claim, value] of Object.entries(decoded)) {
    if (IDENTITY_CLAIMS.has(claim)) return null;
    if (typeof value !== "string") continue;
    if (value.length > 12 || value.includes("@") || /[a-z]\.[a-z]{2,}/i.test(value)) return null;
  }
  return "the payload decodes to trivial, invented claims";
}

/**
 * True when a count reads as an illustration rather than as something somebody
 * counted.
 *
 * This is the one shape that cannot be decided by its form alone: `500
 * migrations` in a docstring is plainly a made-up example, and `147 handlers` is
 * plainly a number that came off a run. The signal is roundness — a multiple of
 * fifty is chosen, anything else is measured — and it is a heuristic, stated
 * here so a reader knows its edge: a *round* count copied from a real run passes
 * this guard, and the prose around it is what has to be honest.
 */
export function isIllustrativeCount(count: number): boolean {
  return count % 50 === 0;
}

/** Extensions whose whole body is prose. */
const PROSE_FILE = /\.(?:md|mdx|txt)$/;

/** A line that is a comment, in any of the languages this tree holds. */
const COMMENT_LINE = /^\s*(?:\/\/|\/\*|\*\/|\*|#|--)/;

/**
 * True when the line is prose: a documentation file, or a comment anywhere.
 *
 * Some shapes only mean anything in prose. A count inside an assertion string is
 * an *input* the test computes from — flagging it would teach a reader to silence
 * the guard — while the same count in a sentence is a claim about a repository.
 */
export function isProse(file: string, line: string): boolean {
  return PROSE_FILE.test(file) || COMMENT_LINE.test(line);
}

// ---------------------------------------------------------------------------
// The shapes
// ---------------------------------------------------------------------------

/** Where a match was found, and enough context for a shape to judge it. */
export interface MatchContext {
  /** Repository-relative path with `/` separators. */
  readonly file: string;
  /** 1-indexed line the match sits on. */
  readonly line: number;
  /** The whole line, so a shape can see how the value was built. */
  readonly text: string;
  /** Every line of the file, for a shape that spans more than one. */
  readonly lines: readonly string[];
  /** The matched text. */
  readonly matched: string;
  /** Named capture groups. */
  readonly groups: Readonly<Record<string, string | undefined>>;
}

/** One marker of a real-world codebase. */
export interface LeakShape {
  /** Stable id, reported with every hit. */
  readonly id: string;
  /** Must carry `g`; named groups feed {@link LeakShape.allow}. */
  readonly pattern: RegExp;
  /** `prose` restricts the shape to documentation files and comments. */
  readonly scope: "everything" | "prose";
  /** Why this shape is a leak, in one sentence, printed on every failure. */
  readonly why: string;
  /** The reason a particular match is legitimate, or null. */
  readonly allow: ((context: MatchContext) => string | null) | null;
  /** A string this shape must flag. */
  readonly witness: string;
  /** The legitimate neighbour it must not flag. */
  readonly nearMiss: string;
}

/**
 * Home-directory accounts that name nobody. `/home/x` is the value the installer
 * test uses for "an environment with a HOME"; the rest are the conventional
 * stand-ins.
 */
const PLACEHOLDER_ACCOUNTS = new Set([
  "x",
  "you",
  "user",
  "username",
  "me",
  "someone",
  "example",
  "runner",
  "node",
  "root",
  "<user>",
  "$USER",
  "${USER}",
]);

/** Domains reserved by RFC 2606 / RFC 6761 for examples and tests. */
const EXAMPLE_DOMAINS =
  /(?:^|\.)(?:example\.(?:com|org|net)|example\.test|test|invalid|localhost)$/;

/** Hosts where `git@host` is a clone URL rather than a mailbox. */
const VCS_HOSTS = new Set(["github.com", "gitlab.com", "bitbucket.org", "codeberg.org"]);

/**
 * Custom header prefixes that are nobody's product name.
 *
 * Two kinds, and the same distinction {@link PLACEHOLDER_OWNERS} draws: a vendor
 * that publishes the header itself, which a matcher has to spell out to
 * recognise a delivery, or a word that names the delivery rather than whoever
 * sends it. An invented prefix belongs on {@link PLACEHOLDER_OWNERS} instead,
 * where it is written down as invented.
 */
const PUBLIC_HEADER_PREFIXES = new Set([
  // Published by the vendor, and spelled out so the webhook rules can match.
  "hub", // GitHub's `x-hub-signature`.
  "github",
  "shopify",
  "slack",
  "stripe",
  "svix",
  "twilio",
  "supabase",
  "vercel",
  // The mechanism, not a product: these name the delivery, not its sender.
  "delivery",
  "partner",
  "webhook",
  "request",
]);

/** Environment segments a fixture never needs, and a real resource always has. */
const ENVIRONMENT_SEGMENT =
  /(?:^|[.-])(?:prod|production|staging|stage|live|preprod|uat)(?:[.-]|$)/;

/** A base64 body line, which is what turns a PEM header into a key. */
const BASE64_BODY = /^[A-Za-z0-9+/=]{40,}$/;

/**
 * Every marker, in the order a reader should meet them: identity, then
 * infrastructure, then credentials, then prose.
 */
export const LEAK_SHAPES: readonly LeakShape[] = [
  {
    id: "home-directory-path",
    pattern: /(?:\/Users\/|\/home\/|[A-Za-z]:\\Users\\)(?<who>[A-Za-z0-9._${}<>-]+)/g,
    scope: "everything",
    why: "an absolute path under a home directory names the machine and the account a tree was written on, and it cannot resolve on anybody else's disk; use a repository-relative path, a temporary directory, or one of the documented placeholder accounts",
    allow: (context) =>
      PLACEHOLDER_ACCOUNTS.has(context.groups.who ?? "")
        ? `\`${context.groups.who}\` is a documented placeholder account`
        : null,
    witness: "/Users/notaplaceholder/code/api/src/index.ts",
    nearMiss: '{ HOME: "/home/x" }',
  },
  {
    id: "email-address",
    pattern: /(?<local>[A-Za-z0-9._%+-]+)@(?<domain>(?:[A-Za-z0-9-]+\.)+(?<tld>[A-Za-z]{2,24}))\b/g,
    scope: "everything",
    why: "a mailbox outside the domains RFC 2606 reserves for examples belongs to a person, and a committed address is both an identity and a spam target; use `@example.com`",
    allow: (context) => {
      const domain = context.groups.domain ?? "";
      if (EXAMPLE_DOMAINS.test(domain)) return `\`${domain}\` is a reserved example domain`;
      if (context.groups.local === "git" && VCS_HOSTS.has(domain)) {
        return `\`git@${domain}\` is an SSH clone URL, not a mailbox`;
      }
      // `pkg@1.2.3-alpha.beta` has the shape of an address and is a version.
      if (/(?:^|\.)\d+(?:\.|$)/.test(domain)) return "a package version, not a domain";
      return null;
    },
    witness: "reported by ops@internal-mail.io",
    nearMiss: "author: dev@example.com",
  },
  {
    id: "machine-name",
    // An mDNS name only counts when the label carries a hyphen or a digit, which
    // is what every laptop name has and what `names.local` — a property access —
    // does not. Without that, this shape reports half the `.local` config files
    // and one member expression in the router enumerator.
    pattern:
      /\b(?<host>(?:[A-Za-z0-9]*[-\d][A-Za-z0-9-]*)\.(?:local|lan)|ip-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}[A-Za-z0-9.-]*|ec2-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}[A-Za-z0-9.-]*|(?:MacBook|iMac|Mac-mini|Mac-Studio)[A-Za-z0-9.-]*)\b/g,
    scope: "everything",
    why: "a host name identifies the laptop or the instance a command was run on, which says who ran it and where; describe the host instead of naming it",
    allow: (context) => {
      const index = context.text.indexOf(context.matched);
      // `.env-2.local` and friends: a dotted file suffix, not an mDNS host.
      return index > 0 && context.text[index - 1] === "."
        ? "a dotted file-name suffix, not a host name"
        : null;
    },
    witness: "ran on ip-10-0-14-233.eu-west-1.compute.internal",
    // Both legitimate neighbours: a member expression, and a dotted file suffix.
    nearMiss: "for (const name of names.local) {\ninjected env (7) from .env-2.local",
  },
  {
    id: "cloud-account-id",
    pattern: /(?<![\d])(?<id>\d{12})(?![\d])/g,
    scope: "everything",
    why: "a 12-digit number is an AWS account id; an invented one has to be visibly invented so that no reader — and no attacker enumerating accounts — has to work out whether it belongs to somebody",
    allow: (context) => {
      const id = context.groups.id ?? "";
      const published = publishedPlaceholderReason(id);
      if (published !== null) return published;
      const synthetic = looksSyntheticDigits(id);
      return synthetic === null ? null : synthetic;
    },
    witness: "role-to-assume: arn:aws:iam::409128637451:role/deploy",
    nearMiss: "arn:aws:iam::111122223333:role/shared-lambda-role",
  },
  {
    id: "iam-role-name",
    pattern: /role\/(?<role>[A-Za-z][A-Za-z0-9+=,.@_-]*)/g,
    scope: "everything",
    why: "an IAM role name is chosen by whoever owns the account, so a specific TitleCase role is one of theirs; a fixture's role should be lower-case and generic, or prefixed to read as invented",
    allow: (context) => {
      const role = context.groups.role ?? "";
      if (!/[A-Z]/.test(role)) return "lower-case and generic, so it names no account";
      return /^(?:Example|Demo|Test|Sample|Fixture|Placeholder|My)/.test(role)
        ? "prefixed so it reads as invented"
        : null;
    },
    witness: "role/PaymentsProdDeployRole",
    nearMiss: "role/ExampleDeployRole",
  },
  {
    id: "bucket-or-cluster-name",
    pattern:
      /(?:s3:\/\/|bucket\s*=\s*"|Bucket:\s+|bucketName"?\s*[:=]\s*"|cluster(?:Name)?"?\s*[:=]\s*"?)(?<name>[a-z0-9][a-z0-9.-]{2,62})/g,
    scope: "everything",
    why: "a bucket or cluster name carrying an environment segment, or four or more hyphenated parts, is somebody's real resource — it is specific enough to address, and specific enough to attack",
    allow: (context) => {
      const name = context.groups.name ?? "";
      if (ENVIRONMENT_SEGMENT.test(name)) return null;
      return name.split("-").length < 4 ? "generic, with no environment segment" : null;
    },
    witness: "s3://reports-prod-eu-west-1",
    nearMiss: 'bucket = "demo-data"',
  },
  {
    id: "cloud-access-key-id",
    pattern: /\b(?<key>(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g,
    scope: "everything",
    why: "this is the exact format AWS mints access key ids in, so a literal one is either live or was live; the only complete literal this tree may hold is the key AWS publishes in its own documentation",
    allow: (context) => {
      const published = publishedPlaceholderReason(context.groups.key ?? "");
      if (published !== null) return published;
      return buildsValueProgrammatically(context.text)
        ? "assembled from pieces, so no complete key is written down"
        : null;
    },
    witness: `AWS_ACCESS_KEY_ID=AKIA${"7ZQXKDLM3WQNPJRT"}`,
    nearMiss: `AKIA${"IOSFODNN7EXAMPLE"}`,
  },
  {
    id: "provider-token",
    pattern:
      /\b(?<token>(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,}|xox[baprs]-[A-Za-z0-9-]{12,}|sk-[A-Za-z0-9]{32,})\b/g,
    scope: "everything",
    why: "a provider mints tokens in exactly this format, so a complete literal is a credential whatever file it sits in; build the shape from pieces when a test needs the length and the prefix",
    allow: (context) =>
      buildsValueProgrammatically(context.text)
        ? "assembled from pieces, so no complete token is written down"
        : null,
    witness: `GITHUB_TOKEN=ghp_${"z".repeat(36)}`,
    nearMiss: 'const ENV_LINE = `GITHUB_TOKEN=ghp_${"x".repeat(36)}`;',
  },
  {
    id: "private-key-block",
    pattern: /-----BEGIN (?<kind>[A-Z ]*)PRIVATE KEY-----/g,
    scope: "everything",
    why: "a PEM header followed by a base64 body is a usable private key; the header on its own is the shape a redaction test needs, and that is the only form allowed here",
    allow: (context) => {
      const body = context.lines.slice(context.line, context.line + 3);
      return body.some((line) => BASE64_BODY.test(line.trim()))
        ? null
        : "a header with no base64 body: a shape, not a key";
    },
    witness: `-----BEGIN RSA PRIVATE KEY-----\n${"MIIEowIBAAKCAQEA".repeat(4)}`,
    nearMiss: '"-----BEGIN RSA PRIVATE KEY-----",\n`MIIE${"o".repeat(15)}`,',
  },
  {
    id: "jwt",
    pattern:
      /\beyJ(?<header>[A-Za-z0-9_-]{4,})\.(?<payload>[A-Za-z0-9_-]{6,})\.(?<signature>[A-Za-z0-9_-]{4,})\b/g,
    scope: "everything",
    why: "a three-segment JWT carries whatever claims it was minted with — an issuer, an audience, a subject that identifies somebody — and base64 hides them from review; only a payload that decodes to trivial invented claims belongs in a fixture",
    allow: (context) => jwtPayloadIsInvented(context.groups.payload ?? ""),
    // `{"iss":"auth.internal-mail.io","sub":"user-8814"}`, base64url-encoded.
    witness:
      "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJhdXRoLmludGVybmFsLW1haWwuaW8iLCJzdWIiOiJ1c2VyLTg4MTQifQ.c2lnbmF0dXJl",
    // `{"sub":"0"}`.
    nearMiss: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIwIn0.QWxsT2ZJdA",
  },
  {
    id: "third-party-owner",
    pattern:
      /(?:uses:\s*['"]?|image:\s*['"]?|FROM\s+(?:--platform=\S+\s+)?)(?<ref>[a-z0-9][a-z0-9.-]*\/[a-z0-9][a-z0-9._/-]*)/g,
    scope: "everything",
    why: "the organisation that owns an action or an image is a name, and a name that is neither a documented placeholder nor a public vendor is whoever wrote the repository this fixture was modelled on",
    allow: (context) => {
      const segments = (context.groups.ref ?? "").split("/");
      const owner = segments[0] ?? "";
      const reason = OWNER_REASON.get(owner);
      if (reason !== undefined) return `\`${owner}\`: ${reason}`;
      // `ghcr.io/acme/api` — a registry host, so the owner is the next segment.
      if (owner.includes(".") && segments.length > 2) {
        const nested = OWNER_REASON.get(segments[1] ?? "");
        if (nested !== undefined) return `\`${segments[1]}\`: ${nested}`;
      }
      return null;
    },
    witness: "uses: northwind-logistics/deploy-action@v3",
    nearMiss: "uses: example-org/example-api-tests@1.0.0",
  },
  {
    id: "custom-header-prefix",
    // The prefix only, and only on a delivery header: `x-api-key` and
    // `x-content-type-options` name a mechanism in their second segment, not a
    // product in their first.
    pattern:
      /\bx-(?<prefix>[a-z0-9]+)-(?<rest>[a-z0-9-]*(?:signature|signed|hmac|event|topic|operator)[a-z0-9-]*)\b/gi,
    scope: "everything",
    why: "the prefix of a custom delivery header is where a product name goes — `x-stripe-signature`, `x-shopify-hmac-sha256` — so a prefix that is neither a documented placeholder nor a vendor that publishes the header is the name of whatever product the fixture was modelled on; use the one invented prefix this tree documents",
    allow: (context) => {
      const prefix = (context.groups.prefix ?? "").toLowerCase();
      const reason = OWNER_REASON.get(`x-${prefix}`);
      if (reason !== undefined) return `\`x-${prefix}\`: ${reason}`;
      return PUBLIC_HEADER_PREFIXES.has(prefix)
        ? `\`${prefix}\` is published by its vendor or names the delivery, not a product`
        : null;
    },
    witness: "headers['x-northwind-signature'] = signDelivery(payloadJson, secret)",
    nearMiss:
      "headers['x-fleet-signature'] = computeDeliverySignature(payloadJson, secret)\nconst s = req.headers['x-hub-signature-256']\nreq.get('X-Shopify-Hmac-Sha256')\nres.setHeader('x-content-type-options', 'nosniff')",
  },
  {
    id: "observation-identifier",
    pattern:
      /\b(?<name>OBSERVED|MEASURED|REAL_WORLD|REAL_REPO|REAL_TREE|FROM_PRODUCTION|CLIENT_REPO|PRODUCTION_SAMPLE)\b/g,
    scope: "everything",
    why: "a table named for an observation says its rows were taken off a real tree rather than invented, which is the claim three reviews rejected; name it for what it is a corpus of",
    allow: null,
    witness: "const OBSERVED: ReadonlyArray<readonly [string, FileKind]> = [",
    nearMiss: "const CORPUS: ReadonlyArray<readonly [string, FileKind]> = [",
  },
  {
    id: "measurement-claim",
    // Two of these phrases have an innocent twin, and the difference is
    // provenance. "A real repository" as the opposite of "a fixture" is ordinary
    // English and appears throughout this tree, so only a *client's* repository
    // is reported; "copied verbatim" instructing a model to quote an id is fine,
    // so only "copied verbatim **from**" — a claim about where data came from —
    // is reported.
    pattern:
      /\b(?:the measured run|the reference (?:run|repository|repo|monorepo|codebase|tree|corpus)\b|the enterprise monorepo|really produced|(?:copied|taken|lifted|reproduced) verbatim from|(?:observed|measured|seen|reproduced|encountered) in production|in production at\b|on (?:a|the) (?:client|customer)(?:'s)? (?:repo|repository|codebase|monorepo)\b|the (?:client|customer)'s (?:repo|repository|codebase)\b)/gi,
    scope: "everything",
    why: "this sentence reports a measurement of a codebase that is not this one — a case history — and a reader cannot check it, reproduce it, or tell which repository it describes; say what this tree's own fixtures do instead",
    allow: null,
    witness: "the counts below come from the reference repository",
    nearMiss:
      "the counts below come from `src/scan/__fixtures__/target/`\nwhat it will be given on a real repository\nMust be one of the unit ids the prompt listed, copied verbatim.",
  },
  {
    id: "other-tool-case-history",
    // Two alternatives because a docstring wraps and a shape sees one line at a
    // time: the phrase survives a line break at either of its two joints. The
    // word on its own stays ordinary — `ancestors(dirname(path))` walks a path,
    // and a rule may describe a previous *phase*.
    pattern:
      /\bthe (?:ancestor|predecessor)\b|\b(?:ancestor|predecessor|previous|earlier|prior) tool\b/gi,
    scope: "everything",
    why: "a defect attributed to another tool is a case history about a system the reader cannot open, run or diff, offered here as the justification for a design — say what property this code holds instead, in the present tense and about this code",
    allow: null,
    witness: "the ancestor tool double-counted spend, so its budget cap tripped at half the figure",
    nearMiss:
      "spend is recorded once, at dispatch, because a second total halves a budget cap\nfor (const dir of ancestors(dirname(path))) this.dirs.add(dir);\nthe pass the previous phase skipped",
  },
  {
    id: "census-count",
    pattern:
      /\b(?<count>\d{1,3}(?:,\d{3})+|\d{3,4})\s+(?<noun>units?|migrations?|routes?|handlers?|findings?|files?|endpoints?|tables?|jobs?|packages?|workflows?)\b/g,
    scope: "prose",
    why: "a count this precise in prose reads as a census of a real repository rather than an illustration, and it is the shape the last review rejected; make an example count obviously round, or write the placeholder the renderer fills in",
    allow: (context) => {
      const count = Number((context.groups.count ?? "").replace(/,/g, ""));
      // `a 2023 migration` is a date, and no four-digit year is a census.
      if (count >= 1900 && count <= 2099 && !(context.groups.count ?? "").includes(",")) {
        return `${count} is a year, not a count`;
      }
      return isIllustrativeCount(count)
        ? `${count} is round, so it reads as an illustration`
        : null;
    },
    witness: "the report states `147/147 handlers audited`",
    nearMiss:
      "a count whose `500 migrations` become `500 migration units`\nnever enough to lift a 2023 migration",
  },
];

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

/** One reported marker. */
export interface Leak {
  /** The {@link LeakShape.id} that fired. */
  readonly shape: string;
  /** Repository-relative path. */
  readonly file: string;
  /** 1-indexed line. */
  readonly line: number;
  /** The text that matched. */
  readonly matched: string;
  /** {@link LeakShape.why}. */
  readonly why: string;
  /** The line it sits on, trimmed, so a failure is readable without opening the file. */
  readonly context: string;
}

/** Longest line a report quotes; a minified fixture should not flood the output. */
const CONTEXT_LIMIT = 160;

/** Runs every shape over one file's text. */
export function scanText(file: string, text: string, shapes = LEAK_SHAPES): Leak[] {
  const lines = text.split("\n");
  const leaks: Leak[] = [];
  for (const shape of shapes) {
    lines.forEach((line, index) => {
      if (shape.scope === "prose" && !isProse(file, line)) return;
      for (const match of line.matchAll(shape.pattern)) {
        const context: MatchContext = {
          file,
          line: index + 1,
          text: line,
          lines,
          matched: match[0],
          groups: match.groups ?? {},
        };
        if (shape.allow?.(context) != null) continue;
        const trimmed = line.trim();
        leaks.push({
          shape: shape.id,
          file,
          line: index + 1,
          matched: match[0],
          why: shape.why,
          context:
            trimmed.length > CONTEXT_LIMIT ? `${trimmed.slice(0, CONTEXT_LIMIT)}...` : trimmed,
        });
      }
    });
  }
  return leaks.sort((a, b) => a.line - b.line || a.shape.localeCompare(b.shape));
}

/** One hit, as a reader should meet it: where, what, and why that shape is a leak. */
export function formatLeak(leak: Leak): string {
  return [
    `${leak.file}:${leak.line}  [${leak.shape}]  ${JSON.stringify(leak.matched)}`,
    `    line: ${leak.context}`,
    `    why:  ${leak.why}`,
  ].join("\n");
}

// ---------------------------------------------------------------------------
// The walk
// ---------------------------------------------------------------------------

/** A file that cannot hold prose or a credential in reviewable form. */
const BINARY_SUFFIX = /\.(?:png|jpe?g|gif|webp|ico|pdf|woff2?|ttf|otf|zip|gz|tgz|bin|node)$/i;

/**
 * Every file under `root`, repository-relative and sorted, skipping
 * {@link SKIPPED_DIRECTORIES} and {@link EXEMPT_FILES}.
 *
 * A walk rather than a glob, because the point is to be exhaustive: a glob list
 * is a list of the file kinds somebody thought of, and the leaks this guard
 * exists for arrived in a `.sarif`, a `.toml` and a `README`.
 */
export async function collectFiles(fs: FileSystem, root: string): Promise<string[]> {
  const exempt = new Set(EXEMPT_FILES.map(([file]) => file));
  const skipped = new Set(SKIPPED_DIRECTORIES);
  const found: string[] = [];

  async function descend(relativeDir: string): Promise<void> {
    for (const entry of await fs.readDir(join(root, relativeDir))) {
      const path = relativeDir === "" ? entry.name : `${relativeDir}/${entry.name}`;
      if (entry.isSymbolicLink) continue;
      if (entry.isDirectory) {
        if (!skipped.has(entry.name)) await descend(path);
        continue;
      }
      if (!entry.isFile || exempt.has(path) || BINARY_SUFFIX.test(entry.name)) continue;
      found.push(path);
    }
  }

  await descend("");
  return found.sort();
}

/** Scans the whole repository. Files that are not UTF-8 text are skipped. */
export async function findLeaks(fs: FileSystem, root: string): Promise<Leak[]> {
  const leaks: Leak[] = [];
  for (const file of await collectFiles(fs, root)) {
    const text = await fs.readFile(join(root, file));
    if (text.includes("\u0000")) continue;
    leaks.push(...scanText(file, text));
  }
  return leaks;
}
