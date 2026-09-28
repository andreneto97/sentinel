/**
 * The single severity policy.
 *
 * Three jobs live here, and nowhere else:
 *
 * 1. **Translation** — every analyzer speaks its own dialect (SARIF levels,
 *    trivy's `CRITICAL`, hadolint's `error`/`warning`/`info`, raw CVSS scores).
 *    One table per dialect, so a reader can check the mapping instead of
 *    guessing it from a runner's source.
 * 2. **The secret-strength model** — the one place that decides what a secret
 *    match is worth. A placeholder in `.env.example`, a Kubernetes key *name*, a
 *    fixture token and a live AWS key all arrive as `appsec.hardcoded-secret`,
 *    and they are four different things; {@link gradeSecret} is where that is
 *    settled, from the rule that matched and the context it matched in.
 * 3. **Escalation** — the rules that say when Sentinel's judgement outranks the
 *    tool's. These are the only sanctioned reasons a finding's severity differs
 *    from what the tool said, and every one of them is written down below.
 *
 * Runners assign the *base* severity while they still hold the tool's own
 * payload; `normalise.ts` then runs every finding through {@link escalateFinding}
 * so the escalation rules apply uniformly, whoever produced the finding.
 */

import type { Confidence, Finding, Severity } from "../contracts/findings.ts";

/** Most severe first. This is also the primary sort key of `findings.json`. */
export const SEVERITY_ORDER: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

/** Position in {@link SEVERITY_ORDER}; 0 is `critical`. */
export function severityRank(severity: Severity): number {
  const rank = SEVERITY_ORDER.indexOf(severity);
  return rank === -1 ? SEVERITY_ORDER.length : rank;
}

/** Orders two severities most-severe-first, for `Array#sort`. */
export function compareSeverity(left: Severity, right: Severity): number {
  return severityRank(left) - severityRank(right);
}

/** The more severe of two severities. */
export function maxSeverity(left: Severity, right: Severity): Severity {
  return severityRank(left) <= severityRank(right) ? left : right;
}

/** Raises `severity` to `floor` when it sits below it, and never lowers it. */
export function atLeast(severity: Severity, floor: Severity): Severity {
  return maxSeverity(severity, floor);
}

// ---------------------------------------------------------------------------
// Translation — tool dialects in, Sentinel severities out
// ---------------------------------------------------------------------------

/** SARIF `level`, as opengrep and gitleaks emit it. */
const SARIF_LEVEL: Readonly<Record<string, Severity>> = {
  error: "high",
  warning: "medium",
  note: "low",
  none: "info",
};

/** trivy's severity word, shared by its vulnerability and misconfiguration output. */
const TRIVY_SEVERITY: Readonly<Record<string, Severity>> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  UNKNOWN: "info",
  NONE: "info",
};

/** hadolint's and actionlint's shared lint vocabulary. */
const LINT_LEVEL: Readonly<Record<string, Severity>> = {
  error: "high",
  warning: "medium",
  info: "low",
  style: "info",
  ignore: "info",
};

/** npm/pnpm/yarn `audit` severity, for the package-manager step. */
const AUDIT_SEVERITY: Readonly<Record<string, Severity>> = {
  critical: "critical",
  high: "high",
  moderate: "medium",
  low: "low",
  info: "info",
};

/** The analyzer dialects Sentinel knows how to read. */
export type SeverityScale = "sarif" | "trivy" | "lint" | "audit";

/** Every dialect's table, so a caller can pick one by name. */
const SCALES: Readonly<Record<SeverityScale, Readonly<Record<string, Severity>>>> = {
  sarif: SARIF_LEVEL,
  trivy: TRIVY_SEVERITY,
  lint: LINT_LEVEL,
  audit: AUDIT_SEVERITY,
};

/**
 * What an unrecognised word maps to. `info` and never `critical`: an unknown
 * severity is missing information, and missing information must not be able to
 * manufacture an alarm out of a tool Sentinel does not understand.
 */
export const UNKNOWN_SEVERITY: Severity = "info";

/**
 * Translates one analyzer's severity word. `trivy` matches case-insensitively
 * upper, the rest lower, so `Warning` and `warning` land in the same place.
 */
export function fromToolSeverity(scale: SeverityScale, raw: string | undefined): Severity {
  if (raw === undefined) return UNKNOWN_SEVERITY;
  const table = SCALES[scale];
  const key = scale === "trivy" ? raw.trim().toUpperCase() : raw.trim().toLowerCase();
  return table[key] ?? UNKNOWN_SEVERITY;
}

/** SARIF `level` in, Sentinel severity out. */
export function fromSarifLevel(level: string | undefined): Severity {
  return fromToolSeverity("sarif", level);
}

/** trivy's severity word in, Sentinel severity out. */
export function fromTrivySeverity(severity: string | undefined): Severity {
  return fromToolSeverity("trivy", severity);
}

/** A lint level (hadolint, actionlint) in, Sentinel severity out. */
export function fromLintLevel(level: string | undefined): Severity {
  return fromToolSeverity("lint", level);
}

/**
 * A CVSS base score in, Sentinel severity out, on the standard v3.1 bands
 * (9.0+ critical, 7.0+ high, 4.0+ medium, 0.1+ low, 0.0 none).
 */
export function fromCvssScore(score: number | undefined): Severity {
  if (score === undefined || !Number.isFinite(score)) return UNKNOWN_SEVERITY;
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "info";
}

// ---------------------------------------------------------------------------
// The secret-strength model — what evidence a secret match actually rests on
// ---------------------------------------------------------------------------

/**
 * Four different things arrive as `appsec.hardcoded-secret`, and a scan that
 * grades them all `high` is wrong about three of them:
 *
 * 1. a live credential matched by a provider's own token format;
 * 2. a long, high-entropy value left in a tracked `.env.example`, which every
 *    clone of the repository carries;
 * 3. `key: LOAN_RATE_POINTS_<id>` — the *name* of a key inside a Kubernetes
 *    Secret, whose value is not in the repository at all;
 * 4. the integer `123` in `--account-id=123`, inside a README's usage line.
 *
 * All four arrive as `appsec.hardcoded-secret` at `high` when the only question
 * asked is "did a secret scanner match here". This model asks three more, and
 * every one of them is answered from something a reader can check:
 *
 * - **Which rule matched?** A provider-specific rule (an AWS key id, a private
 *   key block, a Stripe live key) recognises a format only that provider mints.
 *   A generic entropy or `password =` rule recognises a *shape*, which is what a
 *   fixture, a placeholder and a real key have in common.
 * - **What is the matched text?** Not "is it secret" — `classifySecretValue`
 *   only rejects what cannot be a credential: a placeholder, a truncated
 *   example, a decimal integer, a string too short or too repetitive to carry a
 *   key's worth of entropy.
 * - **What is it doing there?** A scalar under `secretKeyRef` is a pointer to a
 *   secret; a `client_id` is the public half of a pair whose secret half is the
 *   next line; text inside a comment is documentation. None of those is a
 *   credential, however random it looks.
 *
 * The model never sees the repository and never holds a value beyond the call:
 * the caller reads the matched text (see `runners/gitleaks.ts`, which reads the
 * blob the scanner matched and masks it before anything is written), passes it
 * in, and gets back a severity, a confidence and the words that say why.
 */

/** How specific the pattern that matched was, which is the strongest signal available. */
export type SecretRuleClass = "private-key" | "cloud" | "provider" | "generic";

/**
 * Scanner rules whose match *is* key material. A private key cannot be
 * "changed" like a password: everything it ever signed or decrypted stays in
 * play until it is revoked, which is why these outrank the rest.
 */
const PRIVATE_KEY_RULES: ReadonlySet<string> = new Set([
  "private-key",
  "pkcs12-file",
  "age-secret-key",
  "cloudflare-origin-ca-key",
  "flutterwave-encryption-key",
]);

/**
 * Rule-id prefixes that mean "credentials to infrastructure": the blast radius
 * is every resource in the account, including the ability to spend money and to
 * read every other secret stored there.
 */
const CLOUD_PROVIDER_PREFIXES: readonly string[] = [
  "aws-",
  "gcp-",
  "azure-",
  "alibaba-",
  "digitalocean-",
  "cloudflare-",
  "heroku-",
  "yandex-",
  "flyio-",
  "scalingo-",
  "openshift-",
  "kubernetes-",
  "hashicorp-tf-",
  "vault-",
];

/**
 * The rules that fire on shape and entropy rather than on a provider's own token
 * format. These are the rules that dominate a real scan — a repository that
 * keeps its credentials out of source still has template files, fixtures and
 * usage lines full of credential-*shaped* strings — which is why a floor applied
 * to "any secret match" is in practice a floor applied to an entropy heuristic.
 */
const GENERIC_SECRET_RULES: ReadonlySet<string> = new Set([
  "generic-api-key",
  "jwt",
  "jwt-base64",
  "curl-auth-header",
  "curl-auth-user",
  "nuget-config-password",
  "hashicorp-tf-password",
  "sidekiq-sensitive-url",
]);

/** True when the rule identifies key material rather than a rotatable token. */
export function isPrivateKeyRule(ruleId: string): boolean {
  return PRIVATE_KEY_RULES.has(ruleId) || ruleId.endsWith("-private-key");
}

/** True when the rule identifies a credential to a cloud provider account. */
export function isCloudProviderRule(ruleId: string): boolean {
  return CLOUD_PROVIDER_PREFIXES.some((prefix) => ruleId.startsWith(prefix));
}

/** True when the rule matched a shape and an entropy level, not a vendor's format. */
export function isGenericSecretRule(ruleId: string): boolean {
  return GENERIC_SECRET_RULES.has(ruleId) || ruleId === "" || ruleId === "unknown-rule";
}

/** Which of the four classes a scanner rule id belongs to. */
export function classifySecretRule(ruleId: string): SecretRuleClass {
  if (isPrivateKeyRule(ruleId)) return "private-key";
  if (isCloudProviderRule(ruleId)) return "cloud";
  return isGenericSecretRule(ruleId) ? "generic" : "provider";
}

/** What the matched text can and cannot be, judged only on its own shape. */
export type SecretValueShape = "placeholder" | "trivial" | "credible" | "unknown";

/**
 * Words that mean "put your own value here". Matched on the whole value, lower
 * cased and stripped of punctuation, so `<your-key>`, `YOUR_KEY` and
 * `changeme!` all land here while `changeme-but-actually-a-long-random-key`
 * does not.
 */
const PLACEHOLDER_WORDS: ReadonlySet<string> = new Set([
  "abc",
  "abc123",
  "abc456",
  "changeme",
  "dummy",
  "example",
  "fake",
  "foo",
  "foobar",
  "bar",
  "here",
  "insertyourkeyhere",
  "none",
  "notset",
  "null",
  "password",
  "placeholder",
  "replaceme",
  "sample",
  "secret",
  "test",
  "todo",
  "undefined",
  "value",
  "xxx",
  "xxxx",
  "yyy",
  "yourkey",
  "yoursecret",
  "yourtoken",
  "yourvaluehere",
]);

/**
 * Endings that mean the value was elided for display rather than written out. A
 * help line of the form `JWT=eyJhbGciOiJIU... make jwt-decode` holds a fragment
 * of a JWT *header* — the public part every HS256 token starts with — and a
 * scanner reports it as a `high` hardcoded credential. Kept to markers no base64
 * alphabet can produce, so a real key that happens to end in `xxx` is not thrown
 * away.
 */
const TRUNCATION_MARKERS: readonly string[] = ["...", "…", "***"];

/**
 * The shortest string that can carry a credential's worth of entropy, and the
 * lowest per-character entropy one can have. Both are deliberately generous:
 * this gate exists to reject `123` and `abc456`, not to second-guess a vendor
 * whose tokens are short.
 */
const MIN_CREDENTIAL_LENGTH = 12;
const MIN_CREDENTIAL_ENTROPY = 3;

/** Shannon entropy in bits per character; 0 for the empty string. */
export function shannonEntropy(text: string): number {
  if (text === "") return 0;
  const counts = new Map<string, number>();
  for (const char of text) counts.set(char, (counts.get(char) ?? 0) + 1);
  let bits = 0;
  for (const count of counts.values()) {
    const p = count / text.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/** A JWT carries three base64url segments; a bare `eyJ…` header prefix carries none. */
function isTruncatedJwt(value: string): boolean {
  return value.startsWith("eyJ") && !/^eyJ[\w-]+\.[\w-]+\.[\w-]*$/.test(value);
}

/**
 * Classifies the matched text. `undefined` means the caller could not read it —
 * the blob for that commit was unavailable — and comes back as `unknown` rather
 * than as an assumption in either direction.
 */
export function classifySecretValue(value: string | undefined): SecretValueShape {
  if (value === undefined) return "unknown";
  const trimmed = value.trim().replace(/^["'`]+|["'`,;]+$/g, "");
  if (trimmed === "") return "placeholder";
  // `<your-key>`, `${API_KEY}`, `{{ .Values.key }}`: a reference or a slot, and
  // in every case not a value.
  if (/^[<{$[].*[>}\])]$/.test(trimmed) || trimmed.includes("${") || trimmed.includes("{{")) {
    return "placeholder";
  }
  if (TRUNCATION_MARKERS.some((marker) => trimmed.endsWith(marker))) return "placeholder";
  if (isTruncatedJwt(trimmed)) return "placeholder";
  const word = trimmed.toLowerCase().replace(/[^a-z0-9]/g, "");
  if (PLACEHOLDER_WORDS.has(word)) return "placeholder";
  if (/^your[-_.]?/i.test(trimmed) || /^(?:my|the)[-_](?:key|secret|token)$/i.test(trimmed)) {
    return "placeholder";
  }

  if (/^\d+$/.test(trimmed)) return "trivial";
  if (trimmed.length < MIN_CREDENTIAL_LENGTH) return "trivial";
  if (shannonEntropy(trimmed) < MIN_CREDENTIAL_ENTROPY) return "trivial";
  return "credible";
}

/** Which half of a credential pair a name refers to. */
export type SecretNameRole = "identifier" | "secret" | "unknown";

/**
 * Names that are the **public** half of a pair. An OAuth `client_id` is sent in
 * plaintext in every `/authorize` request; an AWS `access_key_id` is printed in
 * CloudTrail. Committing one is an inventory fact, not a credential leak — the
 * secret half is the *other* name, usually one line away.
 */
const PUBLIC_HALF_NAMES: readonly string[] = [
  "clientid",
  "accesskeyid",
  "accessid",
  "apikeyid",
  "keyid",
  "appid",
  "applicationid",
  "consumerkey",
  "publishablekey",
  "publickey",
  "username",
  "userid",
  "accountid",
  "projectid",
  "tenantid",
  "organizationid",
  "orgid",
  "audience",
  "issuer",
];

/** Names that are the half that authenticates, and therefore the half that leaks. */
const SECRET_HALF_NAMES: readonly string[] = [
  "clientsecret",
  "secretaccesskey",
  "secretkey",
  "accesstoken",
  "refreshtoken",
  "idtoken",
  "authtoken",
  "bearertoken",
  "apikey",
  "apisecret",
  "apitoken",
  "privatekey",
  "signingkey",
  "encryptionkey",
  "sessionsecret",
  "webhooksecret",
  "password",
  "passwd",
  "secret",
  "credentials",
];

/** Lower-cases and strips separators, so `LENDING_SSO_CLIENT_ID` reads as `lendingssoclientid`. */
function normaliseName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, "");
}

/**
 * Reads the role off the name the value was assigned to. The public list is
 * consulted first because its entries are the more specific: `API_KEY_ID` is an
 * identifier although it contains `apikey`.
 */
export function classifySecretName(name: string | undefined): SecretNameRole {
  if (name === undefined || name.trim() === "") return "unknown";
  const normalised = normaliseName(name);
  if (PUBLIC_HALF_NAMES.some((term) => normalised.includes(term))) return "identifier";
  if (SECRET_HALF_NAMES.some((term) => normalised.includes(term))) return "secret";
  return "unknown";
}

/**
 * What the matched text is *doing* where it sits. The caller derives this from
 * the line and the file, because only the caller has them.
 */
export type SecretContext =
  /** `NAME = value`: the value is held here. The ordinary case. */
  | "assignment"
  /** The text names a secret stored elsewhere: `secretKeyRef.key`, `env[].name`. */
  | "reference"
  /** Inside a comment, a fenced block or a printed usage string. */
  | "documentation"
  /** In an `.env.example` / `*.sample` / `*.template`: a slot to be filled in. */
  | "template"
  /** The caller could not read the line. */
  | "unknown";

/** What the evidence adds up to. This is the one thing the report should sort on. */
export type SecretJudgement =
  /** A provider's own credential format matched. Rotation is required, wherever it sits. */
  | "provider-credential"
  /** A shape-and-entropy match whose value has the length and entropy of a real key. */
  | "likely-credential"
  /** A shape-and-entropy match whose value Sentinel could not read back. */
  | "unverified-match"
  /** The text is the name of a secret held outside the repository. */
  | "secret-reference"
  /** The public half of a credential pair: an id, not the thing that authenticates. */
  | "public-identifier"
  /** A comment, a usage example or documentation prose. */
  | "documented-example"
  /** A placeholder, a truncated example, or a value too short or too plain to be a key. */
  | "placeholder";

/** How strong the evidence is, which is the only thing {@link escalate} reads. */
export type SecretEvidence = "provider-specific" | "heuristic";

/** What the caller knows about one match. Everything optional is genuinely unknown. */
export interface SecretMatchFacts {
  /** The scanner's own rule id, e.g. `generic-api-key` or `aws-access-token`. */
  readonly ruleId: string;
  /** The name the value is assigned to, when the line has one. */
  readonly name?: string | undefined;
  /** The matched text, read from the blob the scanner matched. Never stored. */
  readonly value?: string | undefined;
  /** What the text is doing there; `unknown` when the line could not be read. */
  readonly context?: SecretContext | undefined;
  /**
   * True when this same value also appears in the file as part of the *name* of
   * a secret held elsewhere — `credentialKey: <id>` next to
   * `key: LOAN_RATE_POINTS_<id>`. A value used to name something is an
   * identifier: nobody publishes a credential as metadata.
   */
  readonly reusedAsName?: boolean | undefined;
}

/** The model's verdict on one match, with the words that justify it. */
export interface SecretGrade {
  readonly judgement: SecretJudgement;
  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly evidence: SecretEvidence;
  readonly ruleClass: SecretRuleClass;
  readonly valueShape: SecretValueShape;
  readonly nameRole: SecretNameRole;
  /** What the credential opens, when the rule says. `null` unless it is a credential. */
  readonly credential: CredentialKind | null;
  /** One sentence: why this judgement, from the facts. Rendered into the finding. */
  readonly why: string;
  /** What would turn this into a confirmed credential; `null` when it already is one. */
  readonly whatWouldConfirm: string | null;
  /** True when the finding is not a vulnerability claim but a hygiene observation. */
  readonly hygiene: boolean;
}

/** Severity and confidence per judgement. The whole policy, in one table. */
const JUDGEMENT_GRADE: Readonly<
  Record<SecretJudgement, { severity: Severity; confidence: Confidence; hygiene: boolean }>
> = {
  // `provider-credential` takes its severity from the rule class instead (critical
  // for a cloud account or key material, high for every other vendor token).
  "provider-credential": { severity: "high", confidence: "high", hygiene: false },
  "likely-credential": { severity: "high", confidence: "medium", hygiene: false },
  "unverified-match": { severity: "medium", confidence: "low", hygiene: false },
  "secret-reference": { severity: "info", confidence: "low", hygiene: true },
  "public-identifier": { severity: "low", confidence: "medium", hygiene: true },
  "documented-example": { severity: "info", confidence: "low", hygiene: true },
  placeholder: { severity: "info", confidence: "low", hygiene: true },
};

/**
 * The judgements that are not a credential claim. Counted and named in the scan
 * step's reason, because a demotion nobody can see is a suppression.
 */
export const DEMOTED_SECRET_JUDGEMENTS: readonly SecretJudgement[] = [
  "secret-reference",
  "public-identifier",
  "documented-example",
  "placeholder",
];

/** True when this judgement says "this is not the credential the scanner thought". */
export function isDemotedSecret(judgement: SecretJudgement): boolean {
  return DEMOTED_SECRET_JUDGEMENTS.includes(judgement);
}

/** What a provider-specific match is worth, by what it opens. */
function providerSeverity(ruleClass: SecretRuleClass): Severity {
  return ruleClass === "private-key" || ruleClass === "cloud" ? "critical" : "high";
}

/** The `CredentialKind` a rule class implies, for R2 and for the report's prose. */
function credentialKindOf(ruleClass: SecretRuleClass): CredentialKind {
  if (ruleClass === "private-key") return "private-key";
  return ruleClass === "cloud" ? "cloud" : "generic";
}

/** Picks the judgement from the facts. Order is the policy; see the table below. */
function judge(facts: SecretMatchFacts): { judgement: SecretJudgement; why: string } {
  const ruleClass = classifySecretRule(facts.ruleId);
  const shape = classifySecretValue(facts.value);
  const nameRole = classifySecretName(facts.name);
  const context = facts.context ?? "unknown";
  const named = facts.name === undefined ? "the value" : `\`${facts.name}\``;

  // A placeholder is a placeholder whatever matched it: every cloud provider
  // publishes an `AKIA…EXAMPLE`-style key in its own documentation, and a
  // provider-shaped string elided with `...` is an illustration of a format
  // rather than an instance of one.
  if (shape === "placeholder") {
    return {
      judgement: "placeholder",
      why: `the matched text is a placeholder or an elided example rather than a value, so ${named} carries nothing to rotate`,
    };
  }

  // A provider's own format is the strongest evidence available, and it outranks
  // every contextual signal below: an AWS key id under `secretKeyRef` would be a
  // finding about the key id, not about the pointer.
  if (ruleClass !== "generic") {
    return {
      judgement: "provider-credential",
      why: `the scanner matched \`${facts.ruleId}\`, which recognises a format only this provider mints, so the match is a credential and not a shape that resembles one`,
    };
  }

  if (context === "reference") {
    return {
      judgement: "secret-reference",
      why: "the match is the *name* of a key in a secret held outside the repository (a `secretKeyRef`-style pointer), so the value it names is not in this file",
    };
  }

  // Before the name is consulted: `--account-id=123` is named like an
  // identifier *and* is the integer 123, and what settles it is that no
  // three-character decimal is a credential of any kind.
  if (shape === "trivial") {
    return {
      judgement: "placeholder",
      why: "the matched text is a decimal integer, or is too short and too repetitive to carry a credential's worth of entropy",
    };
  }

  if (nameRole === "identifier" || facts.reusedAsName === true) {
    return {
      judgement: "public-identifier",
      why:
        facts.reusedAsName === true
          ? "the same value is also used in this file to *name* a secret stored elsewhere, and nothing that authenticates is published as metadata, so this is an identifier"
          : `${named} is the public half of a credential pair — it is sent in the clear on every request — and the half that authenticates is a different name`,
    };
  }

  if (context === "documentation") {
    return {
      judgement: "documented-example",
      why: "the match sits inside a comment or a usage example, which documents the shape of a value rather than holding one",
    };
  }

  if (shape === "unknown") {
    return {
      judgement: "unverified-match",
      why: "the scanner matched on shape and entropy, and Sentinel could not read the blob back to see what it matched, so the match is a lead rather than a confirmed credential",
    };
  }

  return {
    judgement: "likely-credential",
    why:
      context === "template"
        ? `${named} sits in an example or template file, but the value is not a placeholder: it has the length and the entropy of a real credential, and the file is tracked, so every clone carries it`
        : `the scanner matched on shape and entropy rather than on a vendor format, and the matched value has the length and the entropy of a real credential assigned to ${named}`,
  };
}

/** What would settle an unconfirmed match, phrased per judgement. */
function confirmationFor(judgement: SecretJudgement, context: SecretContext): string | null {
  switch (judgement) {
    case "provider-credential":
      return null;
    case "likely-credential":
      return "Confirming it takes one call to the provider with this value: if it authenticates, it is live and this is a credential leak; if it does not, record it as a fixture and add it to the scanner's allowlist so the next run stops asking.";
    case "unverified-match":
      return "Reading the blob for that commit (`git show <commit>:<path>`) shows what was matched; Sentinel could not, so this severity reflects the uncertainty rather than the value.";
    case "secret-reference":
      return "If the secret this key names should not be referenced from a tracked file at all, that is a separate decision; the value itself is held by the secret store.";
    case "public-identifier":
      return "If the paired secret — the `*_secret`, `*_token` or `*_access_key` beside it — is also committed, that one is the finding; this identifier only tells an attacker which account to attack.";
    case "documented-example":
      return context === "template"
        ? "If the example file is meant to carry a working default, replace it with an obviously fake value so the next scan has nothing to match."
        : "If the documented value was ever real, rotate it; otherwise no action is needed beyond keeping examples obviously fake.";
    case "placeholder":
      return "Nothing confirms a placeholder. If this value was once a real credential that has since been shortened or elided, the original still sits in the commit it was written in.";
  }
}

/**
 * **The single secret-strength policy.** Facts in, one grade out.
 *
 * The rows are tried in this order, and the order is part of the policy:
 *
 * | rule matched | what it is doing there | the value | judgement | severity |
 * |---|---|---|---|---|
 * | any | any | a placeholder or an elided example | `placeholder` | `info` |
 * | a provider's own format | any | anything else | `provider-credential` | `critical`/`high` |
 * | generic | names a secret held elsewhere | any | `secret-reference` | `info` |
 * | generic | any | digits, short, or low entropy | `placeholder` | `info` |
 * | generic | name is the public half, or the value names something | any | `public-identifier` | `low` |
 * | generic | a comment or a usage line | any | `documented-example` | `info` |
 * | generic | any | unreadable | `unverified-match` | `medium` |
 * | generic | assigned (including in a template file) | real | `likely-credential` | `high` |
 *
 * Only `provider-credential` earns `high` confidence, and only it earns the R1
 * floor and the T3 exemption in `_file-kind.ts`: both read `confidence === "high"`
 * as "a provider-specific rule matched", and this function is what makes that
 * true.
 */
export function gradeSecret(facts: SecretMatchFacts): SecretGrade {
  const ruleClass = classifySecretRule(facts.ruleId);
  const context = facts.context ?? "unknown";
  const { judgement, why } = judge(facts);
  const row = JUDGEMENT_GRADE[judgement];
  const provider = judgement === "provider-credential";

  return {
    judgement,
    severity: provider ? providerSeverity(ruleClass) : row.severity,
    confidence: row.confidence,
    evidence: provider ? "provider-specific" : "heuristic",
    ruleClass,
    valueShape: classifySecretValue(facts.value),
    nameRole: classifySecretName(facts.name),
    credential:
      judgement === "provider-credential" || judgement === "likely-credential"
        ? credentialKindOf(ruleClass)
        : null,
    why,
    whatWouldConfirm: confirmationFor(judgement, context),
    hygiene: row.hygiene,
  };
}

// ---------------------------------------------------------------------------
// Escalation — where Sentinel's judgement outranks the tool's
// ---------------------------------------------------------------------------

/** Where a committed credential still is. */
export type SecretExposure = "worktree" | "history-only";

/** What kind of credential leaked, which is what decides the blast radius. */
export type CredentialKind = "cloud" | "private-key" | "generic";

/**
 * The facts the escalation rules weigh. Anything a caller cannot prove is left
 * `undefined`: an absent signal never escalates, so a gap in what Sentinel
 * knows can only make a finding less alarming, never more.
 */
export interface SeveritySignals {
  /** The finding reports a committed credential, and where that credential is. */
  readonly secret?: SecretExposure | undefined;
  /**
   * How specific the pattern that matched was. Absent means "the producer did
   * not say", which is read as `heuristic`: a floor is an alarm, and an alarm
   * must not be manufactured out of missing information.
   */
  readonly secretEvidence?: SecretEvidence | undefined;
  /** What the credential opens. Only trusted on a high-confidence match. */
  readonly credential?: CredentialKind | undefined;
  /** The CVE is known to be exploited in the wild, not merely scored. */
  readonly knownExploited?: boolean | undefined;
}

/** The outcome of the policy for one finding, with the reason it moved. */
export interface SeverityDecision {
  /** What the finding should carry. */
  readonly severity: Severity;
  /** What the tool said, before the policy ran. */
  readonly base: Severity;
  /** True when `severity` is more severe than `base`. */
  readonly escalated: boolean;
  /** One sentence naming the rule that moved it; absent when nothing moved. */
  readonly rationale?: string | undefined;
}

/**
 * The escalation rules, in the order they are applied. Each one is a floor: it
 * can only raise a severity, so two rules that both fire agree on the highest.
 *
 * - **R1 — a committed *provider-specific* credential is never below `high`,
 *   wherever it now lives.** A secret deleted from the working tree is still in
 *   every clone and fork; removing the file does not revoke the credential. A
 *   tool that grades a history-only hit as informational is grading the file,
 *   not the exposure.
 *
 *   The floor is gated on the evidence, and that gate is the fix for the largest
 *   source of inflation this policy can produce: R1 used to fire on
 *   `signals.secret !== undefined` alone, so every entropy match — placeholders,
 *   Kubernetes key *names*, the integer `123` in a README — arrived at `high` no
 *   matter what the model thought. A heuristic match now keeps the severity
 *   {@link gradeSecret} gave it: the evidence is weaker, so there is nothing for
 *   a floor to assert.
 * - **R2 — a cloud account credential or a private key is `critical`.**
 *   A cloud key spends money, reads every data store and unlocks every other
 *   secret in the account; a private key cannot be rotated away from what it
 *   already signed or decrypted. Applied only to a provider-specific match, so
 *   an entropy heuristic cannot manufacture a critical.
 * - **R3 — a CVE known to be exploited in the wild is `critical`, whatever its
 *   CVSS band says.** A band is a model of how bad an attack would be; a known
 *   exploit is evidence that the attack exists. Evidence outranks the model.
 */
export const ESCALATION_RULES = {
  secretFloor: "R1",
  credentialBlastRadius: "R2",
  knownExploited: "R3",
} as const;

/**
 * Severity floor R1 puts under a committed secret, **by how specific the match
 * was**. A provider-specific hit is a credential and gets the floor; a
 * shape-and-entropy hit keeps whatever {@link gradeSecret} decided, because a
 * floor would be asserting more than the evidence carries.
 */
const SECRET_FLOOR: Readonly<Record<SecretEvidence, Severity | null>> = {
  "provider-specific": "high",
  heuristic: null,
};

/** Applies the escalation rules to a base severity. Never lowers it. */
export function escalate(base: Severity, signals: SeveritySignals): SeverityDecision {
  let severity = base;
  let rationale: string | undefined;

  /** Keeps the rationale of the rule that actually moved the needle. */
  const raise = (floor: Severity, why: string): void => {
    const raised = atLeast(severity, floor);
    if (raised !== severity) {
      severity = raised;
      rationale = why;
    }
  };

  if (signals.secret !== undefined) {
    const floor = SECRET_FLOOR[signals.secretEvidence ?? "heuristic"];
    if (floor !== null) {
      raise(
        floor,
        signals.secret === "history-only"
          ? `Sentinel raised this to ${floor} (R1): a provider-specific credential match is a credential, and although the value is no longer in the working tree every clone and fork still carries it — deleting a file does not revoke a credential.`
          : `Sentinel raised this to ${floor} (R1): a provider-specific credential match is a credential, and this one is exposed to everyone with read access to the repository.`,
      );
    }
  }

  if (signals.credential === "cloud") {
    raise(
      "critical",
      "Sentinel raised this to critical (R2): a cloud account credential grants whatever its identity can do, including reading every other secret held in that account.",
    );
  } else if (signals.credential === "private-key") {
    raise(
      "critical",
      "Sentinel raised this to critical (R2): a private key cannot be rotated away from what it already signed or decrypted, so every artefact and session it produced stays in play until it is revoked.",
    );
  }

  if (signals.knownExploited === true) {
    raise(
      "critical",
      "Sentinel raised this to critical (R3): this CVE is on the known-exploited list, and evidence that an attack exists outranks the CVSS band that models how bad one would be.",
    );
  }

  return {
    severity,
    base,
    escalated: severityRank(severity) < severityRank(base),
    ...(rationale === undefined ? {} : { rationale }),
  };
}

/** Rule id every secret finding carries, whoever produced it. */
export const SECRET_RULE = "appsec.hardcoded-secret";

/**
 * The step name of the secret scanner this model is calibrated against. Declared
 * here rather than in the runner so `_file-kind.ts` can name it without
 * importing the runner that imports this module.
 */
export const SECRET_SCANNER = "gitleaks";

/** Rule id trivy's dependency CVEs carry. */
export const VULNERABLE_PACKAGE_RULE = "dependencies.vulnerable-package";

/** CWE that identifies key material rather than a rotatable token. */
const PRIVATE_KEY_CWE = "CWE-321";

/**
 * Phrase the gitleaks runner uses for a provider-scoped account credential. It
 * is the only prose marker this module reads, and it is read only to pick
 * between two escalations that both already sit at `critical` — see the note on
 * {@link signalsOf}.
 */
const CLOUD_CREDENTIAL_MARKER = "cloud provider credential";

/** Pulls the CVE id out of a dependency finding's title (`CVE-2024-1234 in pkg@1.2.3`). */
export function cveIdOf(finding: Finding): string | null {
  return /\b(CVE-\d{4}-\d{4,})\b/.exec(finding.title)?.[1] ?? null;
}

/** What a caller can tell the policy that the finding itself cannot. */
export interface SignalOptions {
  /**
   * CVE ids known to be exploited in the wild, upper-cased. Sentinel ships no
   * such feed today — phase 1 is offline by design — so this is empty unless a
   * caller supplies one, and R3 stays inert rather than guessing.
   */
  readonly knownExploitedCves?: ReadonlySet<string> | undefined;
}

/**
 * Reads the escalation signals off a finding.
 *
 * Everything here is derived from structured fields — the rule id, the CWE
 * list, the confidence, and whether the citation carries a snippet — with one
 * exception: telling a cloud credential from any other one uses the phrase the
 * gitleaks runner writes into the title, because the `Finding` contract has no
 * field for "what kind of credential". Both branches escalate to `critical`, so
 * the marker only decides which sentence the report prints.
 */
export function signalsOf(finding: Finding, options: SignalOptions = {}): SeveritySignals {
  const signals: {
    secret?: SecretExposure;
    secretEvidence?: SecretEvidence;
    credential?: CredentialKind;
    knownExploited?: boolean;
  } = {};

  if (finding.rule === SECRET_RULE) {
    // A secret citation with no snippet is one Sentinel could not read back off
    // disk: the file was deleted or rewritten, and the value survives only in
    // the history the scanner walked.
    signals.secret = finding.location.snippet === undefined ? "history-only" : "worktree";
    // `confidence` is the evidence channel: {@link gradeSecret} issues `high` for
    // a provider-specific match and never for anything else, so this reads the
    // model's verdict rather than re-deriving it from prose.
    signals.secretEvidence = finding.confidence === "high" ? "provider-specific" : "heuristic";
    // An entropy-and-shape match is a lead, not proof of which account it opens,
    // so R2 is withheld from it.
    if (finding.confidence === "high") {
      signals.credential = finding.cwe.some((cwe) => cwe.startsWith(PRIVATE_KEY_CWE))
        ? "private-key"
        : finding.title.toLowerCase().includes(CLOUD_CREDENTIAL_MARKER)
          ? "cloud"
          : "generic";
    }
  }

  const known = options.knownExploitedCves;
  if (known !== undefined && known.size > 0 && finding.rule === VULNERABLE_PACKAGE_RULE) {
    const cve = cveIdOf(finding);
    if (cve !== null) signals.knownExploited = known.has(cve.toUpperCase());
  }

  return signals;
}

/** Runs the whole policy over one finding: reads its signals, then escalates. */
export function escalateFinding(finding: Finding, options: SignalOptions = {}): SeverityDecision {
  return escalate(finding.severity, signalsOf(finding, options));
}
