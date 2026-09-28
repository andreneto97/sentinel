import type { DetectedFact } from "../contracts/profile.ts";
import type { DetectionContext } from "./detector.ts";
import { type DetectionResult, type Probe, ref } from "./fact-builder.ts";
import {
  type DependencySignal,
  factsFromDependencies,
  findDependency,
  signalLabels,
} from "./manifest.ts";

/** Authentication libraries, proven by a declared dependency. */
export const AUTH_SIGNALS: readonly DependencySignal[] = [
  { value: "next-auth", packages: ["next-auth", "@auth/core"] },
  { value: "clerk", prefixes: ["@clerk/"] },
  { value: "auth0", packages: ["auth0", "@auth0/nextjs-auth0", "express-openid-connect"] },
  { value: "lucia", packages: ["lucia"], prefixes: ["@lucia-auth/"] },
  { value: "better-auth", packages: ["better-auth"] },
  { value: "passport", packages: ["passport"], prefixes: ["passport-"] },
  { value: "jsonwebtoken", packages: ["jsonwebtoken"] },
  { value: "jose", packages: ["jose"] },
];

/**
 * Supabase ships auth and a database in one client, so the dependency alone
 * proves neither; the auth fact is only emitted when a call site uses it.
 */
const SUPABASE_PACKAGES = ["@supabase/supabase-js", "@supabase/ssr"] as const;

/** Session middleware and stores, which decide cookie flags and session lifetime. */
export const SESSION_STORE_SIGNALS: readonly DependencySignal[] = [
  { value: "express-session", packages: ["express-session"] },
  { value: "cookie-session", packages: ["cookie-session"] },
  { value: "iron-session", packages: ["iron-session"] },
  { value: "fastify-session", packages: ["@fastify/session", "@fastify/secure-session"] },
  { value: "connect-redis", packages: ["connect-redis"] },
  { value: "connect-mongo", packages: ["connect-mongo"] },
];

/**
 * Call sites that decide whether a request is authenticated.
 *
 * The appsec phase needs the *location* of the check, not just the library:
 * "this handler never calls the guard" is only provable once the guard is known.
 */
const AUTH_CHECK_PATTERNS: ReadonlyArray<{ readonly pattern: RegExp; readonly label: string }> = [
  { pattern: /\bgetServerSession\s*\(/, label: "next-auth getServerSession" },
  { pattern: /\bgetServerAuthSession\s*\(/, label: "next-auth session helper" },
  { pattern: /\bunstable_getServerSession\s*\(/, label: "next-auth session helper" },
  { pattern: /\b(?:auth|clerkClient)\s*\(\s*\)\s*\.protect\s*\(/, label: "clerk auth().protect()" },
  { pattern: /\b(?:currentUser|getAuth)\s*\(/, label: "clerk currentUser/getAuth" },
  { pattern: /\bsupabase\s*\.auth\s*\.(getUser|getSession)\s*\(/, label: "supabase auth check" },
  { pattern: /\bjwt\s*\.verify\s*\(/, label: "jsonwebtoken verify" },
  { pattern: /\bjwtVerify\s*\(/, label: "jose jwtVerify" },
  { pattern: /\bpassport\s*\.authenticate\s*\(/, label: "passport.authenticate" },
  { pattern: /@UseGuards\s*\(/, label: "nestjs @UseGuards" },
  {
    pattern:
      /\b(?:export\s+)?(?:async\s+)?function\s+(requireAuth|requireUser|requireSession|ensureAuthenticated|isAuthenticated|assertAuthenticated|withAuth)\b/,
    label: "hand-rolled auth guard",
  },
  {
    pattern:
      /\bconst\s+(requireAuth|requireUser|requireSession|ensureAuthenticated|isAuthenticated|withAuth)\s*[:=]/,
    label: "hand-rolled auth guard",
  },
];

const MAX_AUTH_HELPERS = 25;

/** Detects the auth provider, session store, and where the authentication check lives. */
export async function detectAuth(context: DetectionContext): Promise<DetectionResult> {
  const { manifests, snapshot } = context;
  const providerFacts = factsFromDependencies(manifests, "auth-provider", AUTH_SIGNALS);
  const facts: DetectedFact[] = [
    ...providerFacts,
    ...factsFromDependencies(manifests, "session-store", SESSION_STORE_SIGNALS),
  ];

  const helpersByFile = new Map<string, { line: number; labels: Set<string> }>();
  let verifiesJwtInline = false;
  let jwtEvidence: { file: string; line: number } | undefined;
  for (const { pattern, label } of AUTH_CHECK_PATTERNS) {
    const hits = await snapshot.grep(pattern, { limit: 100 });
    for (const hit of hits) {
      const current = helpersByFile.get(hit.file);
      if (current === undefined) {
        helpersByFile.set(hit.file, { line: hit.line, labels: new Set([label]) });
      } else {
        current.labels.add(label);
      }
      if (label === "jsonwebtoken verify" || label === "jose jwtVerify") {
        verifiesJwtInline = true;
        jwtEvidence ??= { file: hit.file, line: hit.line };
      }
    }
  }
  const sortedHelpers = [...helpersByFile.entries()].sort(([a], [b]) => a.localeCompare(b));
  for (const [file, helper] of sortedHelpers.slice(0, MAX_AUTH_HELPERS)) {
    facts.push({
      kind: "auth-helper",
      value: file,
      confidence: "high",
      detail: [...helper.labels].sort().join(", "),
      evidence: [ref(file, helper.line)],
    });
  }

  const supabaseHelper = sortedHelpers.find(([, helper]) =>
    helper.labels.has("supabase auth check"),
  );
  const supabaseDependency = SUPABASE_PACKAGES.map((name) => findDependency(manifests, name)).find(
    (hit) => hit !== undefined,
  );
  if (supabaseHelper !== undefined && supabaseDependency !== undefined) {
    facts.push({
      kind: "auth-provider",
      value: "supabase-auth",
      confidence: "high",
      detail: `${supabaseDependency.name} with an auth call site`,
      evidence: [ref(supabaseHelper[0], supabaseHelper[1].line)],
    });
  }

  // A JWT verified by hand is a different audit surface from a managed
  // provider: expiry, algorithm and signature checks are the repo's problem.
  const managed = new Set(["next-auth", "clerk", "auth0", "better-auth", "lucia"]);
  const hasManagedProvider =
    providerFacts.some((f) => managed.has(f.value)) || supabaseHelper !== undefined;
  if (verifiesJwtInline && jwtEvidence !== undefined && !hasManagedProvider) {
    facts.push({
      kind: "auth-provider",
      value: "hand-rolled-jwt",
      confidence: "high",
      detail: "tokens are verified in application code",
      evidence: [ref(jwtEvidence.file, jwtEvidence.line)],
    });
  }

  const warnings: string[] = [];
  if (providerFacts.length > 0 && helpersByFile.size === 0) {
    warnings.push(
      "An authentication library is declared but no authentication check call site was found; the appsec phase has no guard to compare handlers against.",
    );
  }

  const probes: Probe[] = [
    { kind: "auth-provider", searched: [...signalLabels(AUTH_SIGNALS), ...SUPABASE_PACKAGES] },
    { kind: "session-store", searched: signalLabels(SESSION_STORE_SIGNALS) },
    {
      kind: "auth-helper",
      searched: AUTH_CHECK_PATTERNS.map((entry) => entry.label),
      note: "Without a known auth check, per-handler authorization findings cannot be grounded.",
    },
  ];

  return { facts, probes, warnings };
}
