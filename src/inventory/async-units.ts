/**
 * Phase 2 — the units that run outside a request/response cycle (D5), plus the
 * inbound receivers that only look like routes (D2).
 *
 * Serverless functions, queue consumers, scheduled work, webhook receivers and
 * CI jobs are where a backend audit usually stops looking: they are declared in
 * five different file formats, none of them is a route, and no linter counts
 * them. Enumerating them is what lets the report say "6/6 queue consumers
 * audited, none of them deduplicates" instead of never mentioning the queue.
 *
 * Where a unit comes from decides how it is read:
 *
 * - **Manifests** (`serverless.yml`, a SAM template, `vercel.json`,
 *   `wrangler.toml`, a workflow) are parsed, because their structure *is* the
 *   declaration. YAML goes through the reader the delivery rules already use,
 *   which records the file line of every node — a unit without an exact line
 *   cannot be sliced into an audit prompt.
 * - **Code** (a BullMQ worker, a Firebase function, an edge route) goes
 *   through ast-grep, because a regular expression cannot tell a call from the
 *   same words in a comment, and precision here is a coverage claim.
 *
 * A library-specific pattern is only believed in a file that imports the
 * library: `new Worker(...)` is a BullMQ consumer in a file that imports
 * `bullmq` and a browser API everywhere else.
 */

import { basename } from "node:path";
import { z } from "zod";
import type { AuditUnit } from "../contracts/findings.ts";
import { ATTRIBUTE } from "../contracts/inventory.ts";
import { escapeRegExp, importPattern, toLines } from "../profile/text.ts";
import {
  type YamlEntry,
  type YamlNode,
  childOf,
  entriesOf,
  entryOf,
  itemsOf,
  parseYaml,
  textOf,
} from "../scan/rules/_mini-yaml.ts";
import type { StructuralMatch, StructuralRule } from "./_ast-grep.ts";
import {
  type AttributePatch,
  type DraftUnit,
  type EnumerationContext,
  type EnumerationOutcome,
  type InventoryEnumerator,
  brief,
  collapse,
  contentSymbol,
  enclosingSymbol,
  finishOutcome,
  literalOf,
  literalOrExpression,
  notApplicable,
  optionOf,
} from "./_unit-support.ts";
import {
  type ClassifiedCandidate,
  type ProviderCall,
  classifyWebhookCandidate,
  isProductionCandidate,
  isWebhookCandidatePath,
  reclassificationNote,
  stripProse,
} from "./_webhook-shape.ts";

/** Cap per manifest kind, so a pathological monorepo cannot turn phase 2 into a crawl. */
const MAX_MANIFESTS = 50;

/** Attribute value used when a setting exists but is not derivable from the declaration. */
const UNKNOWN = "unknown";

/** Attribute value for a protection that is simply not configured. */
const NONE = "none";

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/** Reads and parses a YAML manifest through the shared snapshot; null when unreadable. */
async function readYaml(
  ctx: EnumerationContext,
  file: string,
): Promise<{ root: YamlNode | null; errors: readonly string[] } | null> {
  const text = await ctx.snapshot.read(file);
  if (text === undefined) return null;
  return parseYaml(text);
}

/** True when the file imports (or requires) any of the packages. */
async function importsAny(
  ctx: EnumerationContext,
  file: string,
  packages: readonly string[],
): Promise<boolean> {
  const text = await ctx.snapshot.read(file);
  if (text === undefined) return false;
  return packages.some((name) => importPattern(name).test(text));
}

/** The first capture of a pattern over a text, or undefined. */
function firstMatch(text: string, pattern: RegExp): string | undefined {
  const found = pattern.exec(text);
  return found?.[1];
}

/**
 * The request path a Next.js file serves, or undefined when it serves none.
 *
 * Both routers, route groups (`(admin)`) and parallel routes (`@modal`)
 * removed, dynamic segments kept as written so a cron path can be matched
 * against them.
 */
export function nextRoutePath(file: string): string | undefined {
  const segments = file.split("/");
  const last = segments[segments.length - 1] ?? "";
  const appIndex = segments.lastIndexOf("app");
  const pagesIndex = segments.lastIndexOf("pages");

  if (appIndex !== -1 && appIndex > pagesIndex) {
    if (!/^(route|page)\.[cm]?[jt]sx?$/.test(last)) return undefined;
    const parts = segments
      .slice(appIndex + 1, -1)
      .filter((part) => !(part.startsWith("(") && part.endsWith(")")) && !part.startsWith("@"));
    return `/${parts.join("/")}`;
  }
  if (pagesIndex !== -1) {
    if (!/\.[cm]?[jt]sx?$/.test(last)) return undefined;
    const parts = segments.slice(pagesIndex + 1, -1);
    const base = last.replace(/\.[cm]?[jt]sx?$/, "");
    return `/${[...parts, ...(base === "index" ? [] : [base])].join("/")}`;
  }
  return undefined;
}

/** Compares two request paths, treating any dynamic segment as a wildcard. */
export function samePath(left: string | undefined, right: string | undefined): boolean {
  if (left === undefined || right === undefined) return false;
  const normalise = (value: string): string[] =>
    value
      .split("?")[0]
      ?.replace(/\/+$/, "")
      .split("/")
      .map((part) =>
        /^[[:{].*[\]:}]$/.test(part) || part.startsWith(":") || part.startsWith("[") ? "*" : part,
      ) ?? [];
  const a = normalise(left);
  const b = normalise(right);
  if (a.length !== b.length) return false;
  return a.every((part, index) => part === "*" || b[index] === "*" || part === b[index]);
}

/** Matches a Vercel `functions` glob (`api/**\/*.ts`) against a repo-relative path. */
export function matchesGlob(pattern: string, file: string): boolean {
  let source = "";
  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index] ?? "";
    if (char === "*") {
      if (pattern[index + 1] === "*") {
        index += 1;
        if (pattern[index + 1] === "/") index += 1;
        source += "(?:.*/)?";
        continue;
      }
      source += "[^/]*";
      continue;
    }
    if (char === "?") {
      source += "[^/]";
      continue;
    }
    source += char.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${source}$`).test(file);
}

/** A value read from a YAML node, collapsed to a single line. */
function scalarOf(node: YamlNode | null | undefined): string | undefined {
  const text = textOf(node);
  return text === null ? undefined : collapse(text);
}

/** The line a mapping entry sits on. */
function entryLine(entry: YamlEntry): number {
  return entry.line;
}

/**
 * The last line a mapping entry covers, taken as the line before the next
 * sibling starts. YAML block structure has no end token, and a unit needs a
 * range for the audit prompt to slice.
 */
function entryEnd(entries: readonly YamlEntry[], index: number, fileLines: number): number {
  const next = entries[index + 1];
  return next === undefined ? fileLines : Math.max(entries[index]?.line ?? 1, next.line - 1);
}

// ---------------------------------------------------------------------------
// Serverless functions
// ---------------------------------------------------------------------------

/** Serverless Framework event keys, mapped to the trigger vocabulary. */
const SERVERLESS_TRIGGERS: Readonly<Record<string, string>> = {
  http: "http",
  httpapi: "http",
  alb: "http",
  websocket: "http",
  schedule: "schedule",
  sqs: "queue",
  sns: "event",
  eventbridge: "event",
  cloudwatchevent: "event",
  s3: "storage",
  stream: "stream",
  kinesis: "stream",
  dynamodb: "stream",
  msk: "stream",
  kafka: "stream",
  cognitouserpool: "event",
  iot: "event",
};

/** SAM event `Type` values, mapped to the same vocabulary. */
const SAM_TRIGGERS: Readonly<Record<string, string>> = {
  api: "http",
  httpapi: "http",
  schedule: "schedule",
  schedulev2: "schedule",
  sqs: "queue",
  sns: "event",
  eventbridgerule: "event",
  s3: "storage",
  dynamodb: "stream",
  kinesis: "stream",
};

/** Reads the function-level and provider-level settings of a serverless.yml. */
async function fromServerlessYaml(ctx: EnumerationContext, notes: string[]): Promise<DraftUnit[]> {
  const units: DraftUnit[] = [];
  const files = ctx.snapshot.filesMatching(/(^|\/)serverless\.ya?ml$/).slice(0, MAX_MANIFESTS);
  for (const file of files) {
    const parsed = await readYaml(ctx, file);
    if (parsed === null) continue;
    if (parsed.errors.length > 0) notes.push(`${file}: ${parsed.errors[0]}`);
    const lineCount = (await ctx.snapshot.lines(file))?.length ?? 1;
    const provider = childOf(parsed.root, "provider");
    const providerRole =
      scalarOf(childOf(provider, "role")) ??
      (entryOf(provider, "iam") !== null ? "provider iam block" : undefined);
    const entries = entriesOf(childOf(parsed.root, "functions"));

    for (let index = 0; index < entries.length; index += 1) {
      const entry = entries[index];
      if (entry === undefined) continue;
      const fn = entry.value;
      const events = itemsOf(childOf(fn, "events"));
      const triggers = new Set<string>();
      const queues: string[] = [];
      let publicUrl = scalarOf(childOf(fn, "url")) === "true" ? "function-url" : "no";
      let authenticated: string | undefined;

      for (const event of events) {
        for (const eventEntry of entriesOf(event)) {
          const key = eventEntry.key.toLowerCase();
          triggers.add(SERVERLESS_TRIGGERS[key] ?? key);
          if (SERVERLESS_TRIGGERS[key] === "http") {
            publicUrl = "yes";
            const authorizer =
              entryOf(eventEntry.value, "authorizer") !== null ||
              scalarOf(childOf(eventEntry.value, "private")) === "true";
            authenticated = authorizer ? "yes" : (authenticated ?? "no");
          }
          if (key === "sqs") {
            const queue =
              scalarOf(childOf(eventEntry.value, "queueName")) ??
              scalarOf(childOf(eventEntry.value, "arn")) ??
              scalarOf(eventEntry.value);
            if (queue !== undefined) queues.push(queue);
          }
        }
      }

      const name = entry.key;
      units.push({
        kind: "serverless-function",
        label: `${name} (${basename(file)})`,
        file,
        line: entryLine(entry),
        endLine: entryEnd(entries, index, lineCount),
        symbol: `fn:${name}`,
        attributes: {
          [ATTRIBUTE.platform]: "aws-lambda",
          declaredBy: "serverless-framework",
          handler: scalarOf(childOf(fn, "handler")),
          [ATTRIBUTE.trigger]: triggers.size === 0 ? NONE : [...triggers].sort().join(","),
          [ATTRIBUTE.queue]: queues.length === 0 ? undefined : queues.join(","),
          memory: scalarOf(childOf(fn, "memorySize")) ?? scalarOf(childOf(provider, "memorySize")),
          timeout: scalarOf(childOf(fn, "timeout")) ?? scalarOf(childOf(provider, "timeout")),
          runtimeVersion:
            scalarOf(childOf(fn, "runtime")) ?? scalarOf(childOf(provider, "runtime")),
          publicUrl,
          [ATTRIBUTE.authenticated]: authenticated,
          iamRoleRef:
            scalarOf(childOf(fn, "role")) ??
            (entryOf(fn, "iamRoleStatements") !== null ? "inline-statements" : undefined) ??
            providerRole ??
            "provider-default",
          dlq: scalarOf(childOf(fn, "onError")) ?? NONE,
          concurrency:
            scalarOf(childOf(fn, "reservedConcurrency")) ??
            scalarOf(childOf(fn, "provisionedConcurrency")) ??
            "unset",
        },
      });
    }
  }
  return units;
}

/** Reads `AWS::Serverless::Function` and `AWS::Lambda::Function` resources. */
async function fromSamTemplates(ctx: EnumerationContext, notes: string[]): Promise<DraftUnit[]> {
  const units: DraftUnit[] = [];
  const files = ctx.snapshot.filesMatching(/(^|\/)template\.ya?ml$/).slice(0, MAX_MANIFESTS);
  for (const file of files) {
    const text = await ctx.snapshot.read(file);
    if (text === undefined || !/AWS::(Serverless|Lambda)::Function/.test(text)) continue;
    const parsed = parseYaml(text);
    if (parsed.errors.length > 0) notes.push(`${file}: ${parsed.errors[0]}`);
    const lineCount = toLines(text).length;
    const globals = childOf(childOf(parsed.root, "Globals"), "Function");
    const entries = entriesOf(childOf(parsed.root, "Resources"));

    for (let index = 0; index < entries.length; index += 1) {
      const entry = entries[index];
      if (entry === undefined) continue;
      const type = scalarOf(childOf(entry.value, "Type"));
      if (type !== "AWS::Serverless::Function" && type !== "AWS::Lambda::Function") continue;
      const properties = childOf(entry.value, "Properties");
      const triggers = new Set<string>();
      for (const event of entriesOf(childOf(properties, "Events"))) {
        const eventType = (scalarOf(childOf(event.value, "Type")) ?? "").toLowerCase();
        if (eventType !== "") triggers.add(SAM_TRIGGERS[eventType] ?? eventType);
      }
      const functionUrl = entryOf(properties, "FunctionUrlConfig");
      const authType = scalarOf(childOf(functionUrl?.value, "AuthType"));

      units.push({
        kind: "serverless-function",
        label: `${entry.key} (${basename(file)})`,
        file,
        line: entryLine(entry),
        endLine: entryEnd(entries, index, lineCount),
        symbol: `resource:${entry.key}`,
        attributes: {
          [ATTRIBUTE.platform]: "aws-lambda",
          declaredBy: type === "AWS::Lambda::Function" ? "cloudformation" : "aws-sam",
          handler: scalarOf(childOf(properties, "Handler")),
          [ATTRIBUTE.trigger]: triggers.size === 0 ? NONE : [...triggers].sort().join(","),
          memory:
            scalarOf(childOf(properties, "MemorySize")) ?? scalarOf(childOf(globals, "MemorySize")),
          timeout:
            scalarOf(childOf(properties, "Timeout")) ?? scalarOf(childOf(globals, "Timeout")),
          runtimeVersion:
            scalarOf(childOf(properties, "Runtime")) ?? scalarOf(childOf(globals, "Runtime")),
          publicUrl: functionUrl === null ? "no" : "function-url",
          [ATTRIBUTE.authenticated]:
            authType === undefined ? undefined : authType === "NONE" ? "no" : "yes",
          iamRoleRef: scalarOf(childOf(properties, "Role")) ?? "generated-role",
          dlq:
            scalarOf(childOf(childOf(properties, "DeadLetterQueue"), "TargetArn")) ??
            scalarOf(childOf(childOf(properties, "DeadLetterConfig"), "TargetArn")) ??
            NONE,
          concurrency: scalarOf(childOf(properties, "ReservedConcurrentExecutions")) ?? "unset",
        },
      });
    }
  }
  return units;
}

/** The subset of `vercel.json` phase 2 reads. */
const VercelConfigSchema = z.object({
  crons: z.array(z.object({ path: z.string(), schedule: z.string() })).optional(),
  functions: z
    .record(
      z.string(),
      z.object({
        memory: z.number().optional(),
        maxDuration: z.number().optional(),
        runtime: z.string().optional(),
      }),
    )
    .optional(),
});
type VercelConfig = z.infer<typeof VercelConfigSchema>;

/** Reads `vercel.json`, or null when it is absent or malformed. */
async function readVercelConfig(ctx: EnumerationContext): Promise<VercelConfig | null> {
  const file = ctx.snapshot.firstExisting(["vercel.json"]);
  if (file === undefined) return null;
  const raw = await ctx.snapshot.read(file);
  if (raw === undefined) return null;
  try {
    const parsed = VercelConfigSchema.safeParse(JSON.parse(raw));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

/** Rule ids for the structural queries this file runs. */
const RULE = {
  edgeRuntime: "edge-runtime",
  maxDuration: "max-duration",
  firebaseHttps: "firebase-https",
  firebaseCallable: "firebase-callable",
  firebaseSchedule: "firebase-schedule",
  firebaseEvent: "firebase-event",
  cdkFunction: "cdk-function",
  bullWorker: "bull-worker",
  queueProcess: "queue-process",
  sqsConsumer: "sqs-consumer",
  sqsReceive: "sqs-receive",
  inngestFunction: "inngest-function",
  triggerJob: "trigger-job",
  triggerTask: "trigger-task",
  bossWork: "boss-work",
  agendaDefine: "agenda-define",
  kafkaSubscribe: "kafka-subscribe",
  amqpConsume: "amqp-consume",
  nestProcessor: "nest-processor",
  nodeCron: "node-cron",
  cronJob: "cron-job",
  scheduleJob: "schedule-job",
  nestCron: "nest-cron",
  repeatableJob: "repeatable-job",
  jobScheduler: "job-scheduler",
  stripeWebhook: "stripe-webhook",
  svixWebhook: "svix-webhook",
  twilioWebhook: "twilio-webhook",
  octokitWebhook: "octokit-webhook",
} as const;

/** `export const runtime = "edge"` and its `maxDuration` sibling. */
const EDGE_RULES: readonly StructuralRule[] = [
  {
    id: RULE.edgeRuntime,
    languages: ["TypeScript", "Tsx", "JavaScript"],
    rule: { pattern: "export const runtime = $VALUE" },
  },
  {
    id: RULE.maxDuration,
    languages: ["TypeScript", "Tsx", "JavaScript"],
    rule: { pattern: "export const maxDuration = $VALUE" },
  },
];

/** Firebase and CDK declarations, all of them ordinary calls. */
const FUNCTION_RULES: readonly StructuralRule[] = [
  { id: RULE.firebaseHttps, rule: { pattern: "$X.https.onRequest($$$ARGS)" } },
  { id: RULE.firebaseCallable, rule: { pattern: "$X.https.onCall($$$ARGS)" } },
  {
    id: RULE.firebaseSchedule,
    rule: { any: [{ pattern: "$X.pubsub.schedule($$$ARGS)" }, { pattern: "onSchedule($$$ARGS)" }] },
  },
  {
    id: RULE.firebaseEvent,
    rule: {
      any: [
        { pattern: "onRequest($$$ARGS)" },
        { pattern: "onCall($$$ARGS)" },
        { pattern: "onMessagePublished($$$ARGS)" },
        { pattern: "onObjectFinalized($$$ARGS)" },
        { pattern: "onDocumentCreated($$$ARGS)" },
        { pattern: "onDocumentWritten($$$ARGS)" },
        { pattern: "$X.firestore.document($$$ARGS)" },
        { pattern: "$X.storage.object($$$ARGS)" },
      ],
    },
  },
  {
    id: RULE.cdkFunction,
    languages: ["TypeScript", "JavaScript"],
    rule: {
      any: [
        { pattern: "new lambda.Function($$$ARGS)" },
        { pattern: "new lambda.NodejsFunction($$$ARGS)" },
        { pattern: "new NodejsFunction($$$ARGS)" },
        { pattern: "new lambda.DockerImageFunction($$$ARGS)" },
      ],
    },
  },
];

/** Firebase packages; a bare `onRequest(...)` is only believed in a file that imports one. */
const FIREBASE_PACKAGES = ["firebase-functions"];

/** The trigger each Firebase rule implies. */
const FIREBASE_TRIGGER: Readonly<Record<string, string>> = {
  [RULE.firebaseHttps]: "http",
  [RULE.firebaseCallable]: "http",
  [RULE.firebaseSchedule]: "schedule",
};

/** Edge routes, Vercel middleware and the `vercel.json` settings that apply to them. */
async function fromVercel(
  ctx: EnumerationContext,
  matches: readonly StructuralMatch[],
): Promise<DraftUnit[]> {
  const units: DraftUnit[] = [];
  const config = await readVercelConfig(ctx);
  const durations = new Map<string, string>();
  for (const match of matches) {
    if (match.ruleId !== RULE.maxDuration) continue;
    const value = match.vars.VALUE;
    if (value !== undefined) durations.set(match.file, collapse(value));
  }

  /** Memory and duration `vercel.json` declares for a file, by glob. */
  const configured = (file: string): { memory?: string; timeout?: string } => {
    for (const [pattern, settings] of Object.entries(config?.functions ?? {})) {
      if (!matchesGlob(pattern, file)) continue;
      return {
        ...(settings.memory === undefined ? {} : { memory: String(settings.memory) }),
        ...(settings.maxDuration === undefined ? {} : { timeout: String(settings.maxDuration) }),
      };
    }
    return {};
  };

  for (const match of matches) {
    if (match.ruleId !== RULE.edgeRuntime) continue;
    if (literalOf(match.vars.VALUE) !== "edge") continue;
    const path = nextRoutePath(match.file);
    const settings = configured(match.file);
    // The unit is the whole module, not the one-line export that declares it:
    // what phase 4 has to read is the handler underneath.
    const lineCount = (await ctx.snapshot.lines(match.file))?.length;
    units.push({
      kind: "serverless-function",
      label: path === undefined ? `edge ${match.file}` : `edge ${path}`,
      file: match.file,
      line: match.line,
      endLine: lineCount ?? match.endLine,
      symbol: "edge-runtime",
      attributes: {
        [ATTRIBUTE.platform]: "vercel-edge",
        [ATTRIBUTE.trigger]: "http",
        [ATTRIBUTE.path]: path,
        runtimeVersion: "edge",
        publicUrl: path === undefined ? UNKNOWN : "yes",
        timeout: durations.get(match.file) ?? settings.timeout,
        memory: settings.memory,
      },
    });
  }

  for (const file of ctx.snapshot.filesMatching(/(^|\/)(src\/)?middleware\.[cm]?[jt]sx?$/)) {
    const text = await ctx.snapshot.read(file);
    if (text === undefined || !/export\s+(async\s+)?(function|const|default)\s+/.test(text)) {
      continue;
    }
    if (!/\bmiddleware\b|\bNextResponse\b/.test(text)) continue;
    const lines = toLines(text);
    const line = lines.findIndex((entry) =>
      /export\s+.*\bmiddleware\b|export\s+default/.test(entry),
    );
    units.push({
      kind: "serverless-function",
      label: `edge middleware (${file})`,
      file,
      line: line === -1 ? 1 : line + 1,
      endLine: lines.length,
      symbol: "middleware",
      attributes: {
        [ATTRIBUTE.platform]: "vercel-edge",
        [ATTRIBUTE.trigger]: "http",
        runtimeVersion: "edge",
        publicUrl: "yes",
        matcher: firstMatch(text, /matcher\s*:\s*(\[[^\]]*\]|['"][^'"]*['"])/) ?? UNKNOWN,
      },
    });
  }

  return units;
}

/** Cloudflare Workers, read out of `wrangler.toml` / `wrangler.json(c)`. */
async function fromWrangler(ctx: EnumerationContext): Promise<DraftUnit[]> {
  const units: DraftUnit[] = [];
  const files = ctx.snapshot
    .filesMatching(/(^|\/)wrangler\.(toml|jsonc?)$/)
    .slice(0, MAX_MANIFESTS);
  for (const file of files) {
    const text = await ctx.snapshot.read(file);
    if (text === undefined) continue;
    const name =
      firstMatch(text, /(?:^|\n)\s*"?name"?\s*[=:]\s*["']([^"']+)["']/) ?? basename(file);
    const main = firstMatch(text, /(?:^|\n)\s*"?main"?\s*[=:]\s*["']([^"']+)["']/);
    const crons = firstMatch(text, /crons"?\s*[=:]\s*\[([^\]]*)\]/);
    const compatibility = firstMatch(text, /compatibility_date"?\s*[=:]\s*["']([^"']+)["']/);
    const entry = main === undefined ? undefined : resolveRelative(ctx, file, main);
    const entryText = entry === undefined ? undefined : await ctx.snapshot.read(entry);
    const triggers = new Set<string>();
    if (crons !== undefined && crons.trim() !== "") triggers.add("schedule");
    if (entryText !== undefined) {
      if (/\bfetch\s*[(:]/.test(entryText)) triggers.add("http");
      if (/\bqueue\s*[(:]/.test(entryText)) triggers.add("queue");
      if (/\bscheduled\s*[(:]/.test(entryText)) triggers.add("schedule");
    }
    if (triggers.size === 0) triggers.add("http");

    const located = entry ?? file;
    const lines = entryText === undefined ? undefined : toLines(entryText);
    const defaultExport = lines?.findIndex((line) => /export\s+default/.test(line)) ?? -1;

    units.push({
      kind: "serverless-function",
      label: `worker ${name}`,
      file: located,
      line: entry === undefined ? 1 : defaultExport === -1 ? 1 : defaultExport + 1,
      endLine: lines?.length,
      symbol: `worker:${name}`,
      attributes: {
        [ATTRIBUTE.platform]: "cloudflare-workers",
        declaredBy: basename(file),
        [ATTRIBUTE.trigger]: [...triggers].sort().join(","),
        [ATTRIBUTE.schedule]: crons === undefined ? undefined : cronList(crons).join(","),
        runtimeVersion: compatibility,
        publicUrl: /workers_dev"?\s*[=:]\s*true|routes"?\s*[=:]/.test(text) ? "yes" : UNKNOWN,
      },
    });
  }
  return units;
}

/** Splits a `crons = ["a", "b"]` array into its expressions. */
function cronList(raw: string): string[] {
  return raw
    .split(",")
    .map((entry) => entry.trim().replace(/^['"]|['"]$/g, ""))
    .filter((entry) => entry !== "");
}

/** Resolves a manifest-relative path (`./src/index.ts`) to a repo-relative one. */
function resolveRelative(
  ctx: EnumerationContext,
  manifest: string,
  reference: string,
): string | undefined {
  const dir = manifest.includes("/") ? manifest.slice(0, manifest.lastIndexOf("/")) : "";
  const cleaned = reference.replace(/^\.\//, "");
  const candidate = dir === "" ? cleaned : `${dir}/${cleaned}`;
  if (ctx.snapshot.has(candidate)) return candidate;
  return ctx.snapshot.has(cleaned) ? cleaned : undefined;
}

/** Supabase edge functions: one directory each, with the JWT setting from `config.toml`. */
async function fromSupabase(ctx: EnumerationContext): Promise<DraftUnit[]> {
  const units: DraftUnit[] = [];
  const files = ctx.snapshot
    .filesMatching(/(^|\/)supabase\/functions\/[^/]+\/index\.[cm]?[jt]s$/)
    .slice(0, MAX_MANIFESTS);
  const config = (await ctx.snapshot.read("supabase/config.toml")) ?? "";
  for (const file of files) {
    const name = file.split("/").slice(-2, -1)[0] ?? file;
    const section = new RegExp(
      `\\[functions\\.${escapeRegExp(name)}\\]([\\s\\S]*?)(?=\\n\\[|$)`,
    ).exec(config)?.[1];
    const verifyJwt =
      section === undefined ? undefined : firstMatch(section, /verify_jwt\s*=\s*(\w+)/);
    const lines = (await ctx.snapshot.lines(file))?.length;
    units.push({
      kind: "serverless-function",
      label: `supabase function ${name}`,
      file,
      line: 1,
      endLine: lines,
      symbol: `supabase:${name}`,
      attributes: {
        [ATTRIBUTE.platform]: "supabase-functions",
        [ATTRIBUTE.trigger]: "http",
        publicUrl: "yes",
        // Supabase verifies the JWT unless a function opts out, so an absent
        // setting is a default rather than an unknown.
        [ATTRIBUTE.authenticated]: verifyJwt === "false" ? "no" : "yes",
        verifyJwt: verifyJwt ?? "true (default)",
      },
    });
  }
  return units;
}

/** Firebase functions and CDK lambdas, from the structural matches. */
async function fromCode(
  ctx: EnumerationContext,
  matches: readonly StructuralMatch[],
): Promise<DraftUnit[]> {
  const units: DraftUnit[] = [];
  for (const match of matches) {
    const lines = (await ctx.snapshot.lines(match.file)) ?? [];
    const symbol = enclosingSymbol(lines, match.line);

    if (match.ruleId === RULE.cdkFunction) {
      const args = match.lists.ARGS ?? [];
      const id = literalOf(args[1]) ?? symbol ?? "lambda";
      const props = args[2] ?? "";
      units.push({
        kind: "serverless-function",
        label: `${id} (cdk)`,
        file: match.file,
        line: match.line,
        endLine: match.endLine,
        symbol: `cdk:${id}`,
        attributes: {
          [ATTRIBUTE.platform]: "aws-lambda",
          declaredBy: "aws-cdk",
          // A CDK trigger is attached by a separate `addEventSource` call, so
          // the construct alone cannot say what invokes it.
          [ATTRIBUTE.trigger]: UNKNOWN,
          [ATTRIBUTE.symbol]: symbol,
          handler: literalOf(optionOf(props, "handler")) ?? optionOf(props, "handler"),
          memory: optionOf(props, "memorySize"),
          timeout: optionOf(props, "timeout"),
          runtimeVersion: optionOf(props, "runtime"),
          iamRoleRef: optionOf(props, "role") ?? "generated-role",
          dlq: optionOf(props, "deadLetterQueue") ?? NONE,
          concurrency: optionOf(props, "reservedConcurrentExecutions") ?? "unset",
        },
      });
      continue;
    }

    if (!(await importsAny(ctx, match.file, FIREBASE_PACKAGES))) continue;
    const args = match.lists.ARGS ?? [];
    const options = args.find((argument) => argument.trim().startsWith("{")) ?? "";
    const name = symbol ?? contentSymbol("fn", match.text);
    const trigger = FIREBASE_TRIGGER[match.ruleId] ?? "event";
    units.push({
      kind: "serverless-function",
      label: `${name} (firebase ${trigger})`,
      file: match.file,
      line: match.line,
      endLine: match.endLine,
      symbol: `firebase:${name}`,
      attributes: {
        [ATTRIBUTE.platform]: "firebase-functions",
        [ATTRIBUTE.trigger]: trigger,
        [ATTRIBUTE.symbol]: symbol,
        memory: literalOf(optionOf(match.text, "memory")) ?? optionOf(options, "memory"),
        timeout: optionOf(match.text, "timeoutSeconds"),
        concurrency: optionOf(match.text, "concurrency") ?? "unset",
        publicUrl: trigger === "http" ? "yes" : "no",
        [ATTRIBUTE.authenticated]:
          match.ruleId === RULE.firebaseCallable ? "yes (callable context)" : undefined,
      },
    });
  }
  return units;
}

/** Enumerates every function that runs on somebody else's compute. */
export const serverlessFunctionEnumerator: InventoryEnumerator = {
  name: "serverless-functions",
  kinds: ["serverless-function"],
  async enumerate(ctx: EnumerationContext): Promise<EnumerationOutcome> {
    const notes: string[] = [];
    const found = await ctx.search.search([...EDGE_RULES, ...FUNCTION_RULES]);
    if (!found.ok && found.reason !== undefined) notes.push(found.reason);

    const units = [
      ...(await fromServerlessYaml(ctx, notes)),
      ...(await fromSamTemplates(ctx, notes)),
      ...(await fromVercel(ctx, found.matches)),
      ...(await fromWrangler(ctx)),
      ...(await fromSupabase(ctx)),
      ...(await fromCode(ctx, found.matches)),
    ];

    return finishOutcome(units, {
      notes,
      searchOk: found.ok,
      emptyReason: "no serverless function is declared in this repository",
    });
  },
};

// ---------------------------------------------------------------------------
// Queue consumers
// ---------------------------------------------------------------------------

/** One consumer pattern: the rule that finds it, and what it means when it matches. */
interface ConsumerSignal {
  readonly ruleId: string;
  readonly library: string;
  /** Packages the file must import for the match to be believed. */
  readonly packages: readonly string[];
  /** Index of the argument naming the queue, topic or event. */
  readonly queueArgument: number;
  /** Index of the argument holding the options object, when there is one. */
  readonly optionsArgument?: number | undefined;
}

const CONSUMER_RULES: readonly StructuralRule[] = [
  { id: RULE.bullWorker, rule: { any: [{ pattern: "new Worker($$$ARGS)" }] } },
  { id: RULE.queueProcess, rule: { pattern: "$QUEUE.process($$$ARGS)" } },
  { id: RULE.sqsConsumer, rule: { pattern: "Consumer.create($$$ARGS)" } },
  { id: RULE.sqsReceive, rule: { pattern: "new ReceiveMessageCommand($$$ARGS)" } },
  { id: RULE.inngestFunction, rule: { pattern: "$CLIENT.createFunction($$$ARGS)" } },
  { id: RULE.triggerJob, rule: { pattern: "$CLIENT.defineJob($$$ARGS)" } },
  {
    id: RULE.triggerTask,
    rule: { any: [{ pattern: "task($$$ARGS)" }, { pattern: "schedules.task($$$ARGS)" }] },
  },
  {
    id: RULE.bossWork,
    rule: { any: [{ pattern: "$BOSS.work($$$ARGS)" }, { pattern: "$BOSS.subscribe($$$ARGS)" }] },
  },
  { id: RULE.agendaDefine, rule: { pattern: "$AGENDA.define($$$ARGS)" } },
  { id: RULE.kafkaSubscribe, rule: { pattern: "$CONSUMER.subscribe($$$ARGS)" } },
  { id: RULE.amqpConsume, rule: { pattern: "$CHANNEL.consume($$$ARGS)" } },
  {
    id: RULE.nestProcessor,
    languages: ["TypeScript"],
    rule: { kind: "decorator", has: { kind: "call_expression", pattern: "Processor($$$ARGS)" } },
  },
];

const CONSUMER_SIGNALS: readonly ConsumerSignal[] = [
  {
    ruleId: RULE.bullWorker,
    library: "bullmq",
    packages: ["bullmq"],
    queueArgument: 0,
    optionsArgument: 2,
  },
  {
    ruleId: RULE.queueProcess,
    library: "bull",
    packages: ["bull", "bullmq", "bee-queue"],
    queueArgument: -1,
    optionsArgument: -1,
  },
  {
    ruleId: RULE.sqsConsumer,
    library: "sqs-consumer",
    packages: ["sqs-consumer"],
    queueArgument: -1,
    optionsArgument: 0,
  },
  {
    ruleId: RULE.sqsReceive,
    library: "aws-sdk-sqs",
    packages: ["@aws-sdk/client-sqs"],
    queueArgument: -1,
    optionsArgument: 0,
  },
  {
    ruleId: RULE.inngestFunction,
    library: "inngest",
    packages: ["inngest"],
    queueArgument: 1,
    optionsArgument: 0,
  },
  {
    ruleId: RULE.triggerJob,
    library: "trigger.dev",
    packages: ["@trigger.dev/sdk"],
    queueArgument: -1,
    optionsArgument: 0,
  },
  {
    ruleId: RULE.triggerTask,
    library: "trigger.dev",
    packages: ["@trigger.dev/sdk"],
    queueArgument: -1,
    optionsArgument: 0,
  },
  {
    ruleId: RULE.bossWork,
    library: "pg-boss",
    packages: ["pg-boss"],
    queueArgument: 0,
    optionsArgument: 1,
  },
  {
    ruleId: RULE.agendaDefine,
    library: "agenda",
    packages: ["agenda", "@hokify/agenda"],
    queueArgument: 0,
    optionsArgument: 1,
  },
  {
    ruleId: RULE.kafkaSubscribe,
    library: "kafkajs",
    packages: ["kafkajs"],
    queueArgument: -1,
    optionsArgument: 0,
  },
  {
    ruleId: RULE.amqpConsume,
    library: "amqplib",
    packages: ["amqplib"],
    queueArgument: 0,
    optionsArgument: 2,
  },
  {
    ruleId: RULE.nestProcessor,
    library: "nestjs-bull",
    packages: ["@nestjs/bull", "@nestjs/bullmq"],
    queueArgument: 0,
    optionsArgument: -1,
  },
];

/** Tokens that prove a handler deduplicates its work. */
const IDEMPOTENCY_TOKENS =
  /\b(jobId|idempotencyKey|idempotency_key|deduplication|dedupeKey|dedupe)\b/;

/** Reads a deduplication token out of a consumer's own source, or reports its absence. */
export function idempotencyOf(source: string): string {
  return IDEMPOTENCY_TOKENS.exec(source)?.[1] ?? NONE;
}

/** The queue, topic or event a consumer reads from. */
function queueNameOf(signal: ConsumerSignal, args: readonly string[], options: string): string {
  if (signal.queueArgument >= 0) {
    const literal = literalOf(args[signal.queueArgument]);
    if (literal !== undefined) return literal;
  }
  const fromOptions =
    literalOf(optionOf(options, "queueUrl")) ??
    literalOf(optionOf(options, "queueName")) ??
    literalOf(optionOf(options, "topic")) ??
    literalOf(optionOf(options, "event")) ??
    literalOf(optionOf(options, "id")) ??
    literalOf(optionOf(options, "name"));
  if (fromOptions !== undefined) return fromOptions;
  const raw = args[Math.max(signal.queueArgument, 0)];
  return raw === undefined ? UNKNOWN : brief(raw, 60);
}

/** Enumerates every handler that takes work off a queue. */
export const queueConsumerEnumerator: InventoryEnumerator = {
  name: "queue-consumers",
  kinds: ["queue-consumer"],
  async enumerate(ctx: EnumerationContext): Promise<EnumerationOutcome> {
    const found = await ctx.search.search(CONSUMER_RULES);
    const notes: string[] = [];
    if (!found.ok && found.reason !== undefined) notes.push(found.reason);
    const byRule = new Map(CONSUMER_SIGNALS.map((signal) => [signal.ruleId, signal]));
    const units: DraftUnit[] = [];

    for (const match of found.matches) {
      const signal = byRule.get(match.ruleId);
      if (signal === undefined) continue;
      if (!(await importsAny(ctx, match.file, signal.packages))) continue;
      const args = match.lists.ARGS ?? [];
      const options =
        signal.optionsArgument === undefined || signal.optionsArgument < 0
          ? (args.find((argument) => argument.trim().startsWith("{")) ?? "")
          : (args[signal.optionsArgument] ?? "");
      const queue = queueNameOf(signal, args, options);
      const lines = (await ctx.snapshot.lines(match.file)) ?? [];
      const symbol = enclosingSymbol(lines, match.line);

      units.push({
        kind: "queue-consumer",
        label: `${signal.library} consumer ${queue}`,
        file: match.file,
        line: match.line,
        endLine: match.endLine,
        symbol: `consumer:${queue}:${contentSymbol("q", match.text)}`,
        attributes: {
          [ATTRIBUTE.library]: signal.library,
          [ATTRIBUTE.queue]: queue,
          [ATTRIBUTE.symbol]: symbol,
          idempotencyKey: idempotencyOf(match.text),
          attempts:
            optionOf(match.text, "attempts") ??
            optionOf(match.text, "retries") ??
            optionOf(match.text, "maxRetries") ??
            "unset",
          backoff: optionOf(match.text, "backoff") ?? "unset",
          dlq:
            optionOf(match.text, "deadLetter") ??
            optionOf(match.text, "deadLetterQueue") ??
            optionOf(match.text, "dlq") ??
            NONE,
          concurrency:
            optionOf(match.text, "concurrency") ??
            optionOf(match.text, "batchSize") ??
            optionOf(match.text, "partitionsConsumedConcurrently") ??
            "unset",
          timeout:
            optionOf(match.text, "timeout") ??
            optionOf(match.text, "lockDuration") ??
            optionOf(match.text, "visibilityTimeout") ??
            optionOf(match.text, "timeoutSeconds") ??
            "unset",
        },
      });
    }

    return finishOutcome(units, {
      notes,
      searchOk: found.ok,
      emptyReason: "no queue consumer is declared in this repository",
    });
  },
};

// ---------------------------------------------------------------------------
// Scheduled work
// ---------------------------------------------------------------------------

const CRON_RULES: readonly StructuralRule[] = [
  {
    id: RULE.nodeCron,
    rule: { any: [{ pattern: "cron.schedule($$$ARGS)" }, { pattern: "$X.schedule($$$ARGS)" }] },
  },
  {
    id: RULE.cronJob,
    rule: { any: [{ pattern: "new CronJob($$$ARGS)" }, { pattern: "new Cron($$$ARGS)" }] },
  },
  { id: RULE.scheduleJob, rule: { pattern: "$X.scheduleJob($$$ARGS)" } },
  {
    id: RULE.nestCron,
    languages: ["TypeScript"],
    rule: { kind: "decorator", has: { kind: "call_expression", pattern: "Cron($$$ARGS)" } },
  },
];

/**
 * A recurring queue job, which is scheduled work that no cron rule finds.
 *
 * `repeat: { every | pattern | cron }` is Bull's and BullMQ's repeat option and
 * effectively nothing else's, and `upsertJobScheduler` is the API that replaced
 * it. The shapes are here because a queue job that re-enqueues itself is
 * declared nowhere a cron source globs for, so a repository whose only schedule
 * looks like this would be reported as declaring *no scheduled work* at all —
 * a sentence Sentinel is not entitled to say, because a rule that was never
 * written is not the same as a repository with nothing in it.
 *
 * Matched by node kind rather than by pattern: `repeat: { ... }` is an object
 * property, and ast-grep's pattern syntax parses a bare property as an
 * expression and matches nothing.
 */
const RECURRING_JOB_RULES: readonly StructuralRule[] = [
  {
    id: RULE.repeatableJob,
    rule: {
      kind: "pair",
      all: [
        { has: { field: "key", regex: "^(repeat|'repeat'|\"repeat\")$" } },
        {
          has: {
            field: "value",
            kind: "object",
            has: { kind: "pair", has: { field: "key", regex: "^(every|pattern|cron)$" } },
          },
        },
      ],
    },
  },
  {
    id: RULE.jobScheduler,
    rule: {
      any: [
        { pattern: "$QUEUE.upsertJobScheduler($$$ARGS)" },
        { pattern: "$QUEUE.upsertRepeatableJob($$$ARGS)" },
      ],
    },
  },
];

/**
 * Vocabulary that confirms a `repeat` option belongs to a queue.
 *
 * The file that declares one rarely imports the queue library itself: a job
 * class commonly extends a base class that holds the queue, several directories
 * away, so the import guard the other code rules use would reject a real match.
 * What such a file does always carry is the queue's own vocabulary.
 */
const QUEUE_JOB_VOCABULARY =
  /\b(?:queueName|jobQueue|jobName|jobId|repeatJobKey|JobsOptions|RepeatOptions|Queue|queue)\b/;

/** In-process schedulers, by the rule that finds them. */
const CRON_PACKAGES: Readonly<Record<string, readonly string[]>> = {
  [RULE.nodeCron]: ["node-cron", "croner", "cron"],
  [RULE.cronJob]: ["cron", "croner"],
  [RULE.scheduleJob]: ["node-schedule"],
  [RULE.nestCron]: ["@nestjs/schedule"],
};

/** A cron expression looks like one: five or six fields, or an `@` shorthand. */
function looksLikeSchedule(value: string | undefined): boolean {
  if (value === undefined) return false;
  const text = value.trim();
  if (text.startsWith("@")) return true;
  const fields = text.split(/\s+/);
  return fields.length >= 5 && fields.length <= 6 && /^[\d*/,\-?A-Za-z]+$/.test(fields[0] ?? "");
}

/** Tokens that prove a cron endpoint checks something before doing the work. */
const CRON_AUTH_PATTERNS: ReadonlyArray<{ readonly token: string; readonly pattern: RegExp }> = [
  { token: "CRON_SECRET", pattern: /\bCRON_SECRET\b/ },
  { token: "x-vercel-signature", pattern: /x-vercel-signature/i },
  { token: "qstash-signature", pattern: /verifySignature|QSTASH_CURRENT_SIGNING_KEY/ },
  { token: "authorization header", pattern: /headers\s*[.[]\s*(get\()?\s*['"]authorization/i },
  { token: "bearer token", pattern: /\bBearer\s|\bbearer\b/ },
  { token: "shared secret", pattern: /\b[A-Z0-9_]*SECRET[A-Z0-9_]*\b/ },
  { token: "api key", pattern: /\b[A-Z0-9_]*API_KEY[A-Z0-9_]*\b|x-api-key/i },
  { token: "session", pattern: /getServerSession|requireAuth|\bauth\(\)|currentUser\(/ },
];

/** The check a cron target performs, or null when it performs none. */
export function cronAuthCheck(source: string): string | null {
  for (const candidate of CRON_AUTH_PATTERNS) {
    if (candidate.pattern.test(source)) return candidate.token;
  }
  return null;
}

/** `vercel.json` crons: a schedule, and the path it calls. */
async function cronsFromVercel(ctx: EnumerationContext): Promise<DraftUnit[]> {
  const config = await readVercelConfig(ctx);
  if (config?.crons === undefined) return [];
  const lines = (await ctx.snapshot.lines("vercel.json")) ?? [];
  return config.crons.map((cron) => ({
    kind: "cron" as const,
    label: `${cron.schedule} -> ${cron.path}`,
    file: "vercel.json",
    line: Math.max(1, lines.findIndex((line) => line.includes(cron.path)) + 1),
    symbol: `vercel-cron:${cron.path}`,
    attributes: {
      [ATTRIBUTE.library]: "vercel",
      [ATTRIBUTE.schedule]: cron.schedule,
      targetPath: cron.path,
      [ATTRIBUTE.path]: cron.path,
      // Filled in by the cross-reference, once the route inventory exists.
      [ATTRIBUTE.authenticated]: UNKNOWN,
    },
  }));
}

/** `serverless.yml` schedule events. */
async function cronsFromServerless(ctx: EnumerationContext): Promise<DraftUnit[]> {
  const units: DraftUnit[] = [];
  for (const file of ctx.snapshot
    .filesMatching(/(^|\/)serverless\.ya?ml$/)
    .slice(0, MAX_MANIFESTS)) {
    const parsed = await readYaml(ctx, file);
    if (parsed === null) continue;
    for (const entry of entriesOf(childOf(parsed.root, "functions"))) {
      for (const event of itemsOf(childOf(entry.value, "events"))) {
        const schedule = entryOf(event, "schedule");
        if (schedule === null) continue;
        const expression =
          scalarOf(schedule.value) ?? scalarOf(childOf(schedule.value, "rate")) ?? UNKNOWN;
        units.push({
          kind: "cron",
          label: `${expression} -> ${entry.key}`,
          file,
          line: schedule.line,
          symbol: `serverless-schedule:${entry.key}:${contentSymbol("s", expression)}`,
          attributes: {
            [ATTRIBUTE.library]: "serverless-framework",
            [ATTRIBUTE.schedule]: expression,
            targetFunction: entry.key,
            enabled: scalarOf(childOf(schedule.value, "enabled")) ?? "true",
          },
        });
      }
    }
  }
  return units;
}

/** GitHub Actions `on: schedule:` entries. */
async function cronsFromWorkflows(ctx: EnumerationContext): Promise<DraftUnit[]> {
  const units: DraftUnit[] = [];
  for (const file of workflowFiles(ctx)) {
    const parsed = await readYaml(ctx, file);
    if (parsed === null) continue;
    const schedule = childOf(entryOf(parsed.root, "on")?.value, "schedule");
    for (const item of itemsOf(schedule)) {
      const cron = entryOf(item, "cron");
      const expression = scalarOf(cron?.value);
      if (cron === null || expression === undefined) continue;
      units.push({
        kind: "cron",
        label: `${expression} -> ${basename(file)}`,
        file,
        line: cron.line,
        symbol: `workflow-schedule:${contentSymbol("s", expression)}`,
        attributes: {
          [ATTRIBUTE.library]: "github-actions",
          [ATTRIBUTE.schedule]: expression,
          targetWorkflow: file,
        },
      });
    }
  }
  return units;
}

/** Cloudflare cron triggers declared in `wrangler.toml`. */
async function cronsFromWrangler(ctx: EnumerationContext): Promise<DraftUnit[]> {
  const units: DraftUnit[] = [];
  for (const file of ctx.snapshot.filesMatching(/(^|\/)wrangler\.(toml|jsonc?)$/)) {
    const text = await ctx.snapshot.read(file);
    if (text === undefined) continue;
    const lines = toLines(text);
    const index = lines.findIndex((line) => /crons\s*[=:]/.test(line));
    if (index === -1) continue;
    const inner = firstMatch(text, /crons"?\s*[=:]\s*\[([^\]]*)\]/) ?? "";
    for (const expression of cronList(inner)) {
      units.push({
        kind: "cron",
        label: `${expression} -> cloudflare worker`,
        file,
        line: index + 1,
        symbol: `wrangler-cron:${contentSymbol("s", expression)}`,
        attributes: {
          [ATTRIBUTE.library]: "cloudflare-workers",
          [ATTRIBUTE.schedule]: expression,
        },
      });
    }
  }
  return units;
}

/** In-process schedulers found in code. */
async function cronsFromCode(
  ctx: EnumerationContext,
  matches: readonly StructuralMatch[],
): Promise<DraftUnit[]> {
  const units: DraftUnit[] = [];
  for (const match of matches) {
    const packages = CRON_PACKAGES[match.ruleId];
    if (packages === undefined) continue;
    if (!(await importsAny(ctx, match.file, packages))) continue;
    const args = match.lists.ARGS ?? [];
    const expression = literalOf(args[0]);
    if (!looksLikeSchedule(expression)) continue;
    const lines = (await ctx.snapshot.lines(match.file)) ?? [];
    const symbol = enclosingSymbol(lines, match.line);
    units.push({
      kind: "cron",
      label: `${expression} -> ${symbol ?? match.file}`,
      file: match.file,
      line: match.line,
      endLine: match.endLine,
      symbol: `code-cron:${contentSymbol("s", `${expression}:${symbol ?? ""}`)}`,
      attributes: {
        [ATTRIBUTE.library]: packages[0] ?? "in-process",
        [ATTRIBUTE.schedule]: expression,
        [ATTRIBUTE.symbol]: symbol,
        timezone: literalOf(optionOf(match.text, "timezone")) ?? "process default",
      },
    });
  }
  return units;
}

/**
 * Recurring queue jobs found in code.
 *
 * The schedule is whichever of `pattern`/`cron`/`every` the option carries, and
 * `repeatKey` is what BullMQ deduplicates a repeatable job on — the closest
 * thing this kind has to the lock the D5 overlap check asks about, so its
 * absence is spelled out rather than omitted.
 */
async function cronsFromRecurringJobs(
  ctx: EnumerationContext,
  matches: readonly StructuralMatch[],
): Promise<DraftUnit[]> {
  const units: DraftUnit[] = [];
  for (const match of matches) {
    if (match.ruleId !== RULE.repeatableJob && match.ruleId !== RULE.jobScheduler) continue;
    const text = await ctx.snapshot.read(match.file);
    if (text === undefined || !QUEUE_JOB_VOCABULARY.test(text)) continue;
    const cron =
      literalOf(optionOf(match.text, "pattern")) ?? literalOf(optionOf(match.text, "cron"));
    const every = optionOf(match.text, "every");
    const schedule = cron ?? (every === undefined ? UNKNOWN : `every ${brief(every, 60)}`);
    const lines = (await ctx.snapshot.lines(match.file)) ?? [];
    const symbol = enclosingSymbol(lines, match.line);
    units.push({
      kind: "cron",
      label: `${schedule} -> ${symbol ?? basename(match.file)}`,
      file: match.file,
      line: match.line,
      endLine: match.endLine,
      symbol: `queue-repeat:${contentSymbol("s", `${schedule}:${symbol ?? ""}`)}`,
      attributes: {
        [ATTRIBUTE.library]: "bullmq",
        [ATTRIBUTE.schedule]: schedule,
        [ATTRIBUTE.symbol]: symbol,
        repeatKey:
          literalOrExpression(
            optionOf(match.text, "key") ??
              optionOf(match.text, "repeatJobKey") ??
              optionOf(match.text, "jobId"),
          ) ?? NONE,
        timezone:
          literalOf(optionOf(match.text, "tz") ?? optionOf(match.text, "timezone")) ??
          "process default",
      },
    });
  }
  return units;
}

/**
 * Enumerates scheduled work, and — for a cron that calls an HTTP endpoint —
 * records whether the endpoint it calls checks anything.
 *
 * The cross-reference is the point of this enumerator. A `vercel.json` cron
 * that hits `GET /api/cron/rotate` is only a finding if that route is open,
 * and the only way to know is to look at the route. It joins to the route
 * inventory by path when one exists, and falls back to resolving the path
 * through the Next.js file conventions when it does not — so the check works
 * before the route enumerator lands, and gets more precise once it has.
 */
export const cronEnumerator: InventoryEnumerator = {
  name: "crons",
  kinds: ["cron"],
  async enumerate(ctx: EnumerationContext): Promise<EnumerationOutcome> {
    const found = await ctx.search.search([...CRON_RULES, ...RECURRING_JOB_RULES]);
    const notes: string[] = [];
    if (!found.ok && found.reason !== undefined) notes.push(found.reason);
    const units = [
      ...(await cronsFromVercel(ctx)),
      ...(await cronsFromServerless(ctx)),
      ...(await cronsFromWorkflows(ctx)),
      ...(await cronsFromWrangler(ctx)),
      ...(await cronsFromCode(ctx, found.matches)),
      ...(await cronsFromRecurringJobs(ctx, found.matches)),
    ];
    return finishOutcome(units, {
      notes,
      searchOk: found.ok,
      emptyReason: "no scheduled work is declared in this repository",
    });
  },

  async crossReference(
    own: readonly AuditUnit[],
    all: readonly AuditUnit[],
    ctx: EnumerationContext,
  ): Promise<AttributePatch> {
    const patches = new Map<string, Record<string, string | undefined>>();
    const routes = all.filter((unit) => unit.kind === "route");
    const byPath = new Map<string, string>();
    for (const file of ctx.snapshot.sourceFiles()) {
      const path = nextRoutePath(file);
      if (path !== undefined && !byPath.has(path)) byPath.set(path, file);
    }

    for (const cron of own) {
      const target = cron.attributes.targetPath;
      if (target === undefined) continue;
      const route = routes.find((candidate) =>
        samePath(candidate.attributes[ATTRIBUTE.path], target),
      );
      const file =
        route?.location.file ??
        byPath.get(target) ??
        [...byPath.entries()].find(([path]) => samePath(path, target))?.[1];
      if (file === undefined) {
        patches.set(cron.id, {
          [ATTRIBUTE.authenticated]: UNKNOWN,
          targetResolved: "no route found for this path",
        });
        continue;
      }
      const source = await ctx.snapshot.read(file);
      if (source === undefined) {
        patches.set(cron.id, { [ATTRIBUTE.authenticated]: UNKNOWN, targetFile: file });
        continue;
      }
      const check = cronAuthCheck(source);
      patches.set(cron.id, {
        [ATTRIBUTE.authenticated]: check === null ? "no" : "yes",
        authCheck: check ?? NONE,
        targetFile: file,
        [ATTRIBUTE.targetUnitId]: route?.id,
      });
    }
    return patches;
  },
};

// ---------------------------------------------------------------------------
// Webhook receivers
// ---------------------------------------------------------------------------

/** One provider, and what proves a receiver belongs to it. */
interface WebhookProvider {
  readonly name: string;
  /** Header names, packages or call names that identify the provider. */
  readonly markers: readonly RegExp[];
}

const WEBHOOK_PROVIDERS: readonly WebhookProvider[] = [
  { name: "stripe", markers: [/stripe-signature/i, /\bstripe\b/i] },
  { name: "github", markers: [/x-hub-signature/i, /@octokit\/webhooks/] },
  { name: "svix", markers: [/\bsvix\b/i, /svix-signature/i, /svix-id/i] },
  { name: "clerk", markers: [/@clerk\//, /clerk-signature/i] },
  { name: "supabase", markers: [/x-supabase-signature/i, /supabase.*webhook/i] },
  { name: "twilio", markers: [/x-twilio-signature/i, /\btwilio\b/i] },
  { name: "shopify", markers: [/x-shopify-hmac/i, /\bshopify\b/i] },
  { name: "slack", markers: [/x-slack-signature/i, /@slack\//] },
];

/**
 * One structural query for a provider's verification call.
 *
 * `packages` is the difference between a shape that can only be that provider
 * and a shape that can be anything. `$X.webhooks.constructEvent(...)` is
 * Stripe's and nobody else's, so it is believed wherever it appears — a
 * verification call in a helper module the handler imports is still the
 * receiver. `new Webhook(...)` is Svix's *and* every other class called
 * `Webhook`, so believing the shape alone adds a false receiver for every
 * unrelated `Webhook` class in the repository; it is believed only in a file
 * that imports one of the packages that own it.
 */
interface WebhookVerificationRule {
  readonly ruleId: string;
  readonly provider: string;
  /** Packages the file must import, when the shape alone is not conclusive. */
  readonly packages?: readonly string[] | undefined;
}

const WEBHOOK_RULES: readonly StructuralRule[] = [
  {
    id: RULE.stripeWebhook,
    rule: {
      any: [
        { pattern: "$X.webhooks.constructEvent($$$ARGS)" },
        { pattern: "$X.webhooks.constructEventAsync($$$ARGS)" },
      ],
    },
  },
  { id: RULE.svixWebhook, rule: { pattern: "new Webhook($$$ARGS)" } },
  { id: RULE.twilioWebhook, rule: { pattern: "$X.validateRequest($$$ARGS)" } },
  {
    id: RULE.octokitWebhook,
    rule: {
      any: [
        { pattern: "$X.webhooks.verify($$$ARGS)" },
        { pattern: "$X.webhooks.verifyAndReceive($$$ARGS)" },
      ],
    },
  },
];

const WEBHOOK_VERIFICATION_RULES: readonly WebhookVerificationRule[] = [
  { ruleId: RULE.stripeWebhook, provider: "stripe" },
  {
    ruleId: RULE.svixWebhook,
    provider: "svix",
    packages: ["svix", "@clerk/backend", "@clerk/nextjs"],
  },
  { ruleId: RULE.twilioWebhook, provider: "twilio", packages: ["twilio"] },
  { ruleId: RULE.octokitWebhook, provider: "github", packages: ["@octokit/webhooks", "octokit"] },
];

/** Cap on candidate files read, so a repository full of `hooks/` cannot stall the phase. */
const MAX_WEBHOOK_CANDIDATES = 400;

/**
 * Enumerates inbound webhook receivers — and only those.
 *
 * The path is a *lead*, never the classification. A receiver verifies a
 * signature over the raw body it was sent; the management endpoints that create
 * and list subscriptions, and the senders that deliver to them, do not — and a
 * `webhooks/` directory holds all three. So the classifier must not count the
 * latter two, or a coverage denominator fills with units that have no
 * third-party signature to check and each one reads as an unverified receiver.
 * See `_webhook-shape.ts` for the decision procedure; what happens here is the
 * bookkeeping around it.
 *
 * A candidate that is not a receiver does not disappear: the enumerator reports
 * how many were reclassified, into what, and with a `file:line` for each, so a
 * D5 coverage denominator can be reconciled against the number of candidates a
 * path-only filter would have offered.
 */
export const webhookEnumerator: InventoryEnumerator = {
  name: "webhooks",
  kinds: ["webhook"],
  async enumerate(ctx: EnumerationContext): Promise<EnumerationOutcome> {
    const found = await ctx.search.search(WEBHOOK_RULES);
    const notes: string[] = [];
    if (!found.ok && found.reason !== undefined) notes.push(found.reason);

    const providerCalls = new Map<string, ProviderCall>();
    const byRule = new Map(WEBHOOK_VERIFICATION_RULES.map((rule) => [rule.ruleId, rule]));
    for (const match of found.matches) {
      const rule = byRule.get(match.ruleId);
      if (rule === undefined || providerCalls.has(match.file)) continue;
      if (rule.packages !== undefined && !(await importsAny(ctx, match.file, rule.packages))) {
        continue;
      }
      providerCalls.set(match.file, {
        provider: rule.provider,
        line: match.line,
        call: brief(match.text, 80),
      });
    }

    const candidates = new Set<string>(
      ctx.snapshot.sourceFiles().filter((file) => isWebhookCandidatePath(file)),
    );
    for (const file of providerCalls.keys()) candidates.add(file);

    const ordered = [...candidates].sort((left, right) => left.localeCompare(right));
    const truncated = ordered.length > MAX_WEBHOOK_CANDIDATES;
    if (truncated) {
      notes.push(
        `${ordered.length} files sit under a webhook-shaped path; only the first ${MAX_WEBHOOK_CANDIDATES} were classified`,
      );
    }

    const classified: ClassifiedCandidate[] = [];
    const units: DraftUnit[] = [];
    let nonProduction = 0;

    for (const file of ordered.slice(0, MAX_WEBHOOK_CANDIDATES)) {
      const text = await ctx.snapshot.read(file);
      if (text === undefined) continue;
      const providerCall = providerCalls.get(file);
      // Comments and template-literal prose are blanked before anything is
      // matched: an OpenAPI description that documents the signature header in
      // prose reads as a signature-header use, which turns a schema file into a
      // receiver.
      const code = stripProse(text);
      const shape = classifyWebhookCandidate({
        file,
        text: code,
        ...(providerCall === undefined ? {} : { providerCall }),
      });
      classified.push({ file, shape });
      if (!isProductionCandidate(file)) nonProduction += 1;
      if (shape.role !== "receiver" || shape.facts === undefined) continue;

      const lines = toLines(text);
      const provider =
        providerCall?.provider ??
        WEBHOOK_PROVIDERS.find((candidate) => candidate.markers.some((marker) => marker.test(code)))
          ?.name ??
        "custom";
      const path = nextRoutePath(file);
      // The citation points at what proves it is a receiver; the symbol comes
      // from the handler boundary, because the symbol is part of the unit's id
      // and must not move when a local variable is renamed.
      const symbol = enclosingSymbol(lines, shape.boundaryLine ?? shape.line);

      units.push({
        kind: "webhook",
        label: `${provider} webhook (${path ?? file})`,
        file,
        line: shape.line,
        endLine: lines.length,
        symbol: `webhook:${provider}:${symbol ?? basename(file)}`,
        note: `classified as a receiver by ${shape.evidence}`,
        attributes: {
          provider,
          [ATTRIBUTE.path]: path,
          [ATTRIBUTE.trigger]: "http",
          [ATTRIBUTE.symbol]: symbol,
          [ATTRIBUTE.library]: providerCall === undefined ? undefined : provider,
          [ATTRIBUTE.method]: /export\s+(async\s+)?function\s+POST|\.post\s*\(|@Post\s*\(/.test(
            code,
          )
            ? "POST"
            : undefined,
          signatureVerified: shape.facts.signatureVerified,
          verification: shape.facts.verification,
          usesRawBody: shape.facts.usesRawBody,
          replayProtection: shape.facts.replayProtection,
          receiverEvidence: brief(shape.facts.receiverEvidence, 120),
        },
      });
    }

    const reclassified = reclassificationNote(classified, nonProduction);
    if (reclassified !== undefined) notes.push(reclassified);

    const outcome = finishOutcome(units, {
      notes,
      searchOk: found.ok,
      emptyReason:
        candidates.size === 0
          ? "no file in this repository sits on a webhook-shaped path"
          : "no inbound webhook receiver was found",
    });
    // A cap that was hit is always `degraded`, never `ok` and never `skipped`:
    // the units enumerated are usable, the claim "this repository has no
    // receiver" is not, because some candidates were never looked at.
    return truncated ? { ...outcome, status: "degraded" } : outcome;
  },
};

// ---------------------------------------------------------------------------
// GitHub Actions jobs
// ---------------------------------------------------------------------------

/** Every workflow file in the repository, capped and sorted. */
function workflowFiles(ctx: EnumerationContext): string[] {
  return ctx.snapshot
    .filesMatching(/(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/)
    .slice(0, MAX_MANIFESTS);
}

/** Renders a `permissions:` node the way a reader of the report needs it. */
export function renderPermissions(node: YamlNode | null): string | undefined {
  if (node === null) return undefined;
  const scalar = textOf(node);
  if (scalar !== null) return scalar;
  const entries = entriesOf(node)
    .map((entry) => `${entry.key}:${textOf(entry.value) ?? ""}`)
    .sort();
  return entries.length === 0 ? undefined : entries.join(",");
}

/** Secret names a range of lines reads. */
export function secretsUsed(lines: readonly string[], from: number, to: number): string[] {
  const names = new Set<string>();
  const pattern = /secrets\.([A-Za-z_][\w-]*)/g;
  for (let index = from - 1; index < Math.min(to, lines.length); index += 1) {
    const text = lines[index];
    if (text === undefined) continue;
    pattern.lastIndex = 0;
    let found = pattern.exec(text);
    while (found !== null) {
      if (found[1] !== undefined) names.add(found[1]);
      found = pattern.exec(text);
    }
  }
  return [...names].sort();
}

/** The events a workflow subscribes to. */
function triggersOf(root: YamlNode | null): string[] {
  const on = entryOf(root, "on")?.value ?? null;
  const scalar = textOf(on);
  if (scalar !== null) return [scalar];
  const entries = entriesOf(on);
  if (entries.length > 0) return entries.map((entry) => entry.key).sort();
  return itemsOf(on)
    .map((item) => textOf(item))
    .filter((value): value is string => value !== null)
    .sort();
}

/** Enumerates every job of every GitHub Actions workflow. */
export const workflowJobEnumerator: InventoryEnumerator = {
  name: "workflow-jobs",
  kinds: ["workflow-job"],
  async enumerate(ctx: EnumerationContext): Promise<EnumerationOutcome> {
    const files = workflowFiles(ctx);
    if (files.length === 0) {
      return notApplicable("the repository has no .github/workflows directory");
    }
    const units: DraftUnit[] = [];
    const notes: string[] = [];

    for (const file of files) {
      const text = await ctx.snapshot.read(file);
      if (text === undefined) continue;
      const parsed = parseYaml(text);
      if (parsed.errors.length > 0) notes.push(`${file}: ${parsed.errors[0]}`);
      const lines = toLines(text);
      const triggers = triggersOf(parsed.root).join(",");
      const workflowPermissions = renderPermissions(childOf(parsed.root, "permissions"));
      const concurrency = entryOf(parsed.root, "concurrency") !== null ? "yes" : "no";
      const entries = entriesOf(childOf(parsed.root, "jobs"));

      for (let index = 0; index < entries.length; index += 1) {
        const entry = entries[index];
        if (entry === undefined) continue;
        const end = entryEnd(entries, index, lines.length);
        const runsOn =
          scalarOf(childOf(entry.value, "runs-on")) ??
          itemsOf(childOf(entry.value, "runs-on"))
            .map((item) => textOf(item))
            .filter((value): value is string => value !== null)
            .join(",");
        const permissions =
          renderPermissions(childOf(entry.value, "permissions")) ??
          workflowPermissions ??
          "not declared";
        const secrets = secretsUsed(lines, entry.line, end);

        units.push({
          kind: "workflow-job",
          label: `${basename(file)}#${entry.key}`,
          file,
          line: entry.line,
          endLine: end,
          symbol: `job:${entry.key}`,
          attributes: {
            job: entry.key,
            workflow: scalarOf(childOf(parsed.root, "name")) ?? basename(file),
            triggers: triggers === "" ? UNKNOWN : triggers,
            permissions,
            usesSecrets: secrets.length === 0 ? NONE : secrets.join(","),
            runsOn: runsOn === "" ? UNKNOWN : runsOn,
            selfHosted: /self-hosted/.test(runsOn) ? "yes" : "no",
            environment: scalarOf(childOf(entry.value, "environment")),
            usesWorkflow: scalarOf(childOf(entry.value, "uses")),
            concurrency,
            condition: scalarOf(childOf(entry.value, "if")),
          },
        });
      }
    }

    return finishOutcome(units, {
      notes,
      searchOk: true,
      emptyReason: "the workflows declare no jobs",
    });
  },
};

/** Every D5 enumerator, in the order the aggregator registers them. */
export const ASYNC_UNIT_ENUMERATORS: readonly InventoryEnumerator[] = [
  serverlessFunctionEnumerator,
  queueConsumerEnumerator,
  cronEnumerator,
  webhookEnumerator,
  workflowJobEnumerator,
];
