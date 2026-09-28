import { z } from "zod";
import type { DetectedFact } from "../contracts/profile.ts";
import type { DetectionContext } from "./detector.ts";
import { type DetectionResult, type Probe, ref } from "./fact-builder.ts";
import { type DependencySignal, factsFromDependencies, signalLabels } from "./manifest.ts";
import type { RepoSnapshot } from "./repo-snapshot.ts";
import { lineOf } from "./text.ts";

/** Queue and background-job libraries, proven by a declared dependency. */
export const QUEUE_SIGNALS: readonly DependencySignal[] = [
  { value: "bullmq", packages: ["bullmq"] },
  { value: "bull", packages: ["bull"] },
  { value: "bee-queue", packages: ["bee-queue"] },
  { value: "sqs", packages: ["@aws-sdk/client-sqs", "sqs-consumer"] },
  { value: "inngest", packages: ["inngest"] },
  { value: "trigger.dev", prefixes: ["@trigger.dev/"] },
  { value: "pg-boss", packages: ["pg-boss"] },
  { value: "graphile-worker", packages: ["graphile-worker"] },
  { value: "agenda", packages: ["agenda", "@hokify/agenda"] },
  { value: "kafkajs", packages: ["kafkajs"] },
  { value: "amqplib", packages: ["amqplib"] },
  { value: "qstash", packages: ["@upstash/qstash"] },
  { value: "cloud-tasks", packages: ["@google-cloud/tasks"] },
];

/** In-process schedulers, proven by a declared dependency. */
export const SCHEDULER_SIGNALS: readonly DependencySignal[] = [
  { value: "node-cron", packages: ["node-cron"] },
  { value: "cron", packages: ["cron"] },
  { value: "croner", packages: ["croner"] },
  { value: "node-schedule", packages: ["node-schedule"] },
  { value: "nestjs-schedule", packages: ["@nestjs/schedule"] },
  { value: "toad-scheduler", packages: ["toad-scheduler"] },
];

const VercelConfigSchema = z.object({
  crons: z.array(z.object({ path: z.string(), schedule: z.string() })).optional(),
});

const FirebaseConfigSchema = z.object({
  functions: z.unknown().optional(),
});

async function detectPlatforms(snapshot: RepoSnapshot): Promise<DetectedFact[]> {
  const facts: DetectedFact[] = [];

  for (const file of snapshot.filesMatching(/(^|\/)serverless\.(ya?ml|ts|js)$/).slice(0, 5)) {
    facts.push({
      kind: "serverless-platform",
      value: "serverless-framework",
      confidence: "high",
      evidence: [ref(file, 1)],
    });
    facts.push({
      kind: "serverless-manifest",
      value: file,
      confidence: "high",
      detail: "serverless framework",
      evidence: [ref(file, 1)],
    });
  }

  // A file called `template.yaml` proves nothing on its own; the SAM transform
  // inside it does.
  const templates = snapshot.filesMatching(/(^|\/)template\.ya?ml$/);
  for (const file of templates.slice(0, 5)) {
    const lines = await snapshot.lines(file);
    if (lines === undefined) continue;
    const line = lineOf(lines, /AWS::Serverless/);
    if (line === undefined) continue;
    facts.push({
      kind: "serverless-platform",
      value: "aws-sam",
      confidence: "high",
      evidence: [ref(file, line, "AWS::Serverless transform")],
    });
    facts.push({
      kind: "serverless-manifest",
      value: file,
      confidence: "high",
      detail: "AWS SAM template",
      evidence: [ref(file, line)],
    });
  }

  if (snapshot.has("cdk.json")) {
    facts.push({
      kind: "serverless-platform",
      value: "aws-cdk",
      confidence: "high",
      evidence: [ref("cdk.json", 1)],
    });
    facts.push({
      kind: "serverless-manifest",
      value: "cdk.json",
      confidence: "high",
      detail: "AWS CDK app",
      evidence: [ref("cdk.json", 1)],
    });
  }

  const terraformLambdas = await snapshot.grep(/resource\s+"aws_lambda_function"/, {
    files: snapshot.filesMatching(/\.tf$/),
    limit: 20,
  });
  for (const hit of terraformLambdas.slice(0, 5)) {
    facts.push({
      kind: "serverless-platform",
      value: "aws-lambda",
      confidence: "high",
      detail: "declared in Terraform",
      evidence: [ref(hit.file, hit.line)],
    });
  }

  if (snapshot.has("vercel.json")) {
    facts.push({
      kind: "serverless-platform",
      value: "vercel",
      confidence: "high",
      evidence: [ref("vercel.json", 1)],
    });
    facts.push({
      kind: "serverless-manifest",
      value: "vercel.json",
      confidence: "high",
      detail: "Vercel project configuration",
      evidence: [ref("vercel.json", 1)],
    });
  }

  for (const file of snapshot.filesMatching(/(^|\/)wrangler\.(toml|jsonc?)$/).slice(0, 5)) {
    facts.push({
      kind: "serverless-platform",
      value: "cloudflare-workers",
      confidence: "high",
      evidence: [ref(file, 1)],
    });
    facts.push({
      kind: "serverless-manifest",
      value: file,
      confidence: "high",
      detail: "Cloudflare Workers configuration",
      evidence: [ref(file, 1)],
    });
  }

  const supabaseFunctions = snapshot.filesMatching(/^supabase\/functions\/[^/]+\/index\.(ts|js)$/);
  const firstSupabase = supabaseFunctions[0];
  if (firstSupabase !== undefined) {
    facts.push({
      kind: "serverless-platform",
      value: "supabase-functions",
      confidence: "high",
      detail: `${supabaseFunctions.length} edge function(s)`,
      evidence: supabaseFunctions.slice(0, 10).map((file) => ref(file, 1)),
    });
  }

  if (snapshot.has("firebase.json")) {
    const raw = await snapshot.read("firebase.json");
    let hasFunctions = false;
    if (raw !== undefined) {
      try {
        hasFunctions = FirebaseConfigSchema.parse(JSON.parse(raw)).functions !== undefined;
      } catch {
        hasFunctions = false;
      }
    }
    if (hasFunctions) {
      facts.push({
        kind: "serverless-platform",
        value: "firebase-functions",
        confidence: "high",
        evidence: [ref("firebase.json", 1, "functions block")],
      });
    }
  }

  if (snapshot.has("netlify.toml") || snapshot.filesMatching(/^netlify\/functions\//).length > 0) {
    const file = snapshot.has("netlify.toml")
      ? "netlify.toml"
      : (snapshot.filesMatching(/^netlify\/functions\//)[0] ?? "netlify.toml");
    facts.push({
      kind: "serverless-platform",
      value: "netlify",
      confidence: "high",
      evidence: [ref(file, 1)],
    });
  }

  return facts;
}

/**
 * Scheduled work, wherever it is declared.
 *
 * `value` is the target when the declaration names one (a Vercel cron path),
 * and the schedule expression otherwise; `detail` always carries both.
 */
async function detectSchedules(snapshot: RepoSnapshot): Promise<DetectedFact[]> {
  const facts: DetectedFact[] = [];

  const vercelRaw = await snapshot.read("vercel.json");
  if (vercelRaw !== undefined) {
    const lines = await snapshot.lines("vercel.json");
    try {
      const config = VercelConfigSchema.parse(JSON.parse(vercelRaw));
      for (const cron of config.crons ?? []) {
        facts.push({
          kind: "scheduled-job",
          value: cron.path,
          confidence: "high",
          detail: `vercel cron ${cron.schedule}`,
          evidence: [ref("vercel.json", lineOf(lines ?? [], cron.path) ?? 1)],
        });
      }
    } catch {
      // A malformed vercel.json is reported by the config detector, not here.
    }
  }

  const serverlessFiles = snapshot.filesMatching(/(^|\/)serverless\.ya?ml$/);
  const serverlessHits = await snapshot.grep(/(?:^|\s)-?\s*schedule:\s*(\S.*)$/, {
    files: serverlessFiles,
    limit: 40,
  });
  for (const hit of serverlessHits) {
    const expression = /schedule:\s*(\S.*)$/.exec(hit.text)?.[1]?.trim();
    if (expression === undefined || expression.length === 0) continue;
    facts.push({
      kind: "scheduled-job",
      value: expression.replace(/^['"]|['"]$/g, ""),
      confidence: "high",
      detail: `serverless schedule in ${hit.file}`,
      evidence: [ref(hit.file, hit.line)],
    });
  }

  const workflows = snapshot.filesMatching(/^\.github\/workflows\/.+\.ya?ml$/);
  const workflowHits = await snapshot.grep(/^\s*-?\s*cron:\s*['"]?([^'"#]+)/, {
    files: workflows,
    limit: 40,
  });
  for (const hit of workflowHits) {
    const expression = /cron:\s*['"]?([^'"#]+)/.exec(hit.text)?.[1]?.trim();
    if (expression === undefined || expression.length === 0) continue;
    facts.push({
      kind: "scheduled-job",
      value: expression,
      confidence: "high",
      detail: `GitHub Actions schedule in ${hit.file}`,
      evidence: [ref(hit.file, hit.line)],
    });
  }

  const wranglerHits = await snapshot.grep(/crons\s*=\s*\[([^\]]*)\]/, {
    files: snapshot.filesMatching(/(^|\/)wrangler\.toml$/),
    limit: 10,
  });
  for (const hit of wranglerHits) {
    const inner = /crons\s*=\s*\[([^\]]*)\]/.exec(hit.text)?.[1] ?? "";
    for (const expression of inner.split(",")) {
      const cleaned = expression.trim().replace(/^['"]|['"]$/g, "");
      if (cleaned.length === 0) continue;
      facts.push({
        kind: "scheduled-job",
        value: cleaned,
        confidence: "high",
        detail: `Cloudflare cron trigger in ${hit.file}`,
        evidence: [ref(hit.file, hit.line)],
      });
    }
  }

  const cronCalls = await snapshot.grep(
    /\b(?:cron|scheduler|schedule)\s*\.\s*(?:schedule|scheduleJob)\s*\(\s*['"]([^'"]+)['"]/,
    { limit: 40 },
  );
  for (const hit of cronCalls) {
    const expression = /\(\s*['"]([^'"]+)['"]/.exec(hit.text)?.[1];
    if (expression === undefined) continue;
    facts.push({
      kind: "scheduled-job",
      value: expression,
      confidence: "high",
      detail: `in-process schedule in ${hit.file}`,
      evidence: [ref(hit.file, hit.line)],
    });
  }

  return facts;
}

/** Detects serverless platforms, their manifests, queue libraries and scheduled work. */
export async function detectServerless(context: DetectionContext): Promise<DetectionResult> {
  const { manifests, snapshot } = context;
  const facts: DetectedFact[] = [
    ...(await detectPlatforms(snapshot)),
    ...factsFromDependencies(manifests, "queue", QUEUE_SIGNALS),
    ...factsFromDependencies(manifests, "scheduler", SCHEDULER_SIGNALS),
    ...(await detectSchedules(snapshot)),
  ];

  const probes: Probe[] = [
    {
      kind: "serverless-platform",
      searched: [
        "serverless.yml",
        "template.yaml (AWS::Serverless)",
        "cdk.json",
        "vercel.json",
        "wrangler.toml",
        "supabase/functions/*/index.ts",
        "firebase.json#functions",
        "netlify.toml",
        "*.tf aws_lambda_function",
      ],
    },
    { kind: "queue", searched: signalLabels(QUEUE_SIGNALS) },
    { kind: "scheduler", searched: signalLabels(SCHEDULER_SIGNALS) },
    {
      kind: "scheduled-job",
      searched: [
        "vercel.json#crons",
        "serverless.yml schedule:",
        ".github/workflows cron:",
        "wrangler.toml crons",
        "cron.schedule()",
      ],
    },
  ];

  return { facts, probes, warnings: [] };
}
