import type { DetectedFact } from "../contracts/profile.ts";
import { envFiles } from "./detect-data-layer.ts";
import type { DetectionContext } from "./detector.ts";
import { type DetectionResult, type Probe, ref } from "./fact-builder.ts";
import { type DependencySignal, factsFromDependencies, signalLabels } from "./manifest.ts";
import type { RepoSnapshot } from "./repo-snapshot.ts";
import { importPattern } from "./text.ts";

/**
 * A dotenv assignment.
 *
 * Only the capture group ever leaves this module: phase 0 records which
 * environment variables exist, never what they are set to. A profile artifact
 * that leaked a value would make the dossier itself a secret-bearing file.
 */
const ENV_ASSIGNMENT = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/;

/** Any read of the environment object, however the individual keys are reached. */
const ENV_OBJECT = /\b(?:process|Bun)\.env\b/;

/** `process.env.FOO`, `process.env["FOO"]` and the Bun equivalent. */
const ENV_ACCESS =
  /\b(?:process|Bun)\.env(?:\.([A-Za-z_][A-Za-z0-9_]*)|\[\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\])/;

/** Libraries whose whole job is validating the environment at startup. */
export const CONFIG_VALIDATION_SIGNALS: readonly DependencySignal[] = [
  { value: "envalid", packages: ["envalid"] },
  { value: "t3-env", packages: ["@t3-oss/env-core", "@t3-oss/env-nextjs"] },
  { value: "znv", packages: ["znv"] },
  { value: "env-schema", packages: ["env-schema"] },
  { value: "convict", packages: ["convict"] },
];

const MAX_ENV_VARS = 300;

function isIgnoredByGit(gitignore: readonly string[], file: string): boolean {
  const base = file.includes("/") ? file.slice(file.lastIndexOf("/") + 1) : file;
  return gitignore.some((raw) => {
    const line = raw.trim();
    if (line.length === 0 || line.startsWith("#")) return false;
    const entry = line.replace(/^\//, "").replace(/\/$/, "");
    if (entry === base || entry === file) return true;
    return entry.endsWith("*") && base.startsWith(entry.slice(0, -1));
  });
}

async function detectEnvSurface(snapshot: RepoSnapshot): Promise<DetectedFact[]> {
  const facts: DetectedFact[] = [];
  const gitignore = (await snapshot.lines(".gitignore")) ?? [];
  const seen = new Set<string>();

  for (const file of envFiles(snapshot)) {
    const lines = await snapshot.lines(file);
    if (lines === undefined) continue;
    const keys: Array<{ name: string; line: number }> = [];
    for (let i = 0; i < lines.length; i += 1) {
      const text = lines[i];
      if (text === undefined) continue;
      const name = ENV_ASSIGNMENT.exec(text)?.[1];
      if (name === undefined) continue;
      keys.push({ name, line: i + 1 });
    }
    const ignored = isIgnoredByGit(gitignore, file);
    facts.push({
      kind: "env-file",
      value: file,
      confidence: "high",
      detail: `${keys.length} key(s); ${ignored ? "matched by .gitignore" : "not matched by .gitignore"}`,
      evidence: [ref(file, 1)],
    });
    for (const key of keys) {
      if (seen.size >= MAX_ENV_VARS && !seen.has(key.name)) continue;
      seen.add(key.name);
      facts.push({
        kind: "env-var",
        value: key.name,
        confidence: "high",
        evidence: [ref(file, key.line, "declared")],
      });
    }
  }

  const accesses = await snapshot.grep(ENV_ACCESS, { limit: 600 });
  for (const hit of accesses) {
    const match = ENV_ACCESS.exec(hit.text);
    const name = match?.[1] ?? match?.[2];
    if (name === undefined) continue;
    if (seen.size >= MAX_ENV_VARS && !seen.has(name)) continue;
    seen.add(name);
    facts.push({
      kind: "env-var",
      value: name,
      confidence: "high",
      evidence: [ref(hit.file, hit.line, "read")],
    });
  }

  return facts;
}

/**
 * Schema validation of the environment, which is what turns a missing variable
 * into a startup failure instead of an `undefined` two layers down.
 */
async function detectZodEnvValidation(snapshot: RepoSnapshot): Promise<DetectedFact[]> {
  const zodFiles = new Set(
    (await snapshot.grep(importPattern("zod"), { limit: 300 })).map((hit) => hit.file),
  );
  if (zodFiles.size === 0) return [];
  const candidates = [...zodFiles].sort();
  // `EnvSchema.parse(process.env)` never names a key, so the broader pattern is
  // the right gate here — the named-key pattern is for the inventory of vars.
  const envUsers = new Set(
    (await snapshot.grep(ENV_OBJECT, { files: candidates, limit: 300 })).map((hit) => hit.file),
  );
  const parseHits = await snapshot.grep(/\.(safeParse|parse)\s*\(/, {
    files: [...envUsers].sort(),
    limit: 100,
  });
  const first = parseHits[0];
  if (first === undefined) return [];
  return [
    {
      kind: "config-validation",
      value: "zod",
      confidence: "high",
      detail: `${new Set(parseHits.map((hit) => hit.file)).size} file(s) parse process.env with a zod schema`,
      evidence: parseHits.slice(0, 5).map((hit) => ref(hit.file, hit.line)),
    },
  ];
}

/** Detects the configuration surface: env files, env var names (never values) and validation. */
export async function detectConfig(context: DetectionContext): Promise<DetectionResult> {
  const { manifests, snapshot } = context;
  const facts: DetectedFact[] = [
    ...(await detectEnvSurface(snapshot)),
    ...factsFromDependencies(manifests, "config-validation", CONFIG_VALIDATION_SIGNALS),
    ...(await detectZodEnvValidation(snapshot)),
  ];

  const warnings: string[] = [];
  const committedEnv = facts.filter(
    (detected) =>
      detected.kind === "env-file" &&
      /(^|\/)\.env$/.test(detected.value) &&
      detected.detail?.includes("not matched by .gitignore") === true,
  );
  for (const file of committedEnv) {
    warnings.push(
      `${file.value} is present and not matched by .gitignore; the delivery phase should treat it as a committed secret file.`,
    );
  }

  const probes: Probe[] = [
    { kind: "env-file", searched: [".env", ".env.example", ".env.*"] },
    { kind: "env-var", searched: [".env* assignments", "process.env.*", "Bun.env.*"] },
    {
      kind: "config-validation",
      searched: [...signalLabels(CONFIG_VALIDATION_SIGNALS), "zod schema over process.env"],
      note: "Environment variables are read without a validating schema; a missing or malformed one fails at use, not at startup.",
    },
  ];

  return { facts, probes, warnings };
}
