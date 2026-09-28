import type { CodeRef } from "../contracts/findings.ts";
import type { DetectedFact, FactKind } from "../contracts/profile.ts";
import { composeFiles } from "./detect-data-layer.ts";
import type { DetectionContext } from "./detector.ts";
import { type DetectionResult, type Probe, ref } from "./fact-builder.ts";
import type { RepoSnapshot } from "./repo-snapshot.ts";
import { lineOf } from "./text.ts";

/** CI systems, each recognised by the file it is configured in. */
const CI_FILES: ReadonlyArray<{ readonly pattern: RegExp; readonly value: string }> = [
  { pattern: /^\.github\/workflows\/[^/]+\.ya?ml$/, value: "github-actions" },
  { pattern: /^\.gitlab-ci\.ya?ml$/, value: "gitlab-ci" },
  { pattern: /^\.circleci\/config\.ya?ml$/, value: "circleci" },
  { pattern: /(^|\/)Jenkinsfile$/, value: "jenkins" },
  { pattern: /^azure-pipelines\.ya?ml$/, value: "azure-pipelines" },
  { pattern: /^bitbucket-pipelines\.ya?ml$/, value: "bitbucket-pipelines" },
  { pattern: /^\.travis\.ya?ml$/, value: "travis-ci" },
  { pattern: /^\.drone\.ya?ml$/, value: "drone-ci" },
];

const MAX_EVIDENCE_FILES = 20;
const MAX_YAML_FILES_INSPECTED = 200;

function fileGroupFact(
  kind: FactKind,
  value: string,
  files: readonly string[],
  detail?: string,
): DetectedFact | undefined {
  const evidence: CodeRef[] = files.slice(0, MAX_EVIDENCE_FILES).map((file) => ref(file, 1));
  if (evidence.length === 0) return undefined;
  return {
    kind,
    value,
    confidence: "high",
    detail: detail ?? `${files.length} file(s)`,
    evidence,
  };
}

/**
 * Kubernetes manifests, identified by content.
 *
 * A YAML file under `k8s/` is a guess; a YAML document with both `apiVersion:`
 * and `kind:` at the top level is a Kubernetes object.
 */
async function detectKubernetes(snapshot: RepoSnapshot): Promise<DetectedFact[]> {
  const candidates = snapshot
    .filesMatching(/\.ya?ml$/)
    .filter((file) => !file.startsWith(".github/"))
    .filter((file) => !/(^|\/)(docker-)?compose([.-][\w.-]+)?\.ya?ml$/.test(file))
    .slice(0, MAX_YAML_FILES_INSPECTED);
  const manifests: string[] = [];
  const charts: string[] = [];
  for (const file of candidates) {
    const lines = await snapshot.lines(file);
    if (lines === undefined) continue;
    if (/(^|\/)Chart\.ya?ml$/.test(file) && lineOf(lines, /^\s*name\s*:/) !== undefined) {
      charts.push(file);
      continue;
    }
    if (lineOf(lines, /^apiVersion\s*:/) === undefined) continue;
    if (lineOf(lines, /^kind\s*:/) === undefined) continue;
    manifests.push(file);
  }
  const facts: DetectedFact[] = [];
  const kubernetes = fileGroupFact("iac", "kubernetes", manifests);
  if (kubernetes !== undefined) facts.push(kubernetes);
  const helm = fileGroupFact("iac", "helm", charts, `${charts.length} chart(s)`);
  if (helm !== undefined) facts.push(helm);
  return facts;
}

/** Detects Dockerfiles, compose files, CI configuration and infrastructure-as-code. */
export async function detectDelivery(context: DetectionContext): Promise<DetectionResult> {
  const { snapshot } = context;
  const facts: DetectedFact[] = [];

  const dockerfiles = snapshot.filesMatching(/(^|\/)Dockerfile(\.[\w.-]+)?$/);
  // Whether a `.dockerignore` exists is a delivery *finding*, not a stack fact,
  // so it rides along as detail rather than inventing a container "type".
  const ignoreNote = snapshot.has(".dockerignore") ? "with .dockerignore" : "no .dockerignore";
  const dockerfileFact = fileGroupFact(
    "container",
    "dockerfile",
    dockerfiles,
    `${dockerfiles.length} file(s), ${ignoreNote}`,
  );
  if (dockerfileFact !== undefined) facts.push(dockerfileFact);

  const compose = composeFiles(snapshot);
  const composeFact = fileGroupFact("container", "docker-compose", compose);
  if (composeFact !== undefined) facts.push(composeFact);

  for (const candidate of CI_FILES) {
    const files = snapshot.filesMatching(candidate.pattern);
    const ciFact = fileGroupFact("ci", candidate.value, files);
    if (ciFact !== undefined) facts.push(ciFact);
  }

  const terraform = snapshot.filesMatching(/\.tf$/);
  const terraformFact = fileGroupFact("iac", "terraform", terraform);
  if (terraformFact !== undefined) facts.push(terraformFact);

  const pulumi = snapshot.filesMatching(/(^|\/)Pulumi\.ya?ml$/);
  const pulumiFact = fileGroupFact("iac", "pulumi", pulumi);
  if (pulumiFact !== undefined) facts.push(pulumiFact);

  facts.push(...(await detectKubernetes(snapshot)));

  const probes: Probe[] = [
    { kind: "container", searched: ["Dockerfile*", "docker-compose*.yml", "compose*.yml"] },
    { kind: "ci", searched: CI_FILES.map((candidate) => candidate.value) },
    {
      kind: "iac",
      searched: ["*.tf", "Chart.yaml", "Pulumi.yaml", "*.yaml with apiVersion + kind"],
      note: "No infrastructure-as-code: `trivy config` has nothing to scan beyond containers.",
    },
  ];

  return { facts, probes, warnings: [] };
}
