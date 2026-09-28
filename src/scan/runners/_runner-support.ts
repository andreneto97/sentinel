/**
 * Shared plumbing for the three dependency/dead-code runners.
 *
 * It holds what `knip`, `dependency-cruiser` and `package-manager` would
 * otherwise repeat three times: the port slices they take, the finding builder
 * with its stable id, raw-artifact writing, and the citation verification that
 * gives every finding a snippet read from disk rather than from tool output.
 */

import { join } from "node:path";
import type { CodeRef, Confidence, Domain, Finding, Severity } from "../../contracts/findings.ts";
import type { StackProfile } from "../../contracts/profile.ts";
import { type VerifyFileSystem, verifyFindings } from "../../verify/index.ts";
import type { StepOutcome, StepStatus } from "../types.ts";

/** The filesystem operations these runners need; the real port satisfies it structurally. */
export interface RunnerFileSystem {
  readFile(path: string): Promise<string>;
  readFileBytes(path: string): Promise<Uint8Array>;
  writeFile(path: string, data: string | Uint8Array): Promise<void>;
  mkdirp(path: string): Promise<void>;
  exists(path: string): Promise<boolean>;
  realpath(path: string): Promise<string>;
}

/** The fields of a spawned command these runners read. */
export interface RunnerProcessResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly timedOut: boolean;
  readonly truncated: boolean;
  readonly notFound: boolean;
}

/** The spawn options these runners set; a subset of `ProcessRunOptions`. */
export interface RunnerProcessOptions {
  readonly cwd?: string;
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly timeoutMs?: number;
  readonly maxOutputBytes?: number;
}

/** The slice of `src/ports/process-executor.ts` these runners depend on. */
export interface RunnerProcessExecutor {
  run(
    command: string,
    args?: readonly string[],
    options?: RunnerProcessOptions,
  ): Promise<RunnerProcessResult>;
}

/** The slice of `src/tools/resolve.ts#ToolResolver` these runners depend on. */
export interface RunnerToolResolver {
  resolve(name: string, options?: { allowPath?: boolean }): Promise<string | null>;
}

/**
 * Everything a runner is handed. The field names match the phase 1 runner
 * context, so the orchestrator can pass its own context object straight in.
 */
export interface RunnerContext {
  readonly fs: RunnerFileSystem;
  readonly exec: RunnerProcessExecutor;
  readonly tools: RunnerToolResolver;
  /** Absolute path of the repository under analysis. Never written to. */
  readonly targetDir: string;
  /** Absolute path of this run's output directory; raw output lands under it. */
  readonly runDir: string;
  /** Phase 0 output, used to decide what is worth running and what cannot apply. */
  readonly profile?: StackProfile | undefined;
  /** Allow a tool found on PATH when the pinned build is not cached. Default false. */
  readonly allowPathTools?: boolean | undefined;
  /** Wall-clock budget for a single command; each runner has its own default. */
  readonly timeoutMs?: number | undefined;
  /** Air-gapped run: registry-backed checks degrade instead of reaching out. */
  readonly offline?: boolean | undefined;
}

/** Writes a tool's untouched output under `<runDir>/raw/<step>/`; returns its path. */
export async function writeRaw(
  ctx: RunnerContext,
  step: string,
  fileName: string,
  content: string,
): Promise<string> {
  const path = join(ctx.runDir, "raw", step, fileName);
  await ctx.fs.writeFile(path, content);
  return path;
}

/** Builds the outcome, keeping `reason` off the object entirely when there is none. */
export function outcome(
  step: string,
  status: StepStatus,
  reason: string | undefined,
  findings: readonly Finding[],
  artifacts: readonly string[],
  startedAt: number,
): StepOutcome {
  return {
    step,
    status,
    ...(reason === undefined ? {} : { reason }),
    findings,
    artifacts: [...artifacts],
    durationMs: Math.max(0, Math.round(performance.now() - startedAt)),
  };
}

/** A step that could not apply, with the reason it could not. */
export function skipped(step: string, startedAt: number, reason: string): StepOutcome {
  return outcome(step, "skipped", reason, [], [], startedAt);
}

/** A step whose output Sentinel refuses to trust. */
export function failedStep(
  step: string,
  startedAt: number,
  reason: string,
  artifacts: readonly string[] = [],
): StepOutcome {
  return outcome(step, "failed", reason, [], artifacts, startedAt);
}

/**
 * Joins several notes into one `reason` sentence, dropping the empty ones.
 *
 * Kept byte-for-byte in step with `src/inventory/_unit-support.ts`, which offers
 * the same helper to the enumerators: the two support modules are private to
 * their own subsystem and neither may import the other, but a `reason` sentence
 * that is assembled differently in phase 1 and phase 2 is a difference a reader
 * of the report would have to explain.
 */
export function joinReasons(parts: ReadonlyArray<string | null | undefined>): string | undefined {
  const kept = parts.filter(
    (part): part is string => part !== null && part !== undefined && part.trim() !== "",
  );
  return kept.length === 0 ? undefined : kept.join("; ");
}

/**
 * Separator for the hashed identity of a finding. ASCII 31 (unit separator)
 * cannot occur in a domain, a rule id, a path or a symbol name, so no two
 * different identities can hash to the same string.
 */
const ID_SEPARATOR = String.fromCharCode(31);

/** Stable across runs and machines: a short hash of what identifies a finding. */
export function findingId(domain: Domain, rule: string, file: string, symbol: string): string {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update([domain, rule, file, symbol].join(ID_SEPARATOR));
  return hasher.digest("hex").slice(0, 16);
}

/**
 * A symbol for a finding that has no named subject — a `RUN` line, a compose
 * key — derived from what the offending text *says* rather than where it sits.
 * A line number in a symbol makes the finding id change whenever anything
 * above it is edited, which breaks diffing runs across commits for no reason.
 */
export function contentSymbol(prefix: string, text: string): string {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(text.replace(/\s+/g, " ").trim());
  return `${prefix}:${hasher.digest("hex").slice(0, 12)}`;
}

/** The fields a runner supplies to build a finding; the id is derived from them. */
export interface FindingInput {
  readonly domain: Domain;
  readonly rule: string;
  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly title: string;
  readonly description: string;
  readonly impact: string;
  readonly recommendation: string;
  readonly file: string;
  readonly line: number;
  readonly endLine?: number | undefined;
  /** What the finding is about (export name, package, cycle key) — part of the id. */
  readonly symbol?: string | undefined;
  readonly evidence?: readonly CodeRef[] | undefined;
  readonly acceptanceCriteria?: readonly string[] | undefined;
  readonly exploitability?: string | undefined;
  readonly cwe?: readonly string[] | undefined;
  readonly owasp?: readonly string[] | undefined;
  readonly source: { readonly kind: "tool" | "rule" | "agent"; readonly name: string };
}

/**
 * Builds a finding with a stable id and no snippet — the snippet is filled in
 * by {@link verifyStepFindings}, which reads it from disk.
 */
export function makeFinding(input: FindingInput): Finding {
  const symbol = input.symbol ?? "";
  return {
    id: findingId(input.domain, input.rule, input.file, symbol),
    domain: input.domain,
    rule: input.rule,
    severity: input.severity,
    confidence: input.confidence,
    title: input.title,
    description: input.description,
    location: {
      file: input.file,
      line: input.line,
      ...(input.endLine === undefined ? {} : { endLine: input.endLine }),
    },
    evidence: [...(input.evidence ?? [])],
    ...(input.exploitability === undefined ? {} : { exploitability: input.exploitability }),
    impact: input.impact,
    recommendation: input.recommendation,
    acceptanceCriteria: [...(input.acceptanceCriteria ?? [])],
    cwe: [...(input.cwe ?? [])],
    owasp: [...(input.owasp ?? [])],
    source: { kind: input.source.kind, name: input.source.name },
  };
}

/** Adapts the filesystem port to the narrower seam the citation verifier takes. */
function verifyFileSystem(fs: RunnerFileSystem): VerifyFileSystem {
  return {
    readBytes: (path: string) => fs.readFileBytes(path),
    realpath: (path: string) => fs.realpath(path),
  };
}

/** What survived citation verification, and how much did not. */
export interface VerifiedStepFindings {
  readonly kept: Finding[];
  readonly droppedFindings: number;
}

/**
 * Proves every finding's citation against disk and replaces its snippet with
 * one Sentinel extracted itself; anything that does not resolve is dropped.
 */
export async function verifyStepFindings(
  findings: readonly Finding[],
  ctx: RunnerContext,
): Promise<VerifiedStepFindings> {
  const result = await verifyFindings(findings, {
    fs: verifyFileSystem(ctx.fs),
    targetDir: ctx.targetDir,
  });
  return { kept: result.kept, droppedFindings: result.droppedFindings };
}

/** Trims a tool's stderr to something a single report line can hold. */
export function briefly(text: string, limit = 300): string {
  const collapsed = text.replace(/\s+/g, " ").trim();
  return collapsed.length <= limit ? collapsed : `${collapsed.slice(0, limit - 1)}...`;
}
