/**
 * Sentinel's own container rules — the Dockerfile and docker-compose checks
 * that decide what an image can do at runtime, rather than how tidy it is.
 *
 * The Dockerfile side parses the instructions itself (line-oriented, with
 * continuations folded) so it can reason about stages: "no USER" is only a
 * finding in the stage that actually ships. The compose side reads the file
 * through `_mini-yaml.ts`. Both anchor on the exact line.
 *
 * ## What the artifact is for decides what its defects are worth
 *
 * These rules fire on every Dockerfile and compose file in the tree, and a
 * repository normally keeps its developer-local ones — an emulator image, the
 * compose files behind a `make up` target — beside the ones a deploy pushes.
 * Graded flat, the pack inverts itself: `runs-as-root` is loud on the emulator
 * that only ever runs on a laptop and silent on the image that reaches the
 * cluster, because that one already sets `USER`, and a docker-socket mount in a
 * file whose own header says `Use with: docker-compose -f … -f …` reads as a
 * `critical` container escape.
 *
 * So both sides start by classifying the artifact, from **its own contents**
 * rather than from its path:
 *
 * - {@link classifyDockerfileRole} reads the base image and the build arguments.
 *   An image built `FROM localstack/localstack`, or one whose build args map the
 *   host's uid and gid so a bind mount stays writable, is developer tooling; it
 *   is not the artifact a deploy pushes to a registry.
 * - {@link classifyCompose} reads the header comments, the service images, the
 *   uid mapping and the bind mounts. A compose file that mounts the repository
 *   root into a service is serving code from the developer's disk, which no
 *   deployment does.
 *
 * The classification **caps** severity and says which signals it used; it never
 * removes a finding. Where a rule genuinely does not apply — a single-stage
 * build in an image that compiles nothing — the decision is returned as a
 * {@link SuppressionNote} and the runner counts it in the step's `reason`.
 *
 * The two questions a reader of the old output could not answer are now separate
 * facts in the finding: whether the docker socket is mounted *at all* (always
 * the strongest host-mount finding) and whether the service that mounts it is
 * the local emulator that documents needing it.
 */

import { dirname, join } from "node:path";
import type { Finding, Severity } from "../../contracts/findings.ts";
import type { StackProfile } from "../../contracts/profile.ts";
import { factsOf, valuesOf } from "../../profile/accessors.ts";
import { composeFilesOf, dockerfilesOf } from "../_delivery-files.ts";
import {
  type FindingInput,
  type RunnerContext,
  contentSymbol,
  joinReasons,
  makeFinding,
  outcome,
  skipped,
  verifyStepFindings,
} from "../runners/_runner-support.ts";
import type { StepOutcome } from "../types.ts";
import {
  type YamlNode,
  childOf,
  entriesOf,
  entryOf,
  isTrue,
  itemsOf,
  parseYaml,
  textOf,
} from "./_mini-yaml.ts";
// The withheld-finding shape and its one-line summary live in `ci.ts`, which
// needed them first. Both delivery rule packs have to account for a finding they
// declined to emit in exactly the same way, and a second copy of the shape would
// be free to drift from the first.
import { type SuppressionNote, summariseSuppressions } from "./ci.ts";

/** Step name for the container rule pack. */
export const CONTAINER_RULES_STEP = "container-rules";

/** Every finding in this pack belongs to D4, so the domain is fixed here once. */
function buildFinding(input: Omit<FindingInput, "domain">): Finding {
  return makeFinding({ ...input, domain: "delivery" });
}

/** Rule ids, namespaced by the artifact they read. */
const RULE = {
  root: "delivery.dockerfile.runs-as-root",
  floatingTag: "delivery.dockerfile.floating-base-tag",
  secretInEnv: "delivery.dockerfile.secret-in-env",
  copyAll: "delivery.dockerfile.copy-all-without-dockerignore",
  singleStage: "delivery.dockerfile.no-multi-stage-build",
  noHealthcheck: "delivery.dockerfile.no-healthcheck",
  cacheLeft: "delivery.dockerfile.package-manager-cache-left",
  aptUnpinned: "delivery.dockerfile.apt-install-unpinned",
  composeDatabasePort: "delivery.compose.database-port-published",
  composePrivileged: "delivery.compose.privileged",
  composeHostMount: "delivery.compose.host-bind-mount",
  composeDefaultCredentials: "delivery.compose.default-credentials",
  composeNoRestart: "delivery.compose.missing-restart",
} as const;

/**
 * Checks hadolint already makes, mapped to the Sentinel rule that subsumes
 * them. The orchestrator uses this to drop the duplicate rather than printing
 * the same problem twice with two different rule ids.
 */
export const HADOLINT_OVERLAP: Readonly<Record<string, readonly string[]>> = {
  [RULE.root]: ["DL3002"],
  [RULE.floatingTag]: ["DL3006", "DL3007"],
  [RULE.secretInEnv]: ["DL3064"],
  [RULE.aptUnpinned]: ["DL3008", "DL3015"],
  [RULE.cacheLeft]: ["DL3009", "DL3016", "DL3018", "DL3019", "DL3042"],
};

/**
 * The same claim for `trivy config`'s Dockerfile checks, keyed by trivy's own
 * check id as {@link HADOLINT_OVERLAP} is keyed by hadolint's.
 *
 * Run beside this pack, `trivy config` restates several of its claims under a
 * second name and a second severity — `DS-0029` (`high`) next to
 * `delivery.dockerfile.apt-install-unpinned` (`low`) on the same line, `DS-0002`
 * next to `runs-as-root`, `DS-0001` next to `floating-base-tag` — while
 * `floating-base-tag`'s own description promises one finding per problem. This
 * table is the missing half of that promise: `normalise.ts` already collapses a
 * subsumed tool finding onto the Sentinel rule that owns it, and needs only to
 * recognise a trivy check id (the runner puts it at the front of the title, e.g.
 * `DS-0029: 'apt-get' install …`) the way it already recognises a `DL####` rule
 * suffix. Until that one line lands, this table is the claim, and
 * `container.test.ts` pins it.
 *
 * Only check ids a rule here actually restates are listed: `DS-0005` ("ADD
 * instead of COPY") is deliberately absent, because no rule here makes that claim
 * and a mapping Sentinel cannot honour would be worse than none.
 */
export const TRIVY_CONFIG_OVERLAP: Readonly<Record<string, readonly string[]>> = {
  // "DS-0002: Image user should not be 'root'".
  [RULE.root]: ["DS-0002"],
  // "DS-0001: ':latest' tag used".
  [RULE.floatingTag]: ["DS-0001"],
  // "DS-0029: 'apt-get' missing '--no-install-recommends'".
  [RULE.aptUnpinned]: ["DS-0029"],
  // "DS-0026: No HEALTHCHECK defined".
  [RULE.noHealthcheck]: ["DS-0026"],
};

/** Environment names that carry a credential rather than configuration. */
export const SECRET_NAME =
  /(^|_)(secret|secrets|password|passwd|pwd|token|apikey|api_key|access_key|private_key|credential|credentials|auth)($|_)/i;

/** Values that are a placeholder for a real secret rather than a real one. */
const PLACEHOLDER_VALUE = /^(\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|""|''|)$/;

/** Credentials that ship as the documented default of the image. */
const WEAK_VALUES: readonly string[] = [
  "postgres",
  "mysql",
  "root",
  "admin",
  "password",
  "passwd",
  "secret",
  "changeme",
  "change-me",
  "example",
  "test",
  "guest",
  "123456",
  "12345678",
  "letmein",
  "dev",
  "development",
  "local",
];

/** What a compose service *is*, which decides which rules can apply to it. */
export type ServiceRole = "datastore" | "web-ui" | "emulator" | "unknown";

/**
 * **The image → role table**, tried in order, matched against the full image
 * repository rather than against a substring of it.
 *
 * The substring version reported `opensearchproject/opensearch-dashboards:3.1.0`
 * — the Kibana fork, an HTTP browser UI on 5601 — as a published database, with
 * an impact about "a client speaking the wire protocol". The dashboard rows
 * therefore come before the datastore rows: first match wins, and the more
 * specific repository has to be asked about first.
 */
const IMAGE_ROLES: ReadonlyArray<{
  readonly role: ServiceRole;
  readonly pattern: RegExp;
  /** How the service reads in a finding. */
  readonly what: string;
}> = [
  // Browser UIs that ship beside a datastore and are routinely confused with it.
  {
    role: "web-ui",
    pattern: /(^|\/)(opensearch-dashboards?|kibana|grafana|adminer|pgadmin4?|redisinsight)$/i,
    what: "a browser UI served over HTTP",
  },
  // Local emulators: present only on a developer machine or in CI.
  {
    role: "emulator",
    pattern:
      /(^|\/)(localstack(-pro)?|dynamodb-local|azurite|fake-gcs-server|wiremock|mailhog|mailpit|elasticmq)$/i,
    what: "a local service emulator",
  },
  {
    role: "datastore",
    pattern:
      /(^|\/)(postgres|postgis|mysql|mariadb|percona|mongo|mongodb|redis|valkey|memcached|elasticsearch|opensearch|clickhouse|cassandra|scylla|neo4j|influxdb|couchdb|rabbitmq|kafka|zookeeper|etcd|minio)$/i,
    what: "a datastore that speaks its own wire protocol",
  },
];

/** The repository part of an image reference: no tag, no digest. */
export function imageRepository(image: string): string {
  const withoutDigest = image.split("@")[0] ?? image;
  const lastSlash = withoutDigest.lastIndexOf("/");
  const colon = withoutDigest.indexOf(":", lastSlash + 1);
  return colon === -1 ? withoutDigest : withoutDigest.slice(0, colon);
}

/** The role of an image reference, or `unknown` when the table says nothing. */
export function roleOfImage(image: string): { role: ServiceRole; what: string } {
  const repository = imageRepository(image.trim());
  for (const entry of IMAGE_ROLES) {
    if (entry.pattern.test(repository)) return { role: entry.role, what: entry.what };
  }
  return { role: "unknown", what: "a service Sentinel could not classify" };
}

/**
 * The role a service *name* implies, for a service that builds its own image and
 * so has no `image:` to read. The same ordered table is used, so a service called
 * `opensearch-dashboard` is not read as a datastore either.
 */
export function roleOfServiceName(name: string): { role: ServiceRole; what: string } {
  const normalised = name.trim().toLowerCase();
  for (const entry of IMAGE_ROLES) {
    if (entry.pattern.test(normalised)) return { role: entry.role, what: entry.what };
  }
  // `db`, `database`, `cache` are the conventional names a compose file gives a
  // datastore service that builds its own image and so declares no `image:`.
  if (/^(db|database|postgres|pg|mysql|mongo|redis|cache|queue)$/.test(normalised)) {
    return { role: "datastore", what: "a datastore that speaks its own wire protocol" };
  }
  return { role: "unknown", what: "a service Sentinel could not classify" };
}

/** Install commands that leave a package cache behind unless told otherwise. */
interface CacheRule {
  readonly install: RegExp;
  readonly cleanup: RegExp;
  readonly manager: string;
  readonly fix: string;
}

const CACHE_RULES: readonly CacheRule[] = [
  {
    install: /\bapt-get\s+(?:[-\w=]+\s+)*install\b/,
    cleanup: /rm\s+-rf\s+[^\n]*\/var\/lib\/apt\/lists/,
    manager: "apt",
    fix: "end the same RUN with `rm -rf /var/lib/apt/lists/*`",
  },
  {
    install: /\bapk\s+add\b/,
    cleanup: /--no-cache|rm\s+-rf\s+[^\n]*\/var\/cache\/apk/,
    manager: "apk",
    fix: "use `apk add --no-cache`",
  },
  {
    install: /\b(npm\s+(?:ci|install|i)\b|yarn\s+install\b|pnpm\s+(?:install|i)\b)/,
    cleanup: /cache\s+clean|store\s+prune|--mount=type=cache|npm_config_cache|YARN_CACHE_FOLDER/,
    manager: "the Node package manager",
    fix: "add `npm cache clean --force` (or a BuildKit `--mount=type=cache`) to the same RUN",
  },
  {
    install: /\bpip3?\s+install\b/,
    cleanup: /--no-cache-dir|--mount=type=cache/,
    manager: "pip",
    fix: "use `pip install --no-cache-dir`",
  },
];

/** One Dockerfile instruction, with its continuation lines folded into `argument`. */
export interface DockerInstruction {
  /** Uppercased keyword: FROM, RUN, USER, ... */
  readonly keyword: string;
  /** The argument, with `\` continuations joined by a space. */
  readonly argument: string;
  /** 1-based line of the keyword. */
  readonly line: number;
  /** 1-based line of the last physical line of the instruction. */
  readonly endLine: number;
}

/** One build stage, from its `FROM` to the next one. */
export interface DockerStage {
  readonly index: number;
  readonly from: DockerInstruction;
  /** The base image reference, flags already stripped. */
  readonly image: string;
  /** The `AS <alias>` name, when there is one. */
  readonly alias: string | null;
  readonly instructions: readonly DockerInstruction[];
}

/** A parsed Dockerfile: its stages, plus every instruction in file order. */
export interface Dockerfile {
  readonly instructions: readonly DockerInstruction[];
  readonly stages: readonly DockerStage[];
}

/** Splits a Dockerfile into instructions, folding `\` continuations. */
export function parseDockerfile(text: string): Dockerfile {
  const lines = text.split("\n").map((line) => line.replace(/\r$/, ""));
  const instructions: DockerInstruction[] = [];

  for (let index = 0; index < lines.length; index += 1) {
    const raw = lines[index] ?? "";
    const trimmed = raw.trim();
    // Dockerfile comments are whole-line only; a `#` inside an argument is data.
    if (trimmed === "" || trimmed.startsWith("#")) continue;

    const parts: string[] = [];
    let current = raw;
    let last = index;
    for (;;) {
      const body = current.trimEnd();
      if (!body.endsWith("\\")) {
        parts.push(body.trim());
        break;
      }
      parts.push(body.slice(0, -1).trim());
      last += 1;
      const next = lines[last];
      if (next === undefined) break;
      // A comment line inside a continuation is skipped, as the builder does.
      if (next.trim().startsWith("#")) {
        current = "\\";
        continue;
      }
      current = next;
    }

    const joined = parts.filter((part) => part !== "").join(" ");
    const match = /^([A-Za-z][A-Za-z_]*)\s*(.*)$/s.exec(joined);
    if (match !== null) {
      instructions.push({
        keyword: (match[1] ?? "").toUpperCase(),
        argument: (match[2] ?? "").trim(),
        line: index + 1,
        endLine: last + 1,
      });
    }
    index = last;
  }

  const stages: DockerStage[] = [];
  for (const instruction of instructions) {
    if (instruction.keyword === "FROM") {
      const parsed = parseFrom(instruction.argument);
      stages.push({
        index: stages.length,
        from: instruction,
        image: parsed.image,
        alias: parsed.alias,
        instructions: [],
      });
      continue;
    }
    const stage = stages[stages.length - 1];
    if (stage === undefined) continue;
    (stage.instructions as DockerInstruction[]).push(instruction);
  }

  return { instructions, stages };
}

/** Reads `FROM [--flags] image[:tag|@digest] [AS alias]`. */
function parseFrom(argument: string): { image: string; alias: string | null } {
  const tokens = argument.split(/\s+/).filter((token) => token !== "");
  const positional = tokens.filter((token) => !token.startsWith("--"));
  const image = positional[0] ?? "";
  const asIndex = positional.findIndex((token) => token.toUpperCase() === "AS");
  const alias = asIndex === -1 ? null : (positional[asIndex + 1] ?? null);
  return { image, alias };
}

/** How specific a base-image tag is; a digest is the only reference that cannot move. */
export type TagPrecision = "digest" | "none" | "latest" | "floating" | "exact";

/** Classifies a base-image reference. */
export function classifyImage(image: string): { precision: TagPrecision; tag: string } {
  if (image.includes("@sha256:")) return { precision: "digest", tag: "digest" };
  // `registry:5000/app` — a colon in the host segment is a port, not a tag.
  const lastSlash = image.lastIndexOf("/");
  const colon = image.indexOf(":", lastSlash + 1);
  if (colon === -1) return { precision: "none", tag: "latest" };
  const tag = image.slice(colon + 1);
  if (tag === "latest") return { precision: "latest", tag };
  const version = /(\d+)(?:\.(\d+))?(?:\.(\d+))?/.exec(tag);
  const patch = version?.[3];
  return { precision: patch === undefined ? "floating" : "exact", tag };
}

// ---------------------------------------------------------------------------
// What the artifact is for
// ---------------------------------------------------------------------------

/**
 * Whether an image is the artifact a deploy ships, or a tool that only ever runs
 * on a developer machine or a CI runner.
 *
 * `shipped` is the conservative answer: it is what an image gets when nothing in
 * the Dockerfile says otherwise, because grading an unknown image as if it ships
 * errs towards reporting.
 */
export type ImageRole = "shipped" | "tooling";

/** The verdict, with the signals that produced it so a reader can disagree. */
export interface ImageRoleVerdict {
  readonly role: ImageRole;
  /** Each signal as a reader would check it; empty for `shipped`. */
  readonly signals: readonly string[];
  /** True when the base image's own entrypoint needs uid 0 to initialise. */
  readonly requiresRoot: boolean;
}

/**
 * Base images whose documented entrypoint is a local emulator or a
 * container-in-container tool: it initialises as root and, for LocalStack,
 * spawns the Lambda execution containers through the Docker socket.
 */
const TOOLING_BASE_IMAGE = /(^|\/)(localstack(-pro)?|docker)(:|$)|:.*dind|(^|\/)dind(:|$)/i;

/**
 * The same question asked of a `build.dockerfile` path, which is how a compose
 * service names an emulator it builds itself:
 * `dockerfile: ./ops/localstack/Dockerfile`.
 */
function buildsToolingImage(dockerfile: string): boolean {
  return (
    TOOLING_BASE_IMAGE.test(dockerfile) || /(^|\/)(localstack|dind)([/_-]|$)/i.test(dockerfile)
  );
}

/**
 * Build arguments that exist to make the container write into a bind mount as the
 * developer who started it. A Dockerfile that takes `DOCKER_USER_ID` and
 * `DOCKER_GROUP_ID` and hands them to `groupadd`/`useradd` is doing exactly that;
 * a deployed image has no host user to match.
 */
const HOST_UID_ARG = /^(DOCKER_)?(USER_ID|GROUP_ID|UID|GID|PUID|PGID|HOST_UID|HOST_GID)$/i;

/**
 * Classifies a Dockerfile from its own contents.
 *
 * Two signals are each sufficient on their own:
 *
 * 1. the base image of the final stage is a local emulator or a
 *    docker-in-docker tool (`FROM localstack/localstack`);
 * 2. a build argument maps the host's uid or gid into the image.
 *
 * A third observation — that the image copies no application source from the
 * build context — is reported as a supporting signal but is never sufficient on
 * its own, because a well-built production image copies only from an earlier
 * stage and would look identical.
 */
export function classifyDockerfileRole(parsed: Dockerfile): ImageRoleVerdict {
  const signals: string[] = [];
  const final = parsed.stages[parsed.stages.length - 1];
  const base = final?.image ?? "";
  const emulator = TOOLING_BASE_IMAGE.test(base);
  if (emulator)
    signals.push(`the final stage builds \`FROM ${base}\`, a local emulator or tooling image`);

  const hostUid = parsed.instructions
    .filter((instruction) => instruction.keyword === "ARG")
    .flatMap((instruction) => parseAssignments(instruction.argument))
    .filter((pair) => HOST_UID_ARG.test(pair.name));
  if (hostUid.length > 0) {
    signals.push(
      `build arg(s) ${hostUid.map((pair) => `\`${pair.name}\``).join(", ")} map the host's uid/gid into the image, which only a bind-mounted developer checkout needs`,
    );
  }

  if (signals.length === 0) return { role: "shipped", signals: [], requiresRoot: false };

  const copiesSource = (final?.instructions ?? []).some((instruction) => {
    if (instruction.keyword !== "COPY") return false;
    return !/--from=/.test(instruction.argument);
  });
  if (!copiesSource) {
    signals.push("the final stage copies no application source from the build context");
  }
  return { role: "tooling", signals, requiresRoot: emulator };
}

/**
 * Whether a compose file describes a developer's machine or something that ships.
 *
 * `unknown` is not a claim that the file is a deployment artifact — Sentinel
 * cannot prove that from the file alone — only that nothing in it says it is
 * developer-local, so it is graded as if it ships.
 */
export type ComposeScope = "development" | "unknown";

/** The verdict, with the signals that produced it. */
export interface ComposeScopeVerdict {
  readonly scope: ComposeScope;
  readonly signals: readonly string[];
}

/**
 * Classifies a compose file from its own contents: the header comments, the
 * service images, the uid mapping and the bind mounts.
 *
 * Each signal below is something only a file a developer runs by hand does: it
 * asks to be merged on the command line, it stands up an emulator, it maps the
 * host's uid so a bind mount stays writable, or it serves the repository root
 * from the developer's own disk. Without them, a socket mount in a file that
 * never leaves a laptop is graded as a `critical` container escape.
 */
export function classifyCompose(text: string, root: YamlNode | null): ComposeScopeVerdict {
  const signals: string[] = [];
  const header = text.split("\n").slice(0, 12).join("\n");
  if (/^\s*#.*(override file|-f\s+\S+\.ya?ml\s+-f|use with:)/im.test(header)) {
    signals.push(
      "a header comment describes the file as an override to be merged with `-f a.yml -f b.yml`, which is a command a developer types",
    );
  }

  const services = childOf(root, "services") ?? root;
  for (const service of entriesOf(services)) {
    const node = service.value;
    if (node.kind !== "mapping") continue;
    const image = textOf(childOf(node, "image")) ?? "";
    const build = childOf(node, "build");
    const dockerfile = textOf(childOf(build, "dockerfile")) ?? "";
    const role = image === "" ? roleOfServiceName(service.key) : roleOfImage(image);
    if (role.role === "emulator" || TOOLING_BASE_IMAGE.test(imageRepository(image))) {
      signals.push(
        `service "${service.key}" is ${role.what}, which exists to stand in for a cloud`,
      );
    } else if (buildsToolingImage(dockerfile)) {
      signals.push(
        `service "${service.key}" builds from \`${dockerfile}\`, a local emulator image`,
      );
    }

    const user = textOf(childOf(node, "user")) ?? "";
    if (/\$\{?[A-Za-z_][A-Za-z0-9_]*\}?:\$\{?[A-Za-z_]/.test(user)) {
      signals.push(
        `service "${service.key}" runs as \`user: ${user}\`, the uid/gid of whoever started compose`,
      );
    }
    for (const argument of entriesOf(childOf(build, "args"))) {
      if (!HOST_UID_ARG.test(argument.key)) continue;
      signals.push(
        `service "${service.key}" passes build arg \`${argument.key}\`, which maps the host user into the image`,
      );
      break;
    }

    for (const item of itemsOf(childOf(node, "volumes"))) {
      const mount = textOf(item) ?? `${textOf(childOf(item, "source")) ?? ""}:`;
      const source = (mount.split(":")[0] ?? "").trim();
      if (!/^(\.|\.\/|\.\.|\.\.\/|(\.\.\/)+)$/.test(source)) continue;
      signals.push(
        `service "${service.key}" bind-mounts the repository root (\`${mount}\`), so it runs code from the developer's disk rather than from the image`,
      );
      break;
    }

    for (const pair of readEnvironment(childOf(node, "environment"))) {
      if (pair.name !== "NODE_ENV") continue;
      const value = (pair.value ?? "").trim().toLowerCase();
      if (["dev", "development", "test", "local"].includes(value)) {
        signals.push(`service "${service.key}" sets \`NODE_ENV: ${value}\``);
      }
    }
  }

  const unique = [...new Set(signals)];
  return { scope: unique.length > 0 ? "development" : "unknown", signals: unique };
}

/** The sentence that carries a scope verdict into a finding. */
function scopeSentence(verdict: ComposeScopeVerdict, file: string): string {
  if (verdict.scope === "unknown") {
    return `Nothing in ${file} marks it as developer-local, so it is graded as if it ships.`;
  }
  return `Sentinel read ${file} as a developer-local compose file because ${verdict.signals.map((signal) => signal).join("; ")}. That caps this finding: the blast radius is one workstation or one CI runner, not a deployment.`;
}

/** True when the repository compiles TypeScript, which is what makes one stage a finding. */
export function buildsTypeScript(profile: StackProfile): boolean {
  return (
    valuesOf(profile, "language").includes("typescript") || factsOf(profile, "tsconfig").length > 0
  );
}

/** Splits `ENV`/`ARG` arguments into name/value pairs, both spellings. */
export function parseAssignments(argument: string): Array<{ name: string; value: string | null }> {
  const tokens = argument.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) ?? [];
  const pairs: Array<{ name: string; value: string | null }> = [];
  // Legacy `ENV NAME the rest of the line` has no `=` in the first token.
  const first = tokens[0];
  if (first !== undefined && !first.includes("=") && tokens.length > 1) {
    return [{ name: first, value: unquote(tokens.slice(1).join(" ")) }];
  }
  for (const token of tokens) {
    const equals = token.indexOf("=");
    if (equals === -1) {
      pairs.push({ name: token, value: null });
      continue;
    }
    pairs.push({ name: token.slice(0, equals), value: unquote(token.slice(equals + 1)) });
  }
  return pairs;
}

/** Strips one layer of matching quotes. */
function unquote(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length >= 2) {
    const first = trimmed[0];
    if ((first === '"' || first === "'") && trimmed.endsWith(first)) return trimmed.slice(1, -1);
  }
  return trimmed;
}

/** What analysing one Dockerfile or compose file produced, including what it withheld. */
export interface ContainerAnalysis {
  readonly findings: Finding[];
  readonly suppressed: SuppressionNote[];
}

/** Runs every Dockerfile rule over one file. */
export function analyseDockerfile(
  file: string,
  text: string,
  options: { readonly hasDockerignore: boolean; readonly buildsTypeScript: boolean },
): ContainerAnalysis {
  const parsed = parseDockerfile(text);
  const findings: Finding[] = [];
  const suppressed: SuppressionNote[] = [];
  const stages = parsed.stages;
  const final = stages[stages.length - 1];
  if (final === undefined) return { findings, suppressed };

  const aliases = new Set(
    stages.map((stage) => stage.alias).filter((alias): alias is string => alias !== null),
  );
  const image = classifyDockerfileRole(parsed);
  const tooling = image.role === "tooling";
  // The sentence that every capped finding in this file carries, so the reader
  // sees the classification rather than only its effect.
  const because = tooling
    ? `Sentinel read ${file} as a developer-tooling image because ${image.signals.join("; ")}. A deploy does not push this image, so the finding is capped at \`low\`.`
    : "";

  // --- base image pinning -------------------------------------------------
  for (const stage of stages) {
    const stageImage = stage.image;
    if (stageImage === "" || stageImage === "scratch") continue;
    if (aliases.has(stageImage)) continue;
    if (stageImage.includes("$")) continue;
    const { precision, tag } = classifyImage(stageImage);
    if (precision === "digest" || precision === "exact") continue;
    const unpinned = precision === "latest" || precision === "none";
    // Deployment reachability first, tag specificity second: an untagged
    // emulator that only `make up` builds cannot outrank a partially-tagged
    // base image on the images that serve production traffic.
    const severity: Severity = tooling ? "low" : unpinned ? "high" : "low";
    findings.push(
      buildFinding({
        rule: RULE.floatingTag,
        severity,
        confidence: "high",
        title: unpinned
          ? `Base image \`${stageImage}\` floats on ${precision === "none" ? "an implicit `latest`" : "`latest`"}`
          : `Base image \`${stageImage}\` is pinned only to \`${tag}\``,
        description: `Stage ${stage.index + 1}${stage.alias === null ? "" : ` ("${stage.alias}")`} builds from \`${stageImage}\`. ${unpinned ? "Nothing identifies which build that is" : `\`${tag}\` moves whenever upstream publishes a patch`}, so the same Dockerfile produces a different image — and a different set of CVEs — on every rebuild.${unpinned && tooling ? ` ${because}` : ""}`,
        file,
        line: stage.from.line,
        symbol: `stage${stage.index}`,
        impact: unpinned
          ? "Builds are unreproducible and unauditable: a scan that passed yesterday says nothing about the image that ships today, and a compromised upstream tag is pulled silently."
          : "A patch-level upstream change enters production without a commit, so the image in the registry does not match what the repository was reviewed as.",
        recommendation: `Pin to a digest — \`FROM ${stageImage.split(":")[0] ?? stageImage}@sha256:<digest>\` — and let an automated bump open the PR that changes it.`,
        acceptanceCriteria: [
          `Every \`FROM\` in ${file} references a digest or a fully-qualified version`,
          "Base-image bumps arrive as reviewable commits",
        ],
        cwe: ["CWE-1104"],
        source: { kind: "rule", name: CONTAINER_RULES_STEP },
      }),
    );
  }

  // --- running as root ----------------------------------------------------
  const userInstructions = final.instructions.filter(
    (instruction) => instruction.keyword === "USER",
  );
  const lastUser = userInstructions[userInstructions.length - 1];
  const rootUser =
    lastUser !== undefined && /^(root|0)(:|$)/.test(lastUser.argument.trim().toLowerCase());
  if (lastUser === undefined || rootUser) {
    findings.push(
      buildFinding({
        rule: RULE.root,
        severity: tooling ? "low" : "high",
        confidence: "high",
        title:
          lastUser === undefined
            ? "Final image sets no `USER`, so the container runs as root"
            : "Final image explicitly runs as root",
        description: `${
          lastUser === undefined
            ? `The last stage of ${file} never issues a \`USER\` instruction, so the entrypoint runs as uid 0 inside the container.`
            : `The last \`USER\` instruction in ${file} selects root, so the entrypoint runs as uid 0 inside the container.`
        }${tooling ? ` ${because}${image.requiresRoot ? " Its base image also initialises as uid 0 by design — a local emulator writes into `/etc`, `/var` and, for LocalStack, drives the Docker socket — so `USER` cannot simply be appended here." : ""}` : ""}`,
        file,
        line: lastUser?.line ?? final.from.line,
        symbol: "final-stage",
        exploitability:
          "Requires code execution inside the container first — an RCE in the application, a malicious dependency, or a deserialisation bug.",
        impact: tooling
          ? "Root inside a developer-local container can write every mounted path on that workstation's checkout and reach the container runtime the developer is running; it is not a path into production."
          : "Root in the container can write every mounted path, read every secret file, install tooling and reach the container runtime's attack surface; with a shared kernel it is one escape away from root on the host.",
        recommendation: image.requiresRoot
          ? "Leave the base image's uid 0 alone and keep this image off anything that ships; if it must be hardened, run it under a user namespace (`userns-remap`) rather than appending `USER`."
          : "Create a non-root user in the image (`RUN adduser --system --uid 10001 app`) and end the final stage with `USER 10001`; make sure the paths the app writes to are owned by it.",
        acceptanceCriteria: image.requiresRoot
          ? [
              `${file} is built only by developer or CI targets, and no deploy path references it`,
              "The images that ship end their final stage with a non-root `USER`",
            ]
          : [
              `The final stage of ${file} ends with a non-root \`USER\``,
              "`docker run <image> id -u` prints a non-zero uid",
            ],
        cwe: ["CWE-250", "CWE-269"],
        source: { kind: "rule", name: CONTAINER_RULES_STEP },
      }),
    );
  }

  // --- secrets in ENV / ARG ----------------------------------------------
  // An `ENV` in the stage that ships turns a build argument into part of the
  // runtime environment of every container from this image, which is a step
  // beyond a build-only `ARG`; an `ENV` in a build stage is not shipped at all.
  const shippedEnv = new Set(final.instructions);
  for (const instruction of parsed.instructions) {
    if (instruction.keyword !== "ENV" && instruction.keyword !== "ARG") continue;
    for (const pair of parseAssignments(instruction.argument)) {
      if (!SECRET_NAME.test(pair.name)) continue;
      const literal = pair.value !== null && !PLACEHOLDER_VALUE.test(pair.value);
      const persisted =
        !literal &&
        instruction.keyword === "ENV" &&
        pair.value !== null &&
        pair.value !== "" &&
        shippedEnv.has(instruction);
      findings.push(
        buildFinding({
          rule: RULE.secretInEnv,
          severity: literal || persisted ? "high" : "medium",
          confidence: literal ? "high" : "medium",
          title: literal
            ? `Credential \`${pair.name}\` is baked into the image with a literal value`
            : persisted
              ? `Credential \`${pair.name}\` is persisted into the shipping stage's environment`
              : `Credential \`${pair.name}\` is declared as a build \`${instruction.keyword}\``,
          description: literal
            ? `${instruction.keyword} \`${pair.name}\` assigns a value inside ${file}. Both ENV and ARG values are recorded in the image metadata, so \`docker history\` shows them to anyone who can pull the image, and every layer built afterwards carries them.`
            : persisted
              ? `\`ENV ${pair.name}=${pair.value}\` is in the final stage of ${file}, so whatever the build argument carried becomes part of the environment of every container started from this image, and \`docker inspect\` prints it — not only \`docker history\`.`
              : `\`${pair.name}\` is declared as an ${instruction.keyword} in ${file}. Whatever is passed at build time is written into the image history, even when the variable is never persisted into the final layer.`,
          file,
          line: instruction.line,
          endLine: instruction.endLine,
          symbol: `${instruction.keyword}:${pair.name}`,
          exploitability: literal
            ? "Anyone who can pull the image, or read this repository, has the credential; no exploitation is required."
            : persisted
              ? "Anyone who can run or inspect a container from this image reads the value from its environment; no exploitation is required."
              : "Requires access to the built image or to the build logs.",
          impact: `The credential behind ${pair.name} must be treated as disclosed and rotated; until then it is usable by anyone with the image.`,
          recommendation:
            "Pass the secret at runtime (an orchestrator secret, a mounted file) or, when it is genuinely needed during the build, use a BuildKit secret mount (`RUN --mount=type=secret,id=npm ...`), which never lands in a layer.",
          acceptanceCriteria: [
            `${file} declares no ENV or ARG that carries a credential value`,
            "`docker history --no-trunc <image>` shows no secret material",
            "The exposed credential has been rotated",
          ],
          cwe: ["CWE-798", "CWE-532"],
          owasp: ["A05:2021-Security Misconfiguration"],
          source: { kind: "rule", name: CONTAINER_RULES_STEP },
        }),
      );
    }
  }

  // --- COPY . . without a .dockerignore -----------------------------------
  if (!options.hasDockerignore) {
    const copyAll = parsed.instructions.find((instruction) => {
      if (instruction.keyword !== "COPY" && instruction.keyword !== "ADD") return false;
      const tokens = instruction.argument.split(/\s+/).filter((token) => !token.startsWith("--"));
      return tokens.length >= 2 && (tokens[0] === "." || tokens[0] === "./");
    });
    if (copyAll !== undefined) {
      findings.push(
        buildFinding({
          rule: RULE.copyAll,
          severity: "medium",
          confidence: "high",
          title: "`COPY . .` with no `.dockerignore` in the build context",
          description: `${file} copies the whole build context into the image and no \`.dockerignore\` limits what that context holds, so \`.env\` files, \`.git/\`, local credentials, \`node_modules\` and test fixtures all ship inside the image.`,
          file,
          line: copyAll.line,
          endLine: copyAll.endLine,
          symbol: "copy-all",
          exploitability:
            "Anyone who can pull the image reads the copied files; `.git/` alone discloses the full history, including secrets deleted in later commits.",
          impact:
            "Secrets and source history leak into a distributed artifact, and the image is larger and slower to pull than it needs to be.",
          recommendation:
            "Add a `.dockerignore` that excludes `.git`, `node_modules`, `.env*`, build output and test fixtures, and prefer copying the specific paths the image needs.",
          acceptanceCriteria: [
            "A `.dockerignore` exists in the build context and excludes `.git`, `.env*` and `node_modules`",
            "The built image contains no dotfiles from the working tree",
          ],
          cwe: ["CWE-538"],
          source: { kind: "rule", name: CONTAINER_RULES_STEP },
        }),
      );
    }
  }

  // --- single stage in a TypeScript repository ----------------------------
  if (options.buildsTypeScript && stages.length === 1 && tooling) {
    // The rule's whole claim is that a compiler and the sources it read stay in
    // the image that serves production traffic. A tooling image compiles
    // nothing and serves nothing, so the claim is not true of it.
    suppressed.push({
      rule: RULE.singleStage,
      file,
      line: final.from.line,
      reason: `${file} is a developer-tooling image (${image.signals[0] ?? "no application payload"}), so there is no production runtime for a build stage to be stripped out of`,
    });
  } else if (options.buildsTypeScript && stages.length === 1) {
    findings.push(
      buildFinding({
        rule: RULE.singleStage,
        severity: "medium",
        confidence: "medium",
        title: "TypeScript project ships from a single-stage build",
        description: `${file} has one \`FROM\`, so the toolchain used to compile TypeScript — compilers, dev dependencies, source maps and the source tree itself — stays in the image that runs in production.`,
        file,
        line: final.from.line,
        symbol: "single-stage",
        impact:
          "The runtime image carries a much larger attack surface and a much larger CVE surface than the application needs, and it ships the source of the service it runs.",
        recommendation:
          "Split into a `build` stage that installs dev dependencies and compiles, and a runtime stage that copies only `dist/` plus production dependencies.",
        acceptanceCriteria: [
          `${file} has a dedicated build stage and a runtime stage`,
          "The runtime image contains no dev dependencies and no TypeScript sources",
        ],
        cwe: ["CWE-1188"],
        source: { kind: "rule", name: CONTAINER_RULES_STEP },
      }),
    );
  }

  // --- HEALTHCHECK --------------------------------------------------------
  const runsSomething = final.instructions.some(
    (instruction) => instruction.keyword === "CMD" || instruction.keyword === "ENTRYPOINT",
  );
  const hasHealthcheck = final.instructions.some(
    (instruction) => instruction.keyword === "HEALTHCHECK",
  );
  if (runsSomething && !hasHealthcheck) {
    findings.push(
      buildFinding({
        rule: RULE.noHealthcheck,
        severity: "low",
        confidence: "high",
        title: "Image declares no `HEALTHCHECK`",
        description: `The final stage of ${file} starts a long-running process but never tells the runtime how to tell a healthy container from a wedged one.`,
        file,
        line: final.from.line,
        symbol: "no-healthcheck",
        impact:
          "A container whose process is alive but not serving keeps receiving traffic: the orchestrator has no signal to restart it or to pull it out of the load balancer.",
        recommendation:
          'Add `HEALTHCHECK --interval=30s --timeout=3s CMD ["node", "dist/health.js"]` (or the equivalent probe) and make it exercise the dependencies the service needs.',
        acceptanceCriteria: [
          `${file} declares a HEALTHCHECK on the final stage`,
          "The probe fails when the service cannot reach its database",
        ],
        source: { kind: "rule", name: CONTAINER_RULES_STEP },
      }),
    );
  }

  // --- package manager cache and unpinned apt -----------------------------
  for (const instruction of parsed.instructions) {
    if (instruction.keyword !== "RUN") continue;
    const script = instruction.argument;
    for (const rule of CACHE_RULES) {
      if (!rule.install.test(script) || rule.cleanup.test(script)) continue;
      findings.push(
        buildFinding({
          rule: RULE.cacheLeft,
          severity: "low",
          confidence: "high",
          title: `${rule.manager} cache is left in the layer`,
          description: `The \`RUN\` at line ${instruction.line} of ${file} installs packages with ${rule.manager} and does not clear the cache in the same layer, so the downloaded archives are baked into the image permanently.`,
          file,
          line: instruction.line,
          endLine: instruction.endLine,
          symbol: contentSymbol(`cache:${rule.manager}`, script),
          impact:
            "Every pull ships tens to hundreds of megabytes of package archives that the running service never reads, slowing deploys and widening what a scanner has to inspect.",
          recommendation: `Within the same \`RUN\`, ${rule.fix}. A later \`RUN rm\` does not help: the earlier layer still holds the files.`,
          acceptanceCriteria: ["No package-manager cache remains in any layer of the image"],
          source: { kind: "rule", name: CONTAINER_RULES_STEP },
        }),
      );
    }

    if (!/\bapt-get\s+(?:[-\w=]+\s+)*install\b/.test(script)) continue;
    const recommends = script.includes("--no-install-recommends");
    const pinned = /\s[\w.+-]+=[\w.:+~-]+/.test(script.replace(/--[\w-]+=\S+/g, ""));
    if (recommends && pinned) continue;
    const missing = [
      recommends ? null : "`--no-install-recommends`",
      pinned ? null : "an explicit `package=version`",
    ].filter((item): item is string => item !== null);
    findings.push(
      buildFinding({
        rule: RULE.aptUnpinned,
        severity: "low",
        confidence: "high",
        title: `apt-get install without ${missing.join(" and ")}`,
        description: `The \`RUN\` at line ${instruction.line} of ${file} installs Debian packages without ${missing.join(" and ")}, so the set of packages that lands in the image is decided by the mirror at build time.`,
        file,
        line: instruction.line,
        endLine: instruction.endLine,
        symbol: contentSymbol("apt", instruction.argument),
        impact:
          "The image is unreproducible and larger than intended: recommended packages pull in interpreters and tools the service never uses, each with its own CVE stream.",
        recommendation:
          "Use `apt-get install -y --no-install-recommends pkg=<version>` and bump the pinned versions deliberately.",
        acceptanceCriteria: [
          `Every \`apt-get install\` in ${file} passes \`--no-install-recommends\` and pins its versions`,
        ],
        cwe: ["CWE-1104"],
        source: { kind: "rule", name: CONTAINER_RULES_STEP },
      }),
    );
  }

  return { findings, suppressed };
}

/** A published port, normalised from either compose syntax. */
export interface PublishedPort {
  readonly hostIp: string | null;
  readonly container: string;
  readonly line: number;
  readonly raw: string;
}

/** Reads a `ports:` entry in either the short string form or the long mapping form. */
export function readPort(node: YamlNode): PublishedPort | null {
  const text = textOf(node);
  if (text !== null) {
    const value = text.trim().replace(/\/(tcp|udp)$/i, "");
    if (value === "") return null;
    const parts = value.split(":");
    if (parts.length === 1) {
      // `- "5432"` publishes on a random host port, on every interface.
      return { hostIp: null, container: parts[0] ?? value, line: node.line, raw: text };
    }
    if (parts.length === 2) {
      return { hostIp: null, container: parts[1] ?? "", line: node.line, raw: text };
    }
    return {
      hostIp: parts.slice(0, parts.length - 2).join(":"),
      container: parts[parts.length - 1] ?? "",
      line: node.line,
      raw: text,
    };
  }
  const target = textOf(childOf(node, "target"));
  const published = childOf(node, "published");
  if (target === null && published === null) return null;
  const entry = entryOf(node, "published") ?? entryOf(node, "target");
  return {
    hostIp: textOf(childOf(node, "host_ip")),
    container: target ?? "",
    line: entry?.line ?? node.line,
    raw: `${textOf(published) ?? ""}:${target ?? ""}`,
  };
}

/** True when the published port is reachable from outside the host. */
export function bindsEveryInterface(port: PublishedPort): boolean {
  if (port.hostIp === null) return true;
  const ip = port.hostIp.trim();
  return ip === "" || ip === "0.0.0.0" || ip === "::" || ip === "*";
}

/** A `KEY=VALUE` list entry or a `KEY: VALUE` mapping entry, normalised. */
export interface EnvPair {
  readonly name: string;
  readonly value: string | null;
  readonly line: number;
}

/** Reads `environment:` in either the list form or the mapping form. */
export function readEnvironment(node: YamlNode | null): EnvPair[] {
  if (node === null) return [];
  if (node.kind === "mapping") {
    return node.entries.map((entry) => ({
      name: entry.key,
      value: textOf(entry.value),
      line: entry.line,
    }));
  }
  const pairs: EnvPair[] = [];
  for (const item of itemsOf(node)) {
    const text = textOf(item);
    if (text === null) continue;
    const equals = text.indexOf("=");
    if (equals === -1) {
      pairs.push({ name: text.trim(), value: null, line: item.line });
      continue;
    }
    pairs.push({
      name: text.slice(0, equals).trim(),
      value: text.slice(equals + 1).trim(),
      line: item.line,
    });
  }
  return pairs;
}

/** True when a volume entry's source is a path on the host rather than a named volume. */
export function hostPathOf(source: string): string | null {
  const value = source.trim();
  if (value === "") return null;
  if (/^[./~]/.test(value) || value.startsWith("$") || /^[A-Za-z]:[\\/]/.test(value)) return value;
  return null;
}

/**
 * True when this service is the one that documents needing the Docker socket:
 * it points `DOCKER_HOST` at the socket it mounts, or it is a local emulator
 * (LocalStack spawns its Lambda execution containers through the daemon).
 *
 * This does not make the mount safe. It changes the recommendation — "remove it"
 * breaks the emulator — and it is half of the reason the same mount is graded
 * differently in a developer compose file and in one that ships.
 */
function declaresSocketDependency(node: YamlNode, role: ServiceRole): boolean {
  if (role === "emulator") return true;
  for (const pair of readEnvironment(childOf(node, "environment"))) {
    if (pair.name !== "DOCKER_HOST") continue;
    if ((pair.value ?? "").includes("docker.sock")) return true;
  }
  const build = childOf(node, "build");
  const dockerfile = textOf(childOf(build, "dockerfile")) ?? "";
  return buildsToolingImage(dockerfile);
}

/**
 * **How a host mount is graded.** The socket is never graded below another host
 * mount in the same file; the two axes decide how far above them it sits.
 *
 * | mounts `/var/run/docker.sock` | the service declares it needs it | it does not |
 * |---|---|---|
 * | compose file with no developer-local signal | high | critical |
 * | developer-local compose file | low | high |
 *
 * A non-socket mount is `medium` for an absolute host path and `low` for a path
 * inside the checkout, and a developer-local file caps both at `low`.
 *
 * The bottom-left cell is the one the measurement forced: a socket mount that the
 * service says it needs, in a file nothing outside a workstation runs, is a
 * capability of the developer's own machine. It is still reported, still says
 * what the socket is, and the fix it asks for is a socket proxy rather than a
 * deletion that would break the emulator.
 */
function hostMountSeverity(
  dockerSocket: boolean,
  absolute: boolean,
  development: boolean,
  declared: boolean,
): Severity {
  if (dockerSocket) {
    if (development) return declared ? "low" : "high";
    return declared ? "high" : "critical";
  }
  if (development) return "low";
  return absolute ? "medium" : "low";
}

/** Runs every compose rule over one file. */
export function analyseCompose(file: string, text: string): ContainerAnalysis {
  const document = parseYaml(text);
  const root = document.root;
  const findings: Finding[] = [];
  const suppressed: SuppressionNote[] = [];
  if (root === null) return { findings, suppressed };
  // Compose v2 dropped the top-level `version:`; services may sit at the root.
  const services = childOf(root, "services") ?? root;
  const scope = classifyCompose(text, root);
  const development = scope.scope === "development";
  const because = scopeSentence(scope, file);

  for (const service of entriesOf(services)) {
    const node = service.value;
    if (node.kind !== "mapping") continue;
    const image = textOf(childOf(node, "image")) ?? "";
    const role = image === "" ? roleOfServiceName(service.key) : roleOfImage(image);
    const isDatabase = role.role === "datastore";

    // --- published database ports ----------------------------------------
    if (!isDatabase && itemsOf(childOf(node, "ports")).length > 0 && role.role === "web-ui") {
      // The rule's impact — "a client speaking the wire protocol" — is not true
      // of an HTTP dashboard, and the substring match that said otherwise is
      // what reported `opensearchproject/opensearch-dashboards` as a database.
      suppressed.push({
        rule: RULE.composeDatabasePort,
        file,
        line: service.line,
        reason: `service "${service.key}" runs \`${image}\`, which the image→role table classifies as ${role.what} rather than a datastore, so publishing its port exposes an HTTP UI and not a database wire protocol`,
      });
    }
    if (isDatabase) {
      for (const item of itemsOf(childOf(node, "ports"))) {
        const port = readPort(item);
        if (port === null || !bindsEveryInterface(port)) continue;
        findings.push(
          buildFinding({
            rule: RULE.composeDatabasePort,
            severity: development ? "medium" : "high",
            confidence: "high",
            title: `Database service "${service.key}" publishes port ${port.container} on every interface`,
            description: `\`${port.raw}\` on service "${service.key}" (${image || "no image declared"}) binds the host's every interface, so the database is reachable from the network the host sits on, not only from the compose network. It is ${role.what}.${development ? ` ${because}` : ""}`,
            file,
            line: port.line,
            symbol: `${service.key}:${port.container}`,
            exploitability:
              "Anyone who can reach the host on that port. On a cloud VM with a permissive security group, or on a laptop on a shared network, that is the whole network segment.",
            impact:
              "Direct database access bypasses the application entirely: every authorization rule the API enforces is irrelevant to a client speaking the wire protocol.",
            recommendation: `Bind to loopback (\`"127.0.0.1:${port.container}:${port.container}"\`) so only the host can reach it, or drop the mapping and let the other services use the compose network by name.`,
            acceptanceCriteria: [
              `Service "${service.key}" publishes no port, or publishes it on 127.0.0.1 only`,
              "Application services reach the database by service name over the compose network",
            ],
            cwe: ["CWE-668", "CWE-1327"],
            owasp: ["A05:2021-Security Misconfiguration"],
            source: { kind: "rule", name: CONTAINER_RULES_STEP },
          }),
        );
      }
    }

    // --- privileged --------------------------------------------------------
    const privileged = entryOf(node, "privileged");
    if (privileged !== null && isTrue(privileged.value)) {
      findings.push(
        buildFinding({
          rule: RULE.composePrivileged,
          severity: "high",
          confidence: "high",
          title: `Service "${service.key}" runs privileged`,
          description: `\`privileged: true\` on "${service.key}" disables essentially every container isolation boundary: all capabilities are granted, the device cgroup allows everything, and AppArmor/seccomp profiles are dropped.`,
          file,
          line: privileged.line,
          symbol: service.key,
          exploitability:
            "Requires code execution in the container; from there, escaping to the host is a documented, tool-assisted step rather than a research problem.",
          impact:
            "A container compromise becomes a host compromise, including every other container on the machine.",
          recommendation:
            "Drop `privileged` and grant only the capabilities the service actually needs with `cap_add`, keeping `cap_drop: [ALL]` as the baseline.",
          acceptanceCriteria: [
            `No service in ${file} sets \`privileged: true\``,
            `"${service.key}" runs with an explicit, minimal \`cap_add\` list`,
          ],
          cwe: ["CWE-250", "CWE-269"],
          source: { kind: "rule", name: CONTAINER_RULES_STEP },
        }),
      );
    }

    // --- host bind mounts --------------------------------------------------
    for (const item of itemsOf(childOf(node, "volumes"))) {
      const text = textOf(item);
      const source =
        text !== null ? (text.split(":")[0] ?? "") : (textOf(childOf(item, "source")) ?? "");
      const hostPath = hostPathOf(source);
      if (hostPath === null) continue;
      const dockerSocket = hostPath.includes("docker.sock");
      const absolute = hostPath.startsWith("/") || hostPath.startsWith("~");
      const declared = dockerSocket && declaresSocketDependency(node, role.role);
      findings.push(
        buildFinding({
          rule: RULE.composeHostMount,
          severity: hostMountSeverity(dockerSocket, absolute, development, declared),
          confidence: "high",
          title: dockerSocket
            ? `Service "${service.key}" mounts the Docker socket`
            : `Service "${service.key}" bind-mounts host path \`${hostPath}\``,
          description: `${
            dockerSocket
              ? `"${service.key}" mounts \`${hostPath}\`. The Docker socket is the daemon's full API: a process that can write to it can start a container with the host filesystem mounted, which is root on the machine running the daemon.`
              : `"${service.key}" bind-mounts \`${hostPath}\` from the host. The container writes straight into the host filesystem, and the contents differ from machine to machine, so what runs locally is not what runs anywhere else.`
          }${
            declared
              ? ` This service declares that it needs the socket — ${role.role === "emulator" ? "a local cloud emulator starts the function containers it emulates through the daemon" : "`DOCKER_HOST` on this service points at the socket it mounts"} — so "remove the mount" would stop it working; that is why it is graded below an unexplained socket mount rather than dropped.`
              : ""
          }${development ? ` ${because}` : ""}`,
          file,
          line: item.line,
          symbol: `${service.key}:${hostPath}`,
          ...(dockerSocket
            ? {
                exploitability: development
                  ? "Any code execution inside this container, on the workstation or CI runner that started it. No kernel bug and no misconfiguration elsewhere is required."
                  : "Any code execution inside this container. No kernel bug and no misconfiguration elsewhere is required.",
              }
            : {}),
          impact: dockerSocket
            ? `Escape to root on ${development ? "the developer's machine or the CI runner" : "the host"}, and control over every other container that daemon manages.`
            : "Host state leaks into the container and container writes leak back out; the image stops being a self-contained artifact.",
          recommendation: dockerSocket
            ? declared
              ? "Keep this mount out of anything that ships, and put a socket proxy (`tecnativa/docker-socket-proxy` or equivalent) in front of it that allows only the daemon API calls the emulator makes."
              : "Remove the socket mount. If the service genuinely needs to orchestrate containers, put a socket proxy in front that allows only the specific API calls it makes."
            : "Use a named volume for data the service owns, and keep bind mounts to a development-only compose override file.",
          acceptanceCriteria: dockerSocket
            ? declared
              ? [
                  `No deploy path references ${file}`,
                  `"${service.key}" reaches the daemon through a socket proxy with an allow-list, or not at all`,
                ]
              : [`No service in ${file} mounts \`/var/run/docker.sock\``]
            : [
                `The production compose file declares no host bind mount for "${service.key}"`,
                "Development-only mounts live in `compose.override.yml`",
              ],
          cwe: dockerSocket ? ["CWE-250", "CWE-269"] : ["CWE-668"],
          source: { kind: "rule", name: CONTAINER_RULES_STEP },
        }),
      );
    }

    // --- credentials in environment ---------------------------------------
    for (const pair of readEnvironment(childOf(node, "environment"))) {
      if (!SECRET_NAME.test(pair.name)) continue;
      const value = pair.value;
      if (value === null || PLACEHOLDER_VALUE.test(value)) continue;
      // `${VAR:-fallback}` is a real credential whenever the variable is unset.
      const fallback = /^\$\{[A-Za-z_][A-Za-z0-9_]*:?-(.*)\}$/.exec(value)?.[1];
      const literal = fallback ?? value;
      if (fallback === undefined && value.startsWith("${")) continue;
      // `${VAR- }`, `${VAR-}`, `${VAR:-}`: the default is empty or a single
      // space, which is the idiom for "this variable is optional". Without this
      // branch a line like `AUTH_TOKEN=${AUTH_TOKEN- }` is reported as a
      // hardcoded credential at `high`, telling the reader to rotate a space.
      if (fallback !== undefined && literal.trim() === "") {
        suppressed.push({
          rule: RULE.composeDefaultCredentials,
          file,
          line: pair.line,
          reason: `\`${pair.name}=${value}\` defaults to ${literal === "" ? "the empty string" : "whitespace"}, which is how compose spells an optional variable rather than a baked-in credential`,
        });
        continue;
      }
      const weak = WEAK_VALUES.includes(literal.toLowerCase());
      findings.push(
        buildFinding({
          rule: RULE.composeDefaultCredentials,
          severity: "high",
          confidence: "high",
          title: weak
            ? `Service "${service.key}" uses the default credential \`${pair.name}=${literal}\``
            : `Service "${service.key}" hardcodes \`${pair.name}\``,
          description:
            fallback === undefined
              ? `\`${pair.name}\` is set to a literal value in ${file}, so the credential lives in the repository and in every checkout of it.`
              : `\`${pair.name}\` falls back to \`${literal}\` when the environment does not set it, so a deploy that forgets the variable silently ships a known credential.`,
          file,
          line: pair.line,
          symbol: `${service.key}:${pair.name}`,
          exploitability: weak
            ? "No exploitation needed: the value is one of the published defaults an attacker tries first against an exposed service."
            : "Anyone with read access to this repository, including its full git history.",
          impact: `Whatever ${pair.name} protects is accessible to anyone who reads this file; if the service is also published on a host interface, that is direct access from the network.`,
          recommendation:
            "Move the value into an environment file that is not committed (or the orchestrator's secret store), reference it as `${VAR}` with no fallback so a missing value fails the boot, and rotate the exposed credential.",
          acceptanceCriteria: [
            `${file} contains no literal credential values`,
            "Startup fails loudly when the credential variable is unset",
            "The exposed credential has been rotated",
          ],
          cwe: ["CWE-798", "CWE-1188"],
          owasp: ["A07:2021-Identification and Authentication Failures"],
          source: { kind: "rule", name: CONTAINER_RULES_STEP },
        }),
      );
    }

    // --- restart policy ----------------------------------------------------
    const restart = entryOf(node, "restart");
    const deployRestart = childOf(childOf(node, "deploy"), "restart_policy");
    if (restart === null && deployRestart === null) {
      findings.push(
        buildFinding({
          rule: RULE.composeNoRestart,
          severity: "low",
          confidence: "high",
          title: `Service "${service.key}" declares no \`restart:\` policy`,
          description: `"${service.key}" in ${file} uses the default \`no\` restart policy, so the container stays down after a crash or a host reboot until somebody notices.`,
          file,
          line: service.line,
          symbol: service.key,
          impact:
            "An unattended crash becomes an outage of unbounded length; the failure is silent because nothing tries to bring the service back.",
          recommendation:
            "Set `restart: unless-stopped` (or `on-failure` with a bounded retry count) on every long-running service, and pair it with a HEALTHCHECK so a wedged process is restarted too.",
          acceptanceCriteria: [
            `Every long-running service in ${file} declares a restart policy`,
            "A killed container comes back without manual intervention",
          ],
          source: { kind: "rule", name: CONTAINER_RULES_STEP },
        }),
      );
    }
  }

  return { findings, suppressed };
}

/** Lets the orchestrator hand in the file lists it discovered. */
export interface ContainerRulesOptions {
  /** Repo-relative Dockerfiles; defaults to the ones phase 0 proved. */
  readonly dockerfiles?: readonly string[] | undefined;
  /** Repo-relative compose files; defaults to the ones phase 0 proved. */
  readonly composeFiles?: readonly string[] | undefined;
  /**
   * Whether the repository compiles TypeScript, which is what turns a
   * single-stage build into a finding. Defaults to what the profile proves.
   */
  readonly buildsTypeScript?: boolean | undefined;
}

/**
 * Runs Sentinel's Dockerfile and docker-compose rules over the target. A file
 * that cannot be read or parsed degrades the step, it never throws.
 */
export async function runContainerRules(
  ctx: RunnerContext,
  options: ContainerRulesOptions = {},
): Promise<StepOutcome> {
  const startedAt = performance.now();
  const dockerfiles = [...new Set(options.dockerfiles ?? dockerfilesOf(ctx.profile))].sort();
  const composeFiles = [...new Set(options.composeFiles ?? composeFilesOf(ctx.profile))].sort();
  const typescript =
    options.buildsTypeScript ?? (ctx.profile === undefined ? false : buildsTypeScript(ctx.profile));

  if (dockerfiles.length === 0 && composeFiles.length === 0) {
    return skipped(
      CONTAINER_RULES_STEP,
      startedAt,
      "the target has no Dockerfile and no compose file",
    );
  }

  const findings: Finding[] = [];
  const suppressed: SuppressionNote[] = [];
  const notes: Array<string | null> = [];
  const unreadable: string[] = [];
  let scanned = 0;

  // A `.dockerignore` beside the Dockerfile wins; otherwise the repository root
  // is the build context, which is the layout every `docker build .` produces.
  const rootIgnore = await ctx.fs.exists(join(ctx.targetDir, ".dockerignore"));

  for (const file of dockerfiles) {
    let text: string;
    try {
      text = await ctx.fs.readFile(join(ctx.targetDir, file));
    } catch (cause) {
      unreadable.push(`${file} (${cause instanceof Error ? cause.message : String(cause)})`);
      continue;
    }
    const hasDockerignore =
      rootIgnore || (await ctx.fs.exists(join(ctx.targetDir, dirname(file), ".dockerignore")));
    scanned += 1;
    const analysis = analyseDockerfile(file, text, {
      hasDockerignore,
      buildsTypeScript: typescript,
    });
    findings.push(...analysis.findings);
    suppressed.push(...analysis.suppressed);
  }

  for (const file of composeFiles) {
    let text: string;
    try {
      text = await ctx.fs.readFile(join(ctx.targetDir, file));
    } catch (cause) {
      unreadable.push(`${file} (${cause instanceof Error ? cause.message : String(cause)})`);
      continue;
    }
    for (const error of parseYaml(text).errors) notes.push(`${file}: ${error}`);
    scanned += 1;
    const analysis = analyseCompose(file, text);
    findings.push(...analysis.findings);
    suppressed.push(...analysis.suppressed);
  }

  if (unreadable.length > 0) {
    notes.push(`could not read ${unreadable.join(", ")}`);
  }

  const verified = await verifyStepFindings(findings, ctx);
  if (verified.droppedFindings > 0) {
    notes.push(
      `${verified.droppedFindings} finding(s) cited a line Sentinel could not resolve on disk and were dropped`,
    );
  }

  const total = dockerfiles.length + composeFiles.length;
  // A withheld finding is an accounting line, not a degradation, so the status
  // is decided before the summary joins the reason.
  const status = notes.length === 0 ? "ok" : "degraded";
  return outcome(
    CONTAINER_RULES_STEP,
    status,
    joinReasons([
      `${scanned} of ${total} file(s) analysed (${dockerfiles.length} Dockerfile(s), ${composeFiles.length} compose file(s))`,
      ...notes,
      summariseSuppressions(suppressed),
    ]),
    verified.kept,
    [],
    startedAt,
  );
}

/** Every rule id this pack can emit, for the report's rule index. */
export const CONTAINER_RULE_IDS: readonly string[] = Object.values(RULE);
