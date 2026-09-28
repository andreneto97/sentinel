import type { Confidence } from "../contracts/findings.ts";
import type { DetectedFact } from "../contracts/profile.ts";
import type { DetectionContext } from "./detector.ts";
import { type DetectionResult, type Probe, ref } from "./fact-builder.ts";
import { type DependencySignal, factsFromDependencies, signalLabels } from "./manifest.ts";
import type { RepoSnapshot } from "./repo-snapshot.ts";
import { importPattern } from "./text.ts";

/** ORMs, query builders and drivers, each proven by a declared dependency. */
export const DATA_LAYER_SIGNALS: readonly DependencySignal[] = [
  { value: "prisma", packages: ["@prisma/client", "prisma"] },
  { value: "drizzle", packages: ["drizzle-orm", "drizzle-kit"] },
  { value: "typeorm", packages: ["typeorm"] },
  { value: "sequelize", packages: ["sequelize"] },
  { value: "knex", packages: ["knex"] },
  { value: "mongoose", packages: ["mongoose"] },
  { value: "supabase", packages: ["@supabase/supabase-js", "@supabase/ssr"] },
  { value: "kysely", packages: ["kysely"] },
  { value: "pg", packages: ["pg", "pg-promise"] },
  { value: "postgres-js", packages: ["postgres"] },
  { value: "mysql2", packages: ["mysql2", "mysql"] },
  { value: "mongodb", packages: ["mongodb"] },
  { value: "better-sqlite3", packages: ["better-sqlite3"] },
];

/** Drivers whose mere presence names the engine they talk to. */
const DRIVER_ENGINES: Readonly<Record<string, string>> = {
  pg: "postgresql",
  "postgres-js": "postgresql",
  mysql2: "mysql",
  mongodb: "mongodb",
  mongoose: "mongodb",
  "better-sqlite3": "sqlite",
};

/** Connection-string schemes and the engine each one names. */
const CONNECTION_SCHEMES: ReadonlyArray<{ readonly scheme: string; readonly engine: string }> = [
  { scheme: "postgresql://", engine: "postgresql" },
  { scheme: "postgres://", engine: "postgresql" },
  { scheme: "mysql://", engine: "mysql" },
  { scheme: "mariadb://", engine: "mysql" },
  { scheme: "mongodb+srv://", engine: "mongodb" },
  { scheme: "mongodb://", engine: "mongodb" },
  { scheme: "sqlserver://", engine: "mssql" },
  { scheme: "redis://", engine: "redis" },
];

/** Container images that name a database engine when they appear in a compose file. */
const COMPOSE_IMAGE_ENGINES: ReadonlyArray<{ readonly image: RegExp; readonly engine: string }> = [
  { image: /\b(postgres|postgis)\b/, engine: "postgresql" },
  { image: /\b(mysql|mariadb)\b/, engine: "mysql" },
  { image: /\bmongo\b/, engine: "mongodb" },
  { image: /\bredis\b/, engine: "redis" },
  { image: /mssql|sqlserver/, engine: "mssql" },
];

const PRISMA_PROVIDERS: Readonly<Record<string, string>> = {
  postgresql: "postgresql",
  postgres: "postgresql",
  mysql: "mysql",
  sqlite: "sqlite",
  sqlserver: "mssql",
  mongodb: "mongodb",
  cockroachdb: "postgresql",
};

/** Compose files, where a database service image is often the only proof of the engine. */
export function composeFiles(snapshot: RepoSnapshot): string[] {
  return snapshot.filesMatching(/(^|\/)(docker-)?compose([.-][\w.-]+)?\.ya?ml$/);
}

/** Dotenv-style files; only key names and connection-string *schemes* are ever read from them. */
export function envFiles(snapshot: RepoSnapshot): string[] {
  return snapshot.filesMatching(/(^|\/)\.env(\.[\w.-]+)?$/);
}

function engineFact(
  engine: string,
  confidence: Confidence,
  detail: string,
  file: string,
  line: number,
): DetectedFact {
  return {
    kind: "database-engine",
    value: engine,
    confidence,
    detail,
    evidence: [ref(file, line, detail)],
  };
}

async function detectSchemaFiles(context: DetectionContext): Promise<DetectedFact[]> {
  const { snapshot } = context;
  const facts: DetectedFact[] = [];
  for (const file of snapshot.filesMatching(/\.prisma$/).slice(0, 10)) {
    facts.push({
      kind: "db-schema-file",
      value: file,
      confidence: "high",
      detail: "prisma schema",
      evidence: [ref(file, 1)],
    });
  }
  const drizzleSchemas = await snapshot.grep(importPattern("drizzle-orm"), { limit: 200 });
  const drizzleTables = await snapshot.grep(/\b(pgTable|mysqlTable|sqliteTable)\s*\(/, {
    files: [...new Set(drizzleSchemas.map((hit) => hit.file))],
    limit: 50,
  });
  for (const hit of drizzleTables.slice(0, 10)) {
    facts.push({
      kind: "db-schema-file",
      value: hit.file,
      confidence: "high",
      detail: "drizzle table definition",
      evidence: [ref(hit.file, hit.line)],
    });
  }
  const mongooseSchemas = await snapshot.grep(/new\s+(?:mongoose\.)?Schema\s*\(/, { limit: 50 });
  for (const hit of mongooseSchemas.slice(0, 10)) {
    facts.push({
      kind: "db-schema-file",
      value: hit.file,
      confidence: "high",
      detail: "mongoose schema",
      evidence: [ref(hit.file, hit.line)],
    });
  }
  const entities = await snapshot.grep(/@Entity\s*\(/, { limit: 50 });
  for (const hit of entities.slice(0, 10)) {
    facts.push({
      kind: "db-schema-file",
      value: hit.file,
      confidence: "high",
      detail: "typeorm entity",
      evidence: [ref(hit.file, hit.line)],
    });
  }
  for (const file of snapshot.filesMatching(/(^|\/)knexfile\.(m|c)?(j|t)s$/).slice(0, 5)) {
    facts.push({
      kind: "db-schema-file",
      value: file,
      confidence: "high",
      detail: "knex configuration",
      evidence: [ref(file, 1)],
    });
  }
  for (const file of snapshot.filesMatching(/(^|\/)drizzle\.config\.(m|c)?(j|t)s$/).slice(0, 5)) {
    facts.push({
      kind: "db-schema-file",
      value: file,
      confidence: "high",
      detail: "drizzle configuration",
      evidence: [ref(file, 1)],
    });
  }
  return facts;
}

/** Extensions a migration is actually written in; anything else is bookkeeping. */
const MIGRATION_FILE_RE = /\.(sql|ts|js|mjs|cjs|rb|py|php)$/i;

function detectMigrationDirs(snapshot: RepoSnapshot): DetectedFact[] {
  // The count matters as much as the directory: "84 migrations found" is what
  // the scope proposal offers to analyse in depth.
  const byDirectory = new Map<string, { first: string; count: number }>();
  const record = (directory: string, file: string): void => {
    const current = byDirectory.get(directory);
    if (current === undefined) byDirectory.set(directory, { first: file, count: 1 });
    else current.count += 1;
  };
  for (const file of snapshot.files) {
    const segments = file.split("/");
    // The segment has to *be* `migrations`; `mymigrations/` is a different thing.
    const index = segments.indexOf("migrations");
    if (index === -1 || index === segments.length - 1) continue;
    const rest = segments.slice(index + 1);
    // Only the migrations themselves count. A tool's bookkeeping — Drizzle's
    // `meta/*_snapshot.json`, `meta/_journal.json` — would otherwise inflate
    // the number the scope proposal offers to analyse in depth: 8 migrations
    // with 6 snapshots beside them is not "14 migrations".
    if (rest.includes("meta")) continue;
    const name = rest[rest.length - 1] ?? "";
    if (!MIGRATION_FILE_RE.test(name)) continue;
    record(segments.slice(0, index + 1).join("/"), file);
  }
  // Drizzle names its migration folder after the config, but always drops a
  // journal in `meta/`, which is unambiguous.
  for (const journal of snapshot.filesNamed("_journal.json")) {
    const directory = journal.replace(/\/meta\/_journal\.json$/, "");
    if (directory !== journal && !byDirectory.has(directory)) record(directory, journal);
  }
  return [...byDirectory.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .slice(0, 10)
    .map(([directory, found]) => ({
      kind: "migrations-dir" as const,
      value: directory,
      confidence: "high" as const,
      detail: `${found.count} migration(s)`,
      evidence: [ref(found.first, 1, "first file in the directory")],
    }));
}

async function detectEngine(context: DetectionContext): Promise<DetectedFact[]> {
  const { snapshot } = context;
  const facts: DetectedFact[] = [];

  const prismaFiles = snapshot.filesMatching(/\.prisma$/);
  const providerHits = await snapshot.grep(/provider\s*=\s*"([\w-]+)"/, {
    files: prismaFiles,
    limit: 20,
  });
  for (const hit of providerHits) {
    const provider = /provider\s*=\s*"([\w-]+)"/.exec(hit.text)?.[1];
    // The generator block uses `provider` too, but never with a database name.
    const engine = provider === undefined ? undefined : PRISMA_PROVIDERS[provider];
    if (engine === undefined) continue;
    facts.push(
      engineFact(engine, "high", `prisma datasource provider "${provider}"`, hit.file, hit.line),
    );
  }

  const configFiles = snapshot.filesMatching(
    /(^|\/)(drizzle\.config|knexfile|ormconfig|data-source)\.(m|c)?(j|t)s$/,
  );
  const dialectHits = await snapshot.grep(/(?:dialect|client|type)\s*:\s*['"]([\w-]+)['"]/, {
    files: configFiles,
    limit: 20,
  });
  const DIALECTS: Readonly<Record<string, string>> = {
    postgresql: "postgresql",
    postgres: "postgresql",
    pg: "postgresql",
    "better-sqlite": "sqlite",
    sqlite: "sqlite",
    sqlite3: "sqlite",
    "better-sqlite3": "sqlite",
    mysql: "mysql",
    mysql2: "mysql",
    mariadb: "mysql",
    mssql: "mssql",
    mongodb: "mongodb",
  };
  for (const hit of dialectHits) {
    const dialect = /(?:dialect|client|type)\s*:\s*['"]([\w-]+)['"]/.exec(hit.text)?.[1];
    const engine = dialect === undefined ? undefined : DIALECTS[dialect];
    if (engine === undefined) continue;
    facts.push(engineFact(engine, "high", `configured dialect "${dialect}"`, hit.file, hit.line));
  }

  const compose = composeFiles(snapshot);
  const imageHits = await snapshot.grep(/^\s*image\s*:\s*['"]?([^\s'"]+)/, {
    files: compose,
    limit: 40,
  });
  for (const hit of imageHits) {
    const image = /^\s*image\s*:\s*['"]?([^\s'"]+)/.exec(hit.text)?.[1];
    if (image === undefined) continue;
    for (const candidate of COMPOSE_IMAGE_ENGINES) {
      if (!candidate.image.test(image)) continue;
      facts.push(
        engineFact(candidate.engine, "high", `compose service image ${image}`, hit.file, hit.line),
      );
    }
  }

  // Connection strings: only the scheme is ever recorded, never the value.
  const stringFiles = [...envFiles(snapshot), ...compose, ...snapshot.sourceFiles()];
  const schemeHits = await snapshot.grep(
    /\b(postgresql|postgres|mysql|mariadb|mongodb\+srv|mongodb|sqlserver|redis):\/\//,
    { files: stringFiles, limit: 60 },
  );
  for (const hit of schemeHits) {
    const matched = CONNECTION_SCHEMES.find((candidate) => hit.text.includes(candidate.scheme));
    if (matched === undefined) continue;
    facts.push(
      engineFact(
        matched.engine,
        "medium",
        `connection string scheme ${matched.scheme}`,
        hit.file,
        hit.line,
      ),
    );
  }

  return facts;
}

/** Detects the ORM/driver, schema files, migration directories and the database engine. */
export async function detectDataLayer(context: DetectionContext): Promise<DetectionResult> {
  const { manifests, snapshot } = context;
  const layerFacts = factsFromDependencies(manifests, "data-layer", DATA_LAYER_SIGNALS);
  const facts: DetectedFact[] = [...layerFacts];

  for (const layer of layerFacts) {
    const engine = DRIVER_ENGINES[layer.value];
    if (engine === undefined) continue;
    const first = layer.evidence[0];
    if (first === undefined) continue;
    facts.push(
      engineFact(engine, "high", `${layer.value} driver dependency`, first.file, first.line),
    );
  }

  facts.push(...(await detectSchemaFiles(context)));
  facts.push(...detectMigrationDirs(snapshot));
  facts.push(...(await detectEngine(context)));

  const warnings: string[] = [];
  if (layerFacts.length > 1) {
    const layers = [...new Set(layerFacts.map((f) => f.value))].sort();
    if (layers.length > 2) {
      warnings.push(
        `${layers.length} data-access libraries coexist (${layers.join(", ")}); the data-layer audit will have to cover all of them.`,
      );
    }
  }

  const probes: Probe[] = [
    { kind: "data-layer", searched: signalLabels(DATA_LAYER_SIGNALS) },
    {
      kind: "db-schema-file",
      searched: ["*.prisma", "drizzle *Table()", "new Schema()", "@Entity()", "knexfile.*"],
    },
    { kind: "migrations-dir", searched: ["**/migrations/**", "**/meta/_journal.json"] },
    {
      kind: "database-engine",
      searched: [
        "prisma datasource provider",
        "drizzle/knex/typeorm dialect",
        "compose service images",
        "connection string schemes",
      ],
      note: "Only proven engines are reported; a driver dependency alone names the engine, a hostname does not.",
    },
  ];

  return { facts, probes, warnings };
}
