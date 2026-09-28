/**
 * The migration prompt (D3, migrations).
 *
 * A migration is audited for what it will do to a table that already has rows in
 * it, which is the part a schema linter never sees. The inventory has already
 * replayed the history and recorded what each file does (`destructive`,
 * `lockRisk`, `hasDownMigration`, `mixesDataAndSchema`); the prompt asks the
 * model to read the statements and say what that means for a production
 * deployment — which lock is taken, for how long, and what happens if the deploy
 * is rolled back halfway.
 */

import { type AuditCheck, type PromptSpec, createPromptBuilder } from "./_shared.ts";

/** The D3 questions asked of every migration. */
export const MIGRATION_CHECKS: readonly AuditCheck[] = [
  {
    name: "destructive-safety",
    statement: "no migration drops or rewrites data without preserving it first",
    rule: "data.destructive-migration",
    question:
      "if this migration drops or rewrites data, is the data preserved or provably unused first?",
    fails:
      "a column or table is dropped, or a type is narrowed, with no preceding step that copies the data out and no evidence that it is unused",
    ceiling: "high",
    notApplicable: "the migration only adds",
  },
  {
    name: "lock-safety",
    statement: "migrations run without taking a long lock on a live table",
    rule: "data.locking-migration",
    question:
      "can this migration run against a large, live table without blocking reads or writes for long?",
    fails:
      "the migration adds a `NOT NULL` column with a computed default, creates an index without `CONCURRENTLY`, adds a foreign key or a check without `NOT VALID`, or changes a type in a way that rewrites the table",
    ceiling: "high",
    notApplicable: "the statements take no lock that blocks other sessions",
  },
  {
    name: "rollback-path",
    statement: "every migration has a rollback path",
    rule: "data.migration-without-rollback",
    question: "is there a way back from this migration that does not lose data?",
    fails:
      "the migration has no down step, or a down step that cannot restore what the up step destroyed",
    ceiling: "medium",
    notApplicable:
      "the migration tool in use does not have down migrations: say so rather than reporting it",
  },
  {
    name: "data-and-schema-separation",
    statement: "schema changes and backfills are separate migrations",
    rule: "data.migration-mixes-data-and-schema",
    question: "does this migration change the schema and backfill data in one step?",
    fails:
      "a schema change and a row-touching backfill are in the same transaction, so a slow backfill holds the schema lock",
    ceiling: "medium",
    notApplicable: "the migration does one or the other",
  },
  {
    name: "constraint-integrity",
    statement: "relationships and uniqueness are enforced by the database",
    rule: "data.missing-constraint",
    question:
      "do the relationships and uniqueness this migration creates exist in the database, rather than only in the application?",
    fails:
      "a column that references another table has no foreign key, a get-or-create is not protected by a unique constraint, or a status column is free `text` where a check or an enum belongs",
    ceiling: "medium",
    notApplicable: "the migration creates no relationship and no uniqueness requirement",
  },
  {
    name: "index-coverage",
    statement: "every foreign key is indexed on the referencing side",
    rule: "data.missing-index-on-fk",
    question: "does every foreign key this migration adds have an index on the referencing side?",
    fails: "a foreign key column has no index, so a delete of the parent row scans the child table",
    ceiling: "medium",
    notApplicable: "the migration adds no foreign key",
  },
  {
    name: "row-level-security",
    statement: "tables a client can reach have row-level security with policies",
    rule: "data.rls-without-policy",
    question:
      "if the table is exposed to a client through row-level security, is RLS both enabled and given a policy?",
    fails:
      "the migration creates a table reachable by an anonymous or authenticated database role without enabling RLS, or enables RLS and never adds a policy",
    ceiling: "critical",
    notApplicable:
      "the engine is not Postgres, or nothing but the application's own role reaches the table",
  },
  {
    name: "secrets-and-seed-data",
    statement: "migrations carry no credentials and no production data",
    rule: "appsec.hardcoded-credential",
    question: "is this migration free of real credentials and real personal data?",
    fails:
      "a password hash, an API key, a token, a real email address or a production row is written by the migration or its seed",
    ceiling: "critical",
    notApplicable: "the migration writes no rows",
  },
];

/** How to read the facts the migration enumerator attaches to a unit. */
const MIGRATION_ATTRIBUTES: Readonly<Record<string, string>> = {
  tool: "the migration tool the file belongs to",
  ordinal: "position in the replayed history, counting from 1",
  version: "the version or timestamp in the file name",
  operations: "the SQL operations Sentinel parsed out of the file",
  destructive: "`true` when one of those operations drops or rewrites",
  lockRisk: "the worst lock Sentinel could attribute to the statements",
  hasDownMigration: "`true` when a down or rollback step exists",
  mixesDataAndSchema: "`true` when the file both changes the schema and touches rows",
  tables: "the tables the statements name",
  statements: "how many statements the file contains",
};

/** The migration prompt spec. */
export const MIGRATION_PROMPT: PromptSpec = {
  kind: "migration",
  noun: "migration",
  mission:
    "You decide what each migration will do to a table that is already large and already serving traffic, and whether the schema it leaves behind can hold the invariants the application assumes.",
  checks: MIGRATION_CHECKS,
  attributes: MIGRATION_ATTRIBUTES,
  guidance: [
    "Judge the migration against a table with rows in it. A statement that is instant on an empty table and takes an exclusive lock for minutes on a large one is a finding, and the recommendation is the safe rewrite of that statement.",
    "`lockRisk` and `operations` were parsed by Sentinel. If the slice shows a statement those facts do not mention, trust the slice and say so.",
    "A recommendation here is a concrete statement sequence — add nullable, backfill in batches, set `NOT NULL` with a validated check — not the advice to be careful.",
    "The engine matters: `CONCURRENTLY`, `NOT VALID` and row-level security are Postgres. Read the engine off the stack facts before requiring any of them.",
    "Ordering is part of the audit: a migration whose version sits before one that is already deployed will not run in order on every environment.",
  ],
};

/** The migration prompt builder. */
export const migrationPromptBuilder = createPromptBuilder(MIGRATION_PROMPT);
