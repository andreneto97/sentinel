-- Removes the legacy column and backfills the replacement.
UPDATE "customers" SET "name" = "legacy_name" WHERE "name" IS NULL;

ALTER TABLE "customers" DROP COLUMN "legacy_name";
