-- Adds a required column, an index and row level security.
ALTER TABLE "invoices" ADD COLUMN "organization_id" uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';

CREATE INDEX "invoices_customer_id_idx" ON "invoices" ("customer_id");

ALTER TABLE "invoices" ENABLE ROW LEVEL SECURITY;

CREATE POLICY "invoices_read_own" ON "invoices" FOR SELECT USING (customer_id = auth.uid());
