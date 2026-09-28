-- Creates the billing tables.
CREATE TABLE "customers" (
    "id" uuid PRIMARY KEY,
    "email" text NOT NULL,
    "name" text,
    CONSTRAINT "customers_email_key" UNIQUE ("email")
);

CREATE TABLE "invoices" (
    "id" uuid PRIMARY KEY,
    "customer_id" uuid NOT NULL REFERENCES "customers" ("id") ON DELETE CASCADE,
    "total" integer NOT NULL,
    "issued_at" timestamp with time zone NOT NULL DEFAULT now()
);
