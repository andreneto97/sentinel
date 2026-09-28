-- Creates the two tables the fixture's queries read, and takes a lock doing it.
CREATE TABLE orders (
  id uuid PRIMARY KEY,
  org_id uuid NOT NULL,
  customer_id uuid NOT NULL,
  total numeric NOT NULL DEFAULT 0
);

CREATE TABLE invoices (
  id uuid PRIMARY KEY,
  org_id uuid NOT NULL,
  number text NOT NULL
);

CREATE INDEX orders_org_id_idx ON orders (org_id);

ALTER TABLE invoices ADD COLUMN paid_at timestamp NOT NULL DEFAULT now();
