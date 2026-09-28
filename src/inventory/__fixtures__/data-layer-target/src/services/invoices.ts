import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

/** One customer's invoices, projected and bounded. */
export async function invoicesFor(customerId: string) {
  return await prisma.invoice.findMany({
    where: { customerId },
    select: { id: true, total: true },
    take: 20,
  });
}

/** Every invoice, unbounded and unprojected. */
export async function allInvoices() {
  return await prisma.invoice.findMany({});
}

/** Creates the customer when it is missing. */
export async function ensureCustomer(id: string) {
  return await prisma.customer.upsert({ where: { id }, create: { id }, update: {} });
}

/** Totals, assembled as a string rather than bound. */
export async function totals(table: string) {
  return await prisma.$queryRawUnsafe(`SELECT * FROM ${table}`);
}
