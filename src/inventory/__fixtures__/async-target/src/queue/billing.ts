import { Inngest } from "inngest";

const inngest = new Inngest({ id: "billing" });

/** Charges a customer when the checkout event arrives. */
export const chargeCustomer = inngest.createFunction(
  { id: "charge-customer", retries: 4, concurrency: 2, idempotencyKey: "event.data.orderId" },
  { event: "checkout/completed" },
  async ({ event }: { event: { data: { orderId: string } } }): Promise<void> => {
    await charge(event.data.orderId);
  },
);

async function charge(orderId: string): Promise<void> {
  await fetch(`https://billing.example.test/charge/${orderId}`, { method: "POST" });
}
