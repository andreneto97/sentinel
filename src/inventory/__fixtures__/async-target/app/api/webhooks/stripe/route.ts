import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY ?? "");

/** Stripe receiver: raw body, signature verification and a replay tolerance. */
export async function POST(request: Request): Promise<Response> {
  const payload = await request.text();
  const signature = request.headers.get("stripe-signature") ?? "";
  const event = stripe.webhooks.constructEvent(
    payload,
    signature,
    process.env.STRIPE_WEBHOOK_SECRET ?? "",
    { tolerance: 300 },
  );
  await handle(event);
  return new Response("ok");
}

async function handle(event: { type: string }): Promise<void> {
  await fetch(`https://api.example.test/internal/stripe/${event.type}`, { method: "POST" });
}
