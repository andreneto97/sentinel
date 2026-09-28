import Stripe from "stripe";
import type { Next, Req, Res } from "../../../support/http.ts";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY ?? "");

/** Stripe receiver: raw body, signature verification and a replay tolerance. */
export default async (req: Req, res: Res, next: Next) => {
  try {
    const signature = req.headers["stripe-signature"] ?? "";
    const event = stripe.webhooks.constructEvent(
      req.rawBody,
      signature,
      process.env.STRIPE_WEBHOOK_SECRET ?? "",
      { tolerance: 300 },
    );
    res.status(200).json({ received: event.type });
  } catch (error) {
    next(error);
  }
};
