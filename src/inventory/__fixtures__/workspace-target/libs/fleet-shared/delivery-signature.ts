import { createHmac } from "node:crypto";

/** Signs an outgoing delivery; the same primitive a receiver would verify with. */
export function computeDeliverySignature(payloadJson: string, secret: string): string {
  return `sha256=${createHmac("sha256", secret).update(payloadJson).digest("hex")}`;
}
