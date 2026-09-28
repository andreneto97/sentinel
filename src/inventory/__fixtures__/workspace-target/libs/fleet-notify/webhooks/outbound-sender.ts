import { computeDeliverySignature } from "../../fleet-shared/delivery-signature.ts";
import type { HttpDeliveryClient } from "./http-delivery-client.ts";

/** One delivery the worker takes off its queue. */
export interface DeliveryMessage {
  readonly topic: string;
  readonly payload: unknown;
  readonly httpsEndpoint: string;
  readonly signingSecret: string;
}

/** Builds and signs an outgoing delivery: timeouts and retries, not signatures. */
export class OutboundSender {
  constructor(private readonly httpClient: HttpDeliveryClient) {}

  async send(data: DeliveryMessage): Promise<{ statusCode: number }> {
    const payloadJson = JSON.stringify(data.payload);
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "x-fleet-event": data.topic,
    };
    headers["x-fleet-signature"] = computeDeliverySignature(payloadJson, data.signingSecret);

    return this.httpClient.post({
      endpoint: data.httpsEndpoint,
      payload: data.payload,
      headers,
      timeoutMs: 5_000,
    });
  }
}
