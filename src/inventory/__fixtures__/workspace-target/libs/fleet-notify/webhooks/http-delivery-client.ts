import got from "got";

/** One outbound delivery request. */
export interface DeliveryRequest {
  readonly endpoint: string;
  readonly payload: unknown;
  readonly headers: Record<string, string>;
  readonly timeoutMs: number;
}

/** Performs the delivery. Outbound: there is nothing here to verify. */
export class HttpDeliveryClient {
  async post(delivery: DeliveryRequest): Promise<{ statusCode: number }> {
    const sent = await got.post(delivery.endpoint, {
      json: delivery.payload,
      headers: delivery.headers,
      timeout: { request: delivery.timeoutMs },
    });
    return { statusCode: sent.statusCode };
  }
}
