/** One registered delivery endpoint, reduced to what the fixture needs. */
export interface DeliveryEndpoint {
  readonly id: string;
  readonly httpsEndpoint: string;
  readonly signingSecret: string;
}

/** The CRUD surface a management endpoint writes through. */
export class EndpointRegistry {
  async create(body: unknown, context: { readonly memberId: number }): Promise<DeliveryEndpoint> {
    return { id: `${context.memberId}`, httpsEndpoint: String(body), signingSecret: "s" };
  }

  async listFor(memberId: number): Promise<readonly DeliveryEndpoint[]> {
    return [{ id: `${memberId}`, httpsEndpoint: "", signingSecret: "s" }];
  }

  async rotateSecret(id: string, memberId: number): Promise<DeliveryEndpoint> {
    return { id, httpsEndpoint: "", signingSecret: `${memberId}` };
  }
}
