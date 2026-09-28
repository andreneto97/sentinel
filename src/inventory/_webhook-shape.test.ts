import { describe, expect, test } from "bun:test";
import {
  type ClassifiedCandidate,
  classifyWebhookCandidate,
  isWebhookCandidatePath,
  lineAt,
  reclassificationNote,
  signatureHeaderUse,
  stripProse,
} from "./_webhook-shape.ts";

/**
 * Every source below is a shape that shares a directory with a webhook receiver
 * without being one: a management endpoint, a router, an outbound sender, its
 * HTTP client, a domain module and an OpenAPI document.
 *
 * Each is written in the idiom the classifier has to read through rather than a
 * minimal one — multi-line imports, single quotes, no semicolons, header names
 * as quoted literals, prose inside a template literal — because every signal is
 * matched against text, and a fixture with the noise taken out would pass
 * patterns that a source file defeats. The bodies are trimmed to the lines the
 * classifier reads.
 */
const SHAPES = {
  /** `apps/dock-api/src/http/v1/webhooks/create-endpoint.ts` */
  management: `import { NextFunction, Request, Response } from 'express'
import { EndpointRegistry } from '@application/services'
import { hasOperatorPermissions, hasFleetScope, resolveActingMemberId } from '@application/authorization/helpers'

export default async (req: Request, res: Response, next: NextFunction) => {
  try {
    const isElevated = hasOperatorPermissions(req.auth) || hasFleetScope(req.auth)
    if (!isElevated && req.auth?.user?.type !== 'standard') {
      throw new Unauthorized('Only standard members can create webhooks')
    }
    const memberId = resolveActingMemberId(req)
    const registry = new EndpointRegistry()
    const data = await registry.create(body, { ...req.requestContext, memberId }, req.auth?.permissions ?? [])
    res.status(StatusCodes.CREATED).json(endpointSerializer(data))
  } catch (error) {
    next(error)
  }
}
`,

  /** `apps/dock-api/src/http/v1/webhooks/routes.ts` */
  router: `import { Router } from 'express'
import createEndpoint from './create-endpoint'
import listEndpoints from './list-endpoints'

export const api = Router({ mergeParams: true })

api.get('/', listEndpoints)
api.post('/', createEndpoint)
api.delete('/:id', removeEndpoint)
`,

  /** `libs/fleet-notify/webhooks/outbound-sender.ts` */
  delivery: `import { computeDeliverySignature } from '@shared/delivery-signature'

export class OutboundSender {
  private async executeRequest(data: DeliveryMessage, subscription: SubscriptionEntity) {
    const payloadJson = JSON.stringify(data.payload)
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'x-fleet-event': data.topic,
    }

    if (subscription.signingSecret) {
      headers['x-fleet-signature'] = computeDeliverySignature(payloadJson, subscription.signingSecret)
    }

    const response = await this.httpClient.post({
      endpoint: data.httpsEndpoint,
      payload: data.payload,
      headers,
      timeoutMs: config.DELIVERY_REQUEST_TIMEOUT_MS,
    })
    return DeliveryResult.fromResponse(response)
  }
}
`,

  /** `libs/fleet-notify/webhooks/http-delivery-client.ts` */
  httpClient: `import got from 'got'

export class HttpDeliveryClient implements DeliveryClient {
  async post(request: DeliveryRequest): Promise<DeliveryResponse> {
    const response = await got.post(request.endpoint, request.payload, {
      headers: request.headers,
      timeout: request.timeoutMs,
    })
    return { statusCode: response.status, body: response.data }
  }
}
`,

  /** `libs/fleet-domain/webhooks/topic-filters/condition-matchers.ts` */
  domain: `const strategies = new Map<string, MatcherCreator>([
  ['literal', (c) => new LiteralMatcher(c as string)],
  ['prefix', (c) => new PrefixMatcher((c as { prefix: string }).prefix)],
])

export const matcherFor = (condition: FilterCondition): ConditionMatcher => {
  const creator = strategies.get(discriminatorKey(condition))
  if (!creator) {
    throw new Error('Unknown filter condition')
  }
  return creator(condition)
}
`,

  /** `apps/dock-api/src/http/v1/docs/webhooks.ts` — prose, in a template literal. */
  openapi: `import { registry } from '../../openapi-registry'

registry.registerPath({
  method: 'post',
  path: '/webhooks',
  description: \`Every delivery includes an \\\`x-fleet-signature\\\` header with an
HMAC-SHA256 signature of the raw JSON payload: \\\`sha256=HMAC-SHA256(signingSecret, rawBody)\\\`.
Always verify against the raw request body, not a re-serialized version.\`,
})
`,
};

describe("isWebhookCandidatePath", () => {
  test("a webhook-shaped path is a candidate wherever it sits", () => {
    expect(isWebhookCandidatePath("apps/dock-api/src/http/v1/webhooks/create-endpoint.ts")).toBe(
      true,
    );
    expect(isWebhookCandidatePath("app/api/webhooks/stripe/route.ts")).toBe(true);
    expect(isWebhookCandidatePath("libs/fleet-domain/webhooks/subscription.entity.ts")).toBe(true);
  });

  test("`hooks/` and `callback/` count only inside an HTTP tree", () => {
    expect(isWebhookCandidatePath("apps/dock-api/src/http/hooks/stripe.ts")).toBe(true);
    expect(isWebhookCandidatePath("app/api/auth/callback/route.ts")).toBe(true);
    // A frontend has hundreds of these and not one of them answers a request.
    expect(isWebhookCandidatePath("src/hooks/use-cart.ts")).toBe(false);
    expect(isWebhookCandidatePath("libs/ui/hooks/use-subscription-status.ts")).toBe(false);
  });

  test("a name that merely contains the word is not a path", () => {
    expect(isWebhookCandidatePath("libs/fleet-shared/delivery-signature.ts")).toBe(false);
    expect(isWebhookCandidatePath("src/lib/db.ts")).toBe(false);
  });
});

describe("stripProse", () => {
  test("blanks comments and template prose, keeps quoted literals", () => {
    const stripped = stripProse(SHAPES.openapi);
    expect(stripped).not.toContain("rawBody");
    expect(stripped).not.toContain("HMAC-SHA256");
    // The quoted path and method are code the classifier still needs to read.
    expect(stripped).toContain("'/webhooks'");
    expect(stripped).toContain("'post'");
  });

  test("keeps every offset, so a line number survives the pass", () => {
    const source = "const a = 1; // stripe-signature\nconst b = 'x-hub-signature';\n";
    const stripped = stripProse(source);
    expect(stripped).toHaveLength(source.length);
    expect(lineAt(stripped, stripped.indexOf("x-hub-signature"))).toBe(2);
    expect(stripped).not.toContain("stripe-signature");
  });

  test("code inside a template substitution is not prose", () => {
    const stripped = stripProse("const u = `a ${req.headers['x-signature']} b`;\n");
    expect(stripped).toContain("req.headers['x-signature']");
    expect(stripped).not.toContain("a $");
  });

  test("a block comment that mentions a verify call is not a verify call", () => {
    const stripped = stripProse("/* we should call stripe.webhooks.constructEvent() */\nrun();\n");
    expect(stripped).not.toContain("constructEvent");
    expect(stripped).toContain("run();");
  });
});

describe("signatureHeaderUse", () => {
  test("separates reading the header from writing it", () => {
    const read = signatureHeaderUse("const s = req.headers['x-hub-signature-256']");
    expect(read.read?.token).toBe("the x-hub-signature-256 header");
    expect(read.write).toBeNull();

    // A delivery service writes the header instead of reading one: it signs.
    const write = signatureHeaderUse(
      "headers['x-fleet-signature'] = computeDeliverySignature(payloadJson, subscription.signingSecret)",
    );
    expect(write.read).toBeNull();
    expect(write.write?.token).toBe("the x-fleet-signature header");
  });

  test("reads the framework accessors as well as the index", () => {
    expect(signatureHeaderUse(`request.headers.get("stripe-signature")`).read).not.toBeNull();
    expect(signatureHeaderUse("req.get('X-Shopify-Hmac-Sha256')").read).not.toBeNull();
  });

  test("a header that is not a signature is not one", () => {
    expect(signatureHeaderUse("req.headers['x-fleet-operator-id']").read).toBeNull();
    expect(
      signatureHeaderUse("showSensitiveAttr: { webhooks: ['signingSecret'] }").read,
    ).toBeNull();
  });
});

describe("classifyWebhookCandidate, over the workspace shapes above", () => {
  test("an authenticated CRUD handler is management, not a receiver", () => {
    const shape = classifyWebhookCandidate({
      file: "apps/dock-api/src/http/v1/webhooks/create-endpoint.ts",
      text: SHAPES.management,
    });
    expect(shape.role).toBe("management");
    expect(shape.evidence).toContain("the caller's own session read off the request");
    expect(shape.facts).toBeUndefined();
  });

  test("a router module is management: the route inventory owns its registrations", () => {
    const shape = classifyWebhookCandidate({
      file: "apps/dock-api/src/http/v1/webhooks/routes.ts",
      text: SHAPES.router,
    });
    expect(shape.role).toBe("management");
    expect(shape.evidence).toContain("router module");
  });

  test("the outbound sender is outbound, and its createHmac is not verification", () => {
    const shape = classifyWebhookCandidate({
      file: "libs/fleet-notify/webhooks/outbound-sender.ts",
      text: SHAPES.delivery,
    });
    expect(shape.role).toBe("outbound");
    expect(shape.evidence).toBe("a request built around a stored endpoint");
    // The signature header appears in this file, written rather than read; the
    // version that looked only for the name called this a verified receiver.
    expect(signatureHeaderUse(SHAPES.delivery).read).toBeNull();
  });

  test("the HTTP delivery client is outbound", () => {
    const shape = classifyWebhookCandidate({
      file: "libs/fleet-notify/webhooks/http-delivery-client.ts",
      text: SHAPES.httpClient,
    });
    expect(shape.role).toBe("outbound");
    expect(shape.evidence).toBe("an HTTP client call");
  });

  test("`strategies.get(key)` in a domain module is not an HTTP entry point", () => {
    const shape = classifyWebhookCandidate({
      file: "libs/fleet-domain/webhooks/topic-filters/condition-matchers.ts",
      text: SHAPES.domain,
    });
    expect(shape.role).toBe("inert");
  });

  test("an OpenAPI document that describes a signature is not a receiver", () => {
    const shape = classifyWebhookCandidate({
      file: "apps/dock-api/src/http/v1/docs/webhooks.ts",
      text: SHAPES.openapi,
    });
    expect(shape.role).toBe("inert");
  });
});

describe("classifyWebhookCandidate, on receivers", () => {
  const stripeReceiver = `import Stripe from 'stripe'

export default async (req: Request, res: Response, next: NextFunction) => {
  const signature = req.headers['stripe-signature'] as string
  const event = stripe.webhooks.constructEvent(req.rawBody, signature, secret, { tolerance: 300 })
  res.status(200).json({ received: event.type })
}
`;

  test("a verified receiver carries what it verifies and how", () => {
    const shape = classifyWebhookCandidate({
      file: "apps/dock-api/src/http/v1/webhooks/inbound-events.ts",
      text: stripeReceiver,
    });
    expect(shape.role).toBe("receiver");
    expect(shape.facts).toMatchObject({
      signatureVerified: "yes",
      usesRawBody: "yes",
      replayProtection: "yes",
      verification: "constructEvent()",
    });
    // The citation is the proof; the symbol comes from the boundary above it.
    expect(shape.line).toBe(4);
    expect(shape.boundaryLine).toBe(3);
  });

  test("an unverified receiver is still a receiver — that is the finding", () => {
    const shape = classifyWebhookCandidate({
      file: "app/api/hooks/partner/route.ts",
      text: `export async function POST(request: Request): Promise<Response> {
  const body = await request.json()
  await record(body)
  return new Response('ok')
}
`,
    });
    expect(shape.role).toBe("receiver");
    expect(shape.facts).toMatchObject({
      signatureVerified: "no",
      usesRawBody: "no",
      replayProtection: "no",
      verification: "none",
    });
  });

  test("a provider verification call decides it even outside an HTTP file", () => {
    const shape = classifyWebhookCandidate({
      file: "libs/webhooks/verify.ts",
      text: "export const verified = (p, s) => stripe.webhooks.constructEvent(p, s, secret)\n",
      providerCall: {
        provider: "stripe",
        line: 1,
        call: "stripe.webhooks.constructEvent(p, s, secret)",
      },
    });
    expect(shape.role).toBe("receiver");
    expect(shape.evidence).toContain("a stripe verification call");
    expect(shape.line).toBe(1);
  });

  test("a hand-rolled digest counts only where a signature header is read", () => {
    const compared = classifyWebhookCandidate({
      file: "app/api/webhooks/partner/route.ts",
      text: `export async function POST(req, res) {
  const expected = createHmac('sha256', secret).update(req.rawBody).digest('hex')
  if (expected !== req.headers['x-partner-signature']) return res.status(401).end()
  return res.status(200).end()
}
`,
    });
    expect(compared.facts?.signatureVerified).toBe("yes");

    const signedOnly = classifyWebhookCandidate({
      file: "app/api/webhooks/partner/route.ts",
      text: `export async function POST(req, res) {
  const digest = createHmac('sha256', secret).update(req.rawBody).digest('hex')
  await send(digest)
  return res.status(200).end()
}
`,
    });
    expect(signedOnly.facts?.signatureVerified).toBe("no");
  });
});

describe("reclassificationNote", () => {
  /** One classified candidate, with only the fields the note reads. */
  function entry(file: string, role: ClassifiedCandidate["shape"]["role"]): ClassifiedCandidate {
    return {
      file,
      shape: { role, evidence: "e", line: 7, boundaryLine: undefined, facts: undefined },
    };
  }

  test("names the destination and cites the evidence", () => {
    const note = reclassificationNote(
      [
        entry("apps/dock-api/src/http/v1/webhooks/create-endpoint.ts", "management"),
        entry("apps/dock-api/src/http/v1/webhooks/routes.ts", "management"),
        entry("libs/fleet-notify/webhooks/http-delivery-client.ts", "outbound"),
        entry("libs/fleet-domain/webhooks/subscription.entity.ts", "inert"),
      ],
      32,
    );
    expect(note).toContain("4 files under a webhook-shaped path");
    expect(note).toContain("2 are webhook-subscription management endpoints");
    expect(note).toContain("apps/dock-api/src/http/v1/webhooks/create-endpoint.ts:7");
    expect(note).toContain("1 is outbound delivery code");
    expect(note).toContain("this repository has no inbound webhook receiver");
    expect(note).toContain("32 further candidates are outside production code");
  });

  test("stops naming citations after four, and says how many it did not name", () => {
    const many = Array.from({ length: 11 }, (_, index) =>
      entry(`apps/dock-api/src/http/v1/webhooks/h${index}.ts`, "management"),
    );
    const note = reclassificationNote(many, 0);
    expect(note).toContain("and 7 more");
    expect(note).not.toContain("outside production code");
  });

  test("says so when every candidate is outside production code", () => {
    const note = reclassificationNote(
      [entry("apps/dock-api/src/http/v1/webhooks/create-endpoint.test.ts", "inert")],
      1,
    );
    expect(note).toBe(
      "1 candidate under a webhook-shaped path is outside production code, and no production file sits on one",
    );
  });

  test("says nothing when every candidate is a receiver", () => {
    expect(
      reclassificationNote([entry("app/api/webhooks/stripe/route.ts", "receiver")], 0),
    ).toBeUndefined();
  });

  test("counts only production candidates, and says how many it left out", () => {
    const note = reclassificationNote(
      [
        entry("apps/dock-api/src/http/v1/webhooks/create-endpoint.ts", "management"),
        entry("apps/dock-api/src/http/v1/webhooks/create-endpoint.test.ts", "inert"),
      ],
      1,
    );
    expect(note).toContain("1 file under a webhook-shaped path");
    expect(note).toContain("1 is a webhook-subscription management endpoint");
    expect(note).toContain("1 further candidate is outside production code");
  });
});
