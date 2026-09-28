/** The OpenAPI description of the delivery format, which is prose, not code. */
export const webhookDocumentation = {
  summary: "Webhook subscriptions",
  description: `Every delivery includes an \`x-fleet-signature\` header holding an
HMAC-SHA256 of the raw JSON payload: \`sha256=HMAC-SHA256(signingSecret, rawBody)\`.
Always verify against the raw request body, not a re-serialised version.`,
};
