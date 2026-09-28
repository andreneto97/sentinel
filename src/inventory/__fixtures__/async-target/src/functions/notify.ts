import * as functions from "firebase-functions";

/** Public HTTPS function: no authentication, 540s timeout, 1GB of memory. */
export const notify = functions
  .runWith({ memory: "1GB", timeoutSeconds: 540 })
  .https.onRequest(async (request: { body: unknown }, response: { json(body: unknown): void }) => {
    response.json({ received: request.body });
  });
