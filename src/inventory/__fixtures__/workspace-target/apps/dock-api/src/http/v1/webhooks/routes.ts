import { Router } from "express";
import createEndpoint from "./create-endpoint.ts";
import inboundEvents from "./inbound-events.ts";
import listEndpoints from "./list-endpoints.ts";
import rotateSecret from "./rotate-secret.ts";

export const api = Router({ mergeParams: true });

api.post("/", createEndpoint);
api.get("/", listEndpoints);
api.post("/:id/secret", rotateSecret);
api.post("/deliveries", inboundEvents);
