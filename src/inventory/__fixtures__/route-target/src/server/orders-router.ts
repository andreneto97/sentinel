/** A router whose handlers are imported one per file, so every registration is a single line. */

import express from "express";
import listOrders from "./orders/list.ts";
import removeOrder from "./orders/remove.ts";

/** The orders router, mounted below. */
export const orders = express.Router();

orders.get("/", listOrders);
orders.delete("/:orderId", removeOrder);

const app = express();
app.use("/api/orders", orders);
