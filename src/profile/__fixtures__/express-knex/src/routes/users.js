const express = require("express");
const { requireAuth } = require("../middleware/auth");

const router = express.Router();

router.get("/users", requireAuth, async (req, res) => {
  const rows = await req.db("users").select("*");
  res.json(rows);
});

router.post("/users", requireAuth, async (req, res) => {
  const [id] = await req.db("users").insert(req.body);
  res.status(201).json({ id });
});

module.exports = router;
