const express = require("express");
const router = express.Router();
const Risk = require("../models/Risks");

// ✅ GET all risks
router.get("/", async (req, res) => {
  try {
    const risks = await Risk.find();
    res.json(risks);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch risks" });
  }
});

// ✅ GET risk by ID
router.get("/:id", async (req, res) => {
  try {
    const risk = await Risk.findOne({ riskId: req.params.id });
    if (!risk) return res.status(404).json({ error: "Risk not found" });
    res.json(risk);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch risk" });
  }
});

// ✅ POST (create or update)
router.post("/", async (req, res) => {
  try {
    const data = req.body;
    if (!data.riskId)
      return res.status(400).json({ error: "riskId is required" });

    const update = { ...data, updatedAt: new Date() };

    const risk = await Risk.findOneAndUpdate(
      { riskId: data.riskId },
      update,
      { new: true, upsert: true } // create if not found
    );

    res.json(risk);
  } catch (err) {
    res.status(500).json({ error: "Failed to save risk" });
  }
});

// ✅ DELETE risk
router.delete("/:id", async (req, res) => {
  try {
    const result = await Risk.deleteOne({ riskId: req.params.id });
    if (result.deletedCount === 0)
      return res.status(404).json({ error: "Risk not found" });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete risk" });
  }
});

module.exports = router;
