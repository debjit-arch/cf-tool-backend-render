const express = require("express");
const router = express.Router();
const Risk = require("../models/Risks");
const { authenticate } = require("../middleware/auth");

// =============================
// Safe model getter
// =============================
function getRiskModel(db) {
  return db.models.Risk || db.model("Risk", Risk.schema);
}

// =============================
// GET ALL RISKS (ORG + REGION SAFE)
// =============================
router.get("/", authenticate, async (req, res) => {
  try {
    const db = req.db;
    if (!db) return res.status(500).json({ error: "DB not available" });

    const RiskModel = getRiskModel(db);

    const risks = await RiskModel.find({
      organization: req.user.organization,
    });

    res.json(risks);
  } catch (err) {
    console.error("Fetch risks error:", err);
    res.status(500).json({ error: "Failed to fetch risks" });
  }
});

// =============================
// GET RISK BY RISK ID
// =============================
router.get("/:id", authenticate, async (req, res) => {
  try {
    const db = req.db;
    if (!db) return res.status(500).json({ error: "DB not available" });

    const RiskModel = getRiskModel(db);

    const risk = await RiskModel.findOne({
      riskId: req.params.id,
      organization: req.user.organization,
    });

    if (!risk) return res.status(404).json({ error: "Risk not found" });

    res.json(risk);
  } catch (err) {
    console.error("Fetch risk error:", err);
    res.status(500).json({ error: "Failed to fetch risk" });
  }
});

// =============================
// CREATE / UPDATE RISK
// =============================
router.post("/", authenticate, async (req, res) => {
  try {
    const db = req.db;
    if (!db) return res.status(500).json({ error: "DB not available" });

    const RiskModel = getRiskModel(db);

    if (!req.body.riskId)
      return res.status(400).json({ error: "riskId is required" });

    const risk = await RiskModel.findOneAndUpdate(
      {
        riskId: req.body.riskId,
        organization: req.user.organization,
      },
      {
        ...req.body,
        organization: req.user.organization,
        updatedAt: new Date(),
      },
      { upsert: true, new: true }
    );

    res.json(risk);
  } catch (err) {
    console.error("Save risk error:", err);
    res.status(500).json({ error: "Failed to save risk" });
  }
});

// =============================
// DELETE RISK
// =============================
router.delete("/:id", authenticate, async (req, res) => {
  try {
    const db = req.db;
    if (!db) return res.status(500).json({ error: "DB not available" });

    const RiskModel = getRiskModel(db);

    const result = await RiskModel.deleteOne({
      riskId: req.params.id,
      organization: req.user.organization,
    });

    if (!result.deletedCount)
      return res.status(404).json({ error: "Risk not found" });

    res.json({ success: true });
  } catch (err) {
    console.error("Delete risk error:", err);
    res.status(500).json({ error: "Failed to delete risk" });
  }
});

module.exports = router;
