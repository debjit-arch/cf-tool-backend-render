const express = require("express");
const router = express.Router();
const Risk = require("../models/Risks");
const { authenticate } = require("../middleware/auth");

// =============================
// Helper: Get Risk Model (Region-Aware)
// =============================
function getRiskModel(db) {
  return db.model("Risk", Risk.schema);
}

// =============================
// GET ALL RISKS (ORG + REGION SAFE)
// =============================
router.get("/", authenticate, async (req, res) => {
  try {
    const db = req.db;
    if (!db) return res.status(500).json({ error: "DB not available" });

    const RiskModel = getRiskModel(db);

    const query = {};
    if (req.user.organization) {
      query.organization = req.user.organization;
    }

    const risks = await RiskModel.find(query);
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

    const query = {
      riskId: req.params.id,
    };

    if (req.user.organization) {
      query.organization = req.user.organization;
    }

    const risk = await RiskModel.findOne(query);
    if (!risk) return res.status(404).json({ error: "Risk not found" });

    res.json(risk);
  } catch (err) {
    console.error("Fetch risk error:", err);
    res.status(500).json({ error: "Failed to fetch risk" });
  }
});

// =============================
// CREATE / UPDATE RISK (UPSERT)
// =============================
router.post("/", authenticate, async (req, res) => {
  try {
    const db = req.db;
    if (!db) return res.status(500).json({ error: "DB not available" });

    const RiskModel = getRiskModel(db);

    const data = req.body;
    if (!data.riskId)
      return res.status(400).json({ error: "riskId is required" });

    const update = {
      ...data,
      organization: req.user.organization, // 🔐 org isolation
      updatedAt: new Date(),
    };

    const risk = await RiskModel.findOneAndUpdate(
      {
        riskId: data.riskId,
        organization: req.user.organization,
      },
      update,
      { new: true, upsert: true }
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

    if (result.deletedCount === 0)
      return res.status(404).json({ error: "Risk not found" });

    res.json({ success: true });
  } catch (err) {
    console.error("Delete risk error:", err);
    res.status(500).json({ error: "Failed to delete risk" });
  }
});

module.exports = router;
