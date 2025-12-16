const express = require("express");
const router = express.Router();

const { authenticate, authorizeRoles } = require("../middleware/auth");
const getModel = require("../utils/getModel");

const RiskSchema = require("../models/Risks");

// -------------------------
// Tenant / region safe model
// -------------------------
function getRiskModel(db) {
  return getModel(db, "Risk", RiskSchema);
}

/* ======================================================
   GET ALL RISKS (ORG + REGION SAFE)
====================================================== */
router.get("/", authenticate, async (req, res) => {
  try {
    if (!req.db) return res.status(500).json({ error: "DB not available" });

    const Risk = getRiskModel(req.db);

    const risks = await Risk.find({
      organization: req.user.organization,
    }).sort({ updatedAt: -1 });

    res.json(risks);
  } catch (err) {
    console.error("Fetch risks error:", err);
    res.status(500).json({ error: "Failed to fetch risks" });
  }
});

/* ======================================================
   GET RISK BY riskId
====================================================== */
router.get("/:id", authenticate, async (req, res) => {
  try {
    if (!req.db) return res.status(500).json({ error: "DB not available" });

    const Risk = getRiskModel(req.db);

    const risk = await Risk.findOne({
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

/* ======================================================
   CREATE / UPDATE RISK (UPSERT)
====================================================== */
router.post(
  "/",
  authenticate,
  authorizeRoles("super_admin", "root", "risk_owner", "risk_manager"),
  async (req, res) => {
    try {
      if (!req.db) return res.status(500).json({ error: "DB not available" });

      if (!req.body.riskId)
        return res.status(400).json({ error: "riskId is required" });

      const Risk = getRiskModel(req.db);

      const { riskId, organization, ...payload } = req.body;

      const risk = await Risk.findOneAndUpdate(
        {
          riskId,
          organization: req.user.organization,
        },
        {
          $set: {
            ...payload,
            organization: req.user.organization,
            updatedAt: new Date(),
          },
          $setOnInsert: {
            riskId,
            createdAt: new Date(),
          },
        },
        {
          upsert: true,
          new: true,
          runValidators: true,
        }
      );

      res.json(risk);
    } catch (err) {
      console.error("Save risk error:", err);
      res.status(500).json({ error: "Failed to save risk" });
    }
  }
);

/* ======================================================
   DELETE RISK
====================================================== */
router.delete(
  "/:id",
  authenticate,
  authorizeRoles("super_admin", "root", "risk_manager"),
  async (req, res) => {
    try {
      if (!req.db) return res.status(500).json({ error: "DB not available" });

      const Risk = getRiskModel(req.db);

      const result = await Risk.deleteOne({
        riskId: req.params.id,
        organization: req.user.organization,
      });

      if (!result.deletedCount)
        return res.status(404).json({ error: "Risk not found" });

      res.json({ message: "Risk deleted" });
    } catch (err) {
      console.error("Delete risk error:", err);
      res.status(500).json({ error: "Failed to delete risk" });
    }
  }
);

module.exports = router;
