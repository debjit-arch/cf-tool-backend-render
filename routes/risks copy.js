const express = require("express");
const fs = require("fs");
const path = require("path");

const router = express.Router();
const RISKS_FILE = path.join(__dirname, "..", "data", "risks.json");

// --- Ensure file exists ---
if (!fs.existsSync(RISKS_FILE)) {
  fs.writeFileSync(RISKS_FILE, "[]");
}

// --- Helpers ---
function readRisks() {
  try {
    const data = fs.readFileSync(RISKS_FILE, "utf-8");
    const parsed = JSON.parse(data);
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    console.error("Error reading risks.json:", err);
    return [];
  }
}

function writeRisks(risks) {
  try {
    fs.writeFileSync(RISKS_FILE, JSON.stringify(risks, null, 2));
  } catch (err) {
    console.error("Error writing risks.json:", err);
  }
}

// --- Routes ---

// ✅ GET all risks
router.get("/", (req, res) => {
  const risks = readRisks();
  res.json(Array.isArray(risks) ? risks : []);
});

// ✅ GET risk by ID
router.get("/:id", (req, res) => {
  const risks = readRisks();
  const risk = risks.find((r) => r.riskId === req.params.id);
  if (!risk) {
    return res.status(404).json({ error: "Risk not found" });
  }
  res.json(risk);
});

// ✅ POST (create or update risk)
router.post("/", (req, res) => {
  let risks = readRisks();
  const data = req.body;

  if (!data.riskId) {
    return res.status(400).json({ error: "riskId is required" });
  }

  const index = risks.findIndex((r) => r.riskId === data.riskId);

  const riskWithMeta = {
    ...data,
    createdAt: data.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    status: data.status || "Active",
  };

  if (index >= 0) {
    risks[index] = riskWithMeta; // update existing
  } else {
    risks.push(riskWithMeta); // insert new
  }

  writeRisks(risks);
  res.json(riskWithMeta);
});

// ✅ DELETE risk
router.delete("/:id", (req, res) => {
  let risks = readRisks();
  const before = risks.length;
  risks = risks.filter((r) => r.riskId !== req.params.id);

  if (risks.length === before) {
    return res.status(404).json({ error: "Risk not found" });
  }

  writeRisks(risks);
  res.json({ success: true });
});

module.exports = router;
