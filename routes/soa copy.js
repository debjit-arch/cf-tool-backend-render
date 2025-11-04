const express = require("express");
const path = require("path");
const fs = require("fs");
const router = express.Router();

const DATA_FILE = path.join(__dirname, "..", "data", "soa.json");
const CONTROLS_FILE = path.join(__dirname, "..", "data", "controls.json");

// Ensure data files exist
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, "[]");
if (!fs.existsSync(CONTROLS_FILE)) fs.writeFileSync(CONTROLS_FILE, "[]");

// Helper functions
function readData(file) {
  return JSON.parse(fs.readFileSync(file, "utf-8") || "[]");
}
function writeData(file, arr) {
  fs.writeFileSync(file, JSON.stringify(arr, null, 2));
}

// Get all SoA entries
router.get("/", (req, res) => {
  res.json(readData(DATA_FILE));
});

// Add SoA entry
router.post("/", (req, res) => {
  const soa = readData(DATA_FILE);
  const entry = { id: Date.now(), ...req.body };
  soa.push(entry);
  writeData(DATA_FILE, soa);
  res.json(entry);
});

router.put("/:id", (req, res) => {
  const soa = readData(DATA_FILE);
  const soaId = parseInt(req.params.id, 10);
  const index = soa.findIndex((s) => s.id === soaId);

  if (index === -1) {
    return res.status(404).json({ error: "SoA entry not found" });
  }

  // Update the entry with new data from request body
  soa[index] = { ...soa[index], ...req.body };

  writeData(DATA_FILE, soa);

  res.json(soa[index]);
});

// Delete SoA entry and its associated controls
router.delete("/:id", (req, res) => {
  const soa = readData(DATA_FILE);
  const soaId = parseInt(req.params.id, 10);
  const index = soa.findIndex((s) => s.id === soaId);

  if (index === -1) {
    return res.status(404).json({ error: "SoA entry not found" });
  }

  const [deletedSoA] = soa.splice(index, 1);

  // Delete associated controls
  const controls = readData(CONTROLS_FILE);
  const remainingControls = controls.filter(
    (c) => !deletedSoA.controlIds.includes(c.id)
  );
  writeData(CONTROLS_FILE, remainingControls);

  // Save updated SoA data
  writeData(DATA_FILE, soa);

  res.json({ deletedSoA, deletedControls: deletedSoA.controlIds });
});

module.exports = router;
