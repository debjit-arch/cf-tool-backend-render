const express = require("express");
const path = require("path");
const fs = require("fs");
const router = express.Router();

const CONTROLS_FILE = path.join(__dirname, "..", "data", "controls.json");
const SOA_FILE = path.join(__dirname, "..", "data", "soa.json");

// Ensure files exist
if (!fs.existsSync(CONTROLS_FILE)) fs.writeFileSync(CONTROLS_FILE, "[]");
if (!fs.existsSync(SOA_FILE)) fs.writeFileSync(SOA_FILE, "[]");

// Helper functions
function readData(file) {
  return JSON.parse(fs.readFileSync(file, "utf-8") || "[]");
}
function writeData(file, arr) {
  fs.writeFileSync(file, JSON.stringify(arr, null, 2));
}

// GET /api/controls
router.get("/", (req, res) => res.json(readData(CONTROLS_FILE)));

// POST /api/controls
router.post("/", (req, res) => {
  const controls = readData(CONTROLS_FILE);

  // Generate sequential ID
  const newId = controls.length > 0 ? Math.max(...controls.map(c => c.id)) + 1 : 1;

  const control = { id: newId, ...req.body };
  controls.push(control);
  writeData(CONTROLS_FILE, controls);
  res.json(control);
});

// DELETE /api/controls/:id
router.delete("/:id", (req, res) => {
  const controls = readData(CONTROLS_FILE);
  const id = parseInt(req.params.id, 10);
  const index = controls.findIndex(c => c.id === id);

  if (index === -1) {
    return res.status(404).json({ error: "Control not found" });
  }

  const deletedControl = controls.splice(index, 1)[0];
  writeData(CONTROLS_FILE, controls);

  // 🔄 Also delete related SoA entries
  const soa = readData(SOA_FILE);
  const remainingSoa = soa.filter(entry => entry.controlId !== deletedControl.id);
  const deletedSoa = soa.filter(entry => entry.controlId === deletedControl.id);
  writeData(SOA_FILE, remainingSoa);

  res.json({
    deletedControl,
    deletedSoaEntries: deletedSoa.map(e => e.id)
  });
});

module.exports = router;
