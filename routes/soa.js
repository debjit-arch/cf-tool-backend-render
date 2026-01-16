const express = require("express");
const router = express.Router();
const Soa = require("../models/Soa");
const Control = require("../models/Controls");

// ✅ GET all SoA entries
router.get("/", async (req, res) => {
  try {
    const soaEntries = await Soa.find().sort({ createdAt: -1 });
    res.json(soaEntries);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch SoA entries" });
  }
});

// ✅ POST create new SoA entry
router.post("/", async (req, res) => {
  try {
    const newSoa = new Soa({
      id: Date.now(),
      controlId: req.body.controlId,
      category: req.body.category,
      description: req.body.description,
      status: req.body.status || "Planned",
      documentRef: req.body.documentRef || [],
      justification: req.body.justification || "",
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    await newSoa.save();
    res.json(newSoa);
  } catch (err) {
    res.status(500).json({ error: "Failed to add SoA entry" });
  }
});

// ✅ PUT update SoA entry
router.put("/:id", async (req, res) => {
  try {
    const soaId = parseInt(req.params.id, 10);
    const updatedSoa = await Soa.findOneAndUpdate(
      { id: soaId },
      { ...req.body, updatedAt: new Date() },
      { new: true }
    );

    if (!updatedSoa) return res.status(404).json({ error: "SoA entry not found" });

    res.json(updatedSoa);
  } catch (err) {
    res.status(500).json({ error: "Failed to update SoA entry" });
  }
});

// ✅ DELETE SoA entry
router.delete("/:id", async (req, res) => {
  try {
    const soaId = parseInt(req.params.id, 10);
    const deletedSoa = await Soa.findOneAndDelete({ id: soaId });

    if (!deletedSoa)
      return res.status(404).json({ error: "SoA entry not found" });

    res.json({ deletedSoa });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete SoA entry" });
  }
});

module.exports = router;
