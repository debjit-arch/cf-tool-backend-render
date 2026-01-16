const express = require("express");
const router = express.Router();
const Control = require("../models/Controls");

// ✅ GET all controls
router.get("/", async (req, res) => {
  try {
    const controls = await Control.find().sort({ id: 1 });
    res.json(controls);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch controls" });
  }
});

// ✅ POST create new control
router.post("/", async (req, res) => {
  try {
    const controls = await Control.find().sort({ id: -1 }).limit(1);
    const newId = controls.length > 0 ? controls[0].id + 1 : 1;

    const newControl = new Control({
      id: newId,
      category: req.body.category,
      description: req.body.description,
    });

    await newControl.save();
    res.json(newControl);
  } catch (err) {
    res.status(500).json({ error: "Failed to add control" });
  }
});

// ✅ DELETE control by ID (also removes related SoA entries)
router.delete("/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const deletedControl = await Control.findOneAndDelete({ id });

    if (!deletedControl)
      return res.status(404).json({ error: "Control not found" });

    // 🧩 Delete related SoA entries
    const Soa = require("../models/Soa");
    const deletedSoas = await Soa.deleteMany({ controlId: id });

    res.json({
      deletedControl,
      deletedSoaCount: deletedSoas.deletedCount,
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete control" });
  }
});

module.exports = router;
