const express = require("express");
const router = express.Router();
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const Gap = require("../models/Gaps");

// Ensure uploads folder exists
const uploadsDir = path.join(__dirname, "../uploads");
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

// Multer config
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  },
});
const upload = multer({ storage });

// Upload document file
router.post("/upload", upload.single("file"), (req, res) => {
  console.log("Upload request received");
  if (!req.file) {
    console.log("No file uploaded");
    return res.status(400).json({ message: "No file uploaded" });
  }
  console.log("File uploaded:", req.file.filename);
  res.json({ url: `/uploads/${req.file.filename}` });
});

// Create or update gap entry (employee)
router.post("/", async (req, res) => {
  try {
    const {
      clause,
      standardRequirement,
      question,
      practiceEvidence,
      documentURL,
      createdBy,
    } = req.body;

    let gap = await Gap.findOne({ clause, question });
    if (gap) {
      gap.practiceEvidence = practiceEvidence || gap.practiceEvidence;
      gap.documentURL = documentURL || gap.documentURL;
      gap.createdBy = createdBy || gap.createdBy;
    } else {
      gap = new Gap({
        clause,
        standardRequirement,
        question,
        practiceEvidence,
        documentURL,
        createdBy,
      });
    }

    await gap.save();
    res.json(gap); // ✅ JSON response
  } catch (err) {
    console.error("Gap creation/update failed:", err);
    res.status(500).json({ message: "Server Error", error: err.message }); // ✅ JSON response
  }
});

// Get all gaps
router.get("/", async (req, res) => {
  try {
    const gaps = await Gap.find();
    res.json(gaps);
  } catch (err) {
    res.status(500).send("Server Error");
  }
});

// Auditor updates gap
router.put("/:id", async (req, res) => {
  try {
    const { docScore, practiceScore, docRemarks, practiceRemarks, verifiedBy } =
      req.body;
    const gap = await Gap.findByIdAndUpdate(
      req.params.id,
      {
        docScore,
        practiceScore,
        docRemarks,
        practiceRemarks,
        verifiedBy,
        status: "Verified",
      },
      { new: true }
    );
    res.json(gap);
  } catch (err) {
    res.status(500).send("Server Error");
  }
});

module.exports = router;
