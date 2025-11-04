const express = require("express");
const path = require("path");
const fs = require("fs");
const pdf = require("pdf-parse");
const mammoth = require("mammoth");
const Gap = require("../models/Gaps");

const router = express.Router();
const DOCS_FILE = path.join(__dirname, "..", "data", "documents.json");

// ✅ GET all Gaps
router.get("/", async (req, res) => {
  try {
    const gaps = await Gap.find().sort({ createdAt: -1 });
    res.json(gaps);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ GET one gap by docId
router.get("/:docId", async (req, res) => {
  try {
    const gap = await Gap.findOne({ docId: req.params.docId });
    if (!gap) return res.status(404).json({ error: "Gap not found" });
    res.json(gap);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ POST create new gap
router.post("/", async (req, res) => {
  try {
    const newGap = new Gap(req.body);
    await newGap.save();
    res.json(newGap);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ PUT update or insert gap by docId
router.put("/:docId", async (req, res) => {
  try {
    const { docId } = req.params;
    const updatedGap = await Gap.findOneAndUpdate(
      { docId },
      { ...req.body },
      { new: true, upsert: true }
    );
    res.json(updatedGap);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ PATCH update specific gap fields
router.patch("/:docId", async (req, res) => {
  try {
    const { docId } = req.params;
    const updatedGap = await Gap.findOneAndUpdate(
      { docId },
      { $set: req.body },
      { new: true }
    );
    if (!updatedGap) return res.status(404).json({ message: "Gap not found" });
    res.json(updatedGap);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ DELETE a gap
router.delete("/:docId", async (req, res) => {
  try {
    const deleted = await Gap.findOneAndDelete({ docId: req.params.docId });
    if (!deleted) return res.status(404).json({ error: "Gap not found" });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ COMPLIANCE CHECK
router.post("/:docId/check-compliance", async (req, res) => {
  try {
    const { docId } = req.params;

    const Document = require("../models/Docs"); // <-- import the model

    // inside check-compliance
    const doc = await Document.findOne({ id: Number(docId) });
    if (!doc) return res.status(404).json({ error: "Document not found" });

    // 2️⃣ Resolve file path
    const filePath = path.join(__dirname, "..", doc.url);
    const fileExists = fs.existsSync(filePath);

    // 3️⃣ Extract text
    let text = "";
    if (fileExists) {
      if (filePath.endsWith(".pdf")) {
        const buffer = fs.readFileSync(filePath);
        text = (await pdf(buffer)).text;
      } else if (filePath.endsWith(".docx")) {
        text = (await mammoth.extractRawText({ path: filePath })).value;
      } else {
        text = fs.readFileSync(filePath, "utf-8");
      }
    }

    // 4️⃣ Compliance rules
    const rules = {
      required_sections: ["Purpose", "Scope", "Responsibilities", "Procedure"],
      forbidden_phrases: [
        "should try to",
        "maybe",
        "if possible",
        "where feasible",
      ],
      mandatory_keywords: ["employees", "policy", "must", "procedure"],
    };

    const missing_sections = rules.required_sections.filter(
      (sec) => !text.toLowerCase().includes(sec.toLowerCase())
    );

    const forbidden_phrases_found = rules.forbidden_phrases.filter((p) =>
      text.toLowerCase().includes(p.toLowerCase())
    );

    const missing_keywords = rules.mandatory_keywords.filter(
      (k) => !text.toLowerCase().includes(k.toLowerCase())
    );

    const totalChecks =
      rules.required_sections.length +
      rules.mandatory_keywords.length +
      rules.forbidden_phrases.length;
    const passedChecks =
      rules.required_sections.length -
      missing_sections.length +
      rules.mandatory_keywords.length -
      missing_keywords.length +
      rules.forbidden_phrases.length -
      forbidden_phrases_found.length;

    const score = Math.round((passedChecks / totalChecks) * 100);
    const label = score >= 70 ? "compliant" : "non-compliant";

    // 5️⃣ Prepare compliance result
    const complianceResult = {
      docId,
      docName: doc.name,
      missing_sections,
      forbidden_phrases_found,
      missing_keywords,
      score,
      label,
      status: fileExists
        ? score >= 70
          ? "Waiting for Approval"
          : "Rejeceted"
        : "Missing",
      checkedAt: new Date(),
    };

    // 6️⃣ Save/update to DB
    const updatedGap = await Gap.findOneAndUpdate({ docId }, complianceResult, {
      upsert: true,
      new: true,
    });

    res.json(updatedGap);
  } catch (err) {
    console.error("Compliance check error:", err);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
