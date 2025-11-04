const express = require("express");
const path = require("path");
const fs = require("fs");
const pdf = require("pdf-parse");
const mammoth = require("mammoth");
const fetch = require("node-fetch");

const router = express.Router();

const DATA_FILE = path.join(__dirname, "..", "data", "gaps.json");
const DOCS_FILE = path.join(__dirname, "..", "data", "documents.json");

if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, "[]");

function readData() {
  return JSON.parse(fs.readFileSync(DATA_FILE, "utf-8") || "[]");
}
function writeData(arr) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(arr, null, 2));
}

// CRUD
router.get("/", (req, res) => res.json(readData()));
router.post("/", (req, res) => {
  const gaps = readData();
  const gap = { id: Date.now(), ...req.body };
  gaps.push(gap);
  writeData(gaps);
  res.json(gap);
});
router.patch("/:docId", (req, res) => {
  const gaps = readData();
  const docId = req.params.docId;
  const index = gaps.findIndex((g) => g.docId == docId);
  if (index === -1) return res.status(404).json({ message: "Gap not found" });
  gaps[index] = { ...gaps[index], ...req.body };
  writeData(gaps);
  res.json(gaps[index]);
});
router.put("/:docId", (req, res) => {
  const gaps = readData();
  const docId = req.params.docId;
  const index = gaps.findIndex((g) => g.docId == docId);
  if (index === -1) {
    const newGap = { id: Date.now(), docId, ...req.body };
    gaps.push(newGap);
    writeData(gaps);
    return res.json(newGap);
  }
  gaps[index] = { ...gaps[index], ...req.body, docId };
  writeData(gaps);
  res.json(gaps[index]);
});

// Compliance check (auto-update gaps)
router.post("/:docId/check-compliance", async (req, res) => {
  try {
    const { docId } = req.params;

    // 1️⃣ Load documents.json
    const docs = JSON.parse(fs.readFileSync(DOCS_FILE, "utf-8") || "[]");
    const doc = docs.find((d) => d.id.toString() === docId.toString());

    if (!doc) return res.status(404).json({ error: "Document not found" });

    // 2️⃣ Resolve file path
    const filePath = path.join(__dirname, "..", doc.url);
    const fileExists = fs.existsSync(filePath);

    // 3️⃣ Extract text only if file exists
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
      forbidden_phrases: ["should try to", "maybe", "if possible", "where feasible"],
      mandatory_keywords: ["employees", "policy", "must", "procedure"],
    };

    const missing_sections = text
      ? rules.required_sections.filter(
          (sec) => !text.toLowerCase().includes(sec.toLowerCase())
        )
      : rules.required_sections;

    const forbidden_phrases_found = text
      ? rules.forbidden_phrases.filter((p) =>
          text.toLowerCase().includes(p.toLowerCase())
        )
      : [];

    const missing_keywords = text
      ? rules.mandatory_keywords.filter(
          (k) => !text.toLowerCase().includes(k.toLowerCase())
        )
      : rules.mandatory_keywords;

    // 5️⃣ Score calculation (Python-like)
    const totalChecks =
      rules.required_sections.length +
      rules.mandatory_keywords.length +
      rules.forbidden_phrases.length;
    const passedChecks =
      rules.required_sections.length - missing_sections.length +
      rules.mandatory_keywords.length - missing_keywords.length +
      rules.forbidden_phrases.length - forbidden_phrases_found.length;

    const score = Math.round((passedChecks / totalChecks) * 100);
    const label = score >= 70 ? "compliant" : "non-compliant";

    // 6️⃣ Prepare compliance result
    const complianceResult = {
      docId,
      docName: doc.name, // ✅ store the document name
      missing_sections,
      forbidden_phrases_found,
      missing_keywords,
      score,
      label,
      status: fileExists ? (score >= 70 ? "Waiting for Approval" : "Rejeceted") : "Missing",
      checkedAt: new Date().toISOString(),
    };

    // 7️⃣ Save/update gaps.json
    const gaps = readData();
    const index = gaps.findIndex((g) => g.docId.toString() === docId.toString());

    if (index === -1) {
      gaps.push({ id: Date.now(), docId, ...complianceResult });
    } else {
      gaps[index] = { ...gaps[index], ...complianceResult };
    }

    writeData(gaps);

    res.json(complianceResult);
  } catch (err) {
    console.error("Compliance check error:", err);
    res.status(500).json({ error: err.message });
  }
});


module.exports = router;
