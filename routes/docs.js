const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const Document = require("../models/Docs");

const router = express.Router();
const UPLOADS_DIR = path.join(__dirname, "..", "uploads");

// Ensure uploads folder exists
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);

// Multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, unique + "-" + file.originalname);
  }
});
const upload = multer({ storage });

// GET all documents, optional filter by controlId or soaId
router.get("/", async (req, res) => {
  try {
    const { controlId, soaId } = req.query;
    let filter = {};
    if (controlId) filter.controlId = controlId;
    if (soaId) filter.soaId = soaId;

    const docs = await Document.find(filter).sort({ createdAt: -1 });
    res.json(docs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST upload a document
router.post("/upload", upload.single("file"), async (req, res) => {
  try {
    const { soaId, controlId } = req.body;
    const newDoc = new Document({
      id: Date.now(),
      name: req.file.originalname,
      url: `/uploads/${req.file.filename}`,
      soaId: soaId || null,
      controlId: controlId || null
    });
    await newDoc.save();
    res.json(newDoc);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE document by ID
router.delete("/:id", async (req, res) => {
  try {
    const doc = await Document.findOne({ id: Number(req.params.id) });
    if (!doc) return res.status(404).json({ error: "Document not found" });

    // delete file from uploads folder
    const filePath = path.join(UPLOADS_DIR, path.basename(doc.url));
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

    // delete from database
    await doc.deleteOne();

    res.json({ message: "Document deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
