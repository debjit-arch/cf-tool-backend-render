const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const router = express.Router();

const DATA_FILE = path.join(__dirname, "..", "data", "documents.json");
const UPLOADS_DIR = path.join(__dirname, "..", "uploads");

// ensure file exists
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, "[]");

// helper functions
function readDocs() {
  return JSON.parse(fs.readFileSync(DATA_FILE, "utf-8") || "[]");
}
function writeDocs(docs) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(docs, null, 2));
}

// multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, unique + "-" + file.originalname);
  },
});
const upload = multer({ storage });

// GET all docs (optional ?controlId= or ?soaId=)
router.get("/", (req, res) => {
  const { controlId, soaId } = req.query;
  let docs = readDocs();
  if (controlId) docs = docs.filter((d) => d.controlId == controlId);
  if (soaId) docs = docs.filter((d) => d.soaId == soaId);
  res.json(docs);
});

// POST upload
router.post("/upload", upload.single("file"), (req, res) => {
  const docs = readDocs();
  const newDoc = {
    id: Date.now(),
    name: req.file.originalname,
    url: `/uploads/${req.file.filename}`,
    soaId: req.body.soaId || null,
    controlId: req.body.controlId || null,
    createdAt: new Date().toISOString(),
  };
  docs.push(newDoc);
  writeDocs(docs);
  res.json(newDoc);
});

// DELETE document by ID
router.delete("/:id", (req, res) => {
  const docId = Number(req.params.id);
  let docs = readDocs();
  const docIndex = docs.findIndex((d) => d.id === docId);

  if (docIndex === -1) {
    return res.status(404).send("Document not found");
  }

  // delete file from uploads folder
  const filePath = path.join(UPLOADS_DIR, docs[docIndex].url.replace("/uploads/", ""));
  if (fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
  }

  // remove from JSON
  docs.splice(docIndex, 1);
  writeDocs(docs);

  res.json({ message: "Document deleted successfully" });
});


module.exports = router;
