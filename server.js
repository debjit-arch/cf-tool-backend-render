const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const session = require("express-session");
const mongoose = require("mongoose");
require("dotenv").config();

// Routers
const docsRouter = require("./routes/docs");
const controlsRouter = require("./routes/controls");
const soaRouter = require("./routes/soa");
const gapsRouter = require("./routes/gaps");
const risksRouter = require("./routes/risks");
const taskRouter = require("./routes/tasks");
const usersRouter = require("./routes/users");

const app = express();
const PORT = process.env.PORT || 4000;

// ================= CORS & Session =================
app.set("trust proxy", 1);

app.use(
  session({
    secret: process.env.SESSION_SECRET || "supersecretkey",
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 15 * 60 * 1000,
      httpOnly: true,
      sameSite: "none",
      secure: true,
    },
  })
);

app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "https://tool.consultantsfactory.com",
      "https://microservices.d1iwz64jvqpior.amplifyapp.com",
      "https://www.calvant.com",
      "https://main.d1jl1790poryf2.amplifyapp.com",
      "https://main.d2y8kazdz4iqhv.amplifyapp.com",
      "https://test-2.d2y8kazdz4iqhv.amplifyapp.com",
      "https://main.d3lh6u2gqwaju4.amplifyapp.com",
    ],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "x-org", "x-region"],
  })
);

app.use(express.json());

// ================= Ensure folders exist =================
const dataDir = path.join(__dirname, "data");
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

// Serve uploads
app.use("/uploads", express.static(uploadsDir));

// ================= DB Configs =================
const dbConfigs = {
  INDIA: {
    uri: "mongodb://cftoolind:katana007@docdb-ind.cyarnzzhddsw.ap-south-1.docdb.amazonaws.com:27017/admin",
    conn: null,
  },
  EU: {
    uri: "mongodb://cftooladmin:katana007@docdb-eu.cjfxrwqdm1rm.eu-central-1.docdb.amazonaws.com:27017/admin",
    conn: null,
  },
  US: {
    uri: "mongodb://cftooladmin:katana007@docdb-us.cmuqitnitx1o.us-east-1.docdb.amazonaws.com:27017/admin",
    conn: null,
  },
};

// ================= Helper: Get DB Connection =================
async function getDBConnection(region) {
  const config = dbConfigs[region.toUpperCase()];
  if (!config) throw new Error(`Unknown region: ${region}`);

  if (!config.conn) {
    console.log(`Attempting DB connection: ${region}`);
    config.conn = mongoose.createConnection(config.uri, {
      ssl: true,
      sslCA: path.join(__dirname, "global-bundle.pem"),
      retryWrites: false,
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    config.conn.on("connected", () =>
      console.log(`✅ Connected to ${region} DocumentDB`)
    );
    config.conn.on("error", (err) =>
      console.error(`❌ ${region} DocumentDB error`, err.message)
    );

    // Wait for connection to be ready
    await new Promise((resolve, reject) => {
      config.conn.once("open", resolve);
      config.conn.once("error", reject);
    });
  }

  return config.conn;
}

// ================= Middleware: Attach DB =================
app.use(async (req, res, next) => {
  // Use let because we might reassign it, or use a fallback
  let region = req.headers["x-region"] || "INDIA"; 

  try {
    req.db = await getDBConnection(region);
    next();
  } catch (err) {
    console.error("DB connection error:", err.message);
    res.status(500).json({ error: "DB connection failed" });
  }
});

// ================= Routes =================
app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.use("/api/documents", docsRouter);
app.use("/api/controls", controlsRouter);
app.use("/api/soa", soaRouter);
app.use("/api/gaps", gapsRouter);
app.use("/api/risks", risksRouter);
app.use("/api/tasks", taskRouter);
app.use("/api/users", usersRouter);

// ================= Start Server =================
app.listen(PORT, () => {
  console.log(`✅ Backend running on http://localhost:${PORT}`);
});
