const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const pdfParse = require("pdf-parse");
const mammoth = require("mammoth");
const fetch = require("node-fetch");
require("dotenv").config();
const mongoose = require("mongoose");
const session = require("express-session");

const docsRouter = require("./routes/docs");
const controlsRouter = require("./routes/controls");
const soaRouter = require("./routes/soa");
const gapsRouter = require("./routes/gaps");
const risksRouter = require("./routes/risks");
const taskRouter = require("./routes/tasks");
const usersRouter = require("./routes/users");

const app = express();
const PORT = process.env.PORT || 4000;

app.set("trust proxy", 1);
// ================= CORS setup =================
// Allow React frontend to send credentials (cookies)
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
    origin: ["http://localhost:3000", "https://tool.consultantsfactory.com","https://microservices.d1iwz64jvqpior.amplifyapp.com/"],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json());

// Ensure folders exist
const dataDir = path.join(__dirname, "data");
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

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

// Serve uploads
app.use("/uploads", express.static(uploadsDir));

// ================= Connect DB and start server =================
mongoose
  .connect(
    process.env.MONGO_URL ||
      "mongodb+srv://debjit:katana007@cluster0.kd9pbws.mongodb.net/test?retryWrites=true&w=majority&appName=Cluster0"
  )
  .then(() => {
    console.log("Connected to DataBase");
    app.listen(PORT, () =>
      console.log(`✅ Backend running on http://localhost:${PORT}`)
    );
  })
  .catch((err) => {
    console.error("Failed to Connect DB:", err);
  });
