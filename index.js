require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const Scan = require("./models/Scan");
const User = require("./models/User");

// ---- NEW GOOGLE MODEL IMPORT ----
const { GoogleGenerativeAI } = require("@google/generative-ai");

// CONFIGURATION
const app = express();
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const MODEL_NAME = "gemini-2.5-flash";
const JWT_SECRET = process.env.JWT_SECRET;
const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY;

// MIDDLEWARE
app.options('*', cors());
app.use(
  cors({
    origin: ["http://localhost:3000", "https://sentinal-ai-kappa.vercel.app/"],
    credentials: true,
  })
);
app.use(express.json());

// DATABASE CONNECTION
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB Connection Error:", err));

// ---- AI CLIENT ----
const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: MODEL_NAME });

// AUTH MIDDLEWARE
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ error: "Access Denied: No Token" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid Token" });
    req.user = user;
    next();
  });
};

// =============================
// ROUTES
// =============================

// AUTH ROUTES
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: "User already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashed, role: "user" });
    await user.save();

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "1d" });
    res.json({ id: user._id, email: user.email, role: user.role, token });
  } catch (e) {
    console.log(e);
    res.status(500).json({ error: "Registration failed", message: e.toString() });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "1d" });
    res.json({ id: user._id, email: user.email, role: user.role, token });
  } catch (e) {
    console.log(e);
    res.status(500).json({ error: "Login failed", message: e.toString() });
  }
});

// =============================
// ETHERSCAN PROXY
// =============================
app.get("/api/proxy/contract", async (req, res) => {
  try {
    const { address } = req.query;

    const url = `https://api.etherscan.io/api?module=contract&action=getsourcecode&address=${address}&apikey=${ETHERSCAN_API_KEY}`;
    const response = await axios.get(url);

    if (response.data.status === "1") {
      const sourceCode = response.data.result[0].SourceCode;
      return res.json({ sourceCode });
    }

    res.status(400).json({ error: "Unable to fetch source code" });
  } catch (err) {
    res.status(500).json({ error: "Etherscan fetch failed" });
  }
});

// =============================
// CONTRACT ANALYSIS
// =============================
app.post("/api/analyze/contract", authenticateToken, async (req, res) => {
  try {
    const { sourceCode, address } = req.body;

    const prompt = `
    You are a Web3 Security Auditor. 
    Return ONLY JSON.
    {
      "riskScore": number,
      "riskLevel": "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
      "summary": string,
      "rugPullProb": number,
      "vulnerabilities": [
        { "type": string, "severity": string, "description": string }
      ]
    }
    Analyze this Solidity code:
    ${sourceCode.slice(0, 28000)}
    `;

    const result = await model.generateContent(prompt);
    const text = result.response.text();

    const analysis = JSON.parse(text);

    await Scan.create({
      type: "CONTRACT",
      target: address || "Raw Code",
      riskScore: analysis.riskScore,
      riskLevel: analysis.riskLevel,
      result: analysis,
    });

    res.json(analysis);
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Contract analysis failed" });
  }
});

// =============================
// TX ANALYSIS
// =============================
app.post("/api/analyze/tx", authenticateToken, async (req, res) => {
  try {
    const { inputData } = req.body;

    const prompt = `
    Return JSON:
    {
      "riskScore": number,
      "riskLevel": string,
      "intent": string,
      "flags": [],
      "simulationResult": string
    }
    Analyze this transaction input:
    ${inputData}
    `;

    const result = await model.generateContent(prompt);
    const analysis = JSON.parse(result.response.text());

    await Scan.create({
      type: "TRANSACTION",
      target: inputData.substring(0, 20) + "...",
      riskScore: analysis.riskScore,
      riskLevel: analysis.riskLevel,
      result: analysis,
    });

    res.json(analysis);
  } catch (err) {
    res.status(500).json({ error: "Tx analysis failed" });
  }
});

// =============================
// WALLET ANALYSIS
// =============================
app.post("/api/analyze/wallet", authenticateToken, async (req, res) => {
  try {
    const { address } = req.body;

    const prompt = `
    Return JSON:
    {
      "address": string,
      "reputationScore": number,
      "analysis": string,
      "tags": []
    }
    Analyze this wallet: ${address}
    `;

    const result = await model.generateContent(prompt);
    const analysis = JSON.parse(result.response.text());

    await Scan.create({
      type: "WALLET",
      target: address,
      riskScore: 100 - analysis.reputationScore,
      riskLevel: analysis.reputationScore > 70 ? "SAFE" : "HIGH",
      result: analysis,
    });

    res.json(analysis);
  } catch (err) {
    res.status(500).json({ error: "Wallet analysis failed" });
  }
});

// =============================
// STATS
// =============================
app.get("/api/stats", authenticateToken, async (req, res) => {
  try {
    const totalScans = await Scan.countDocuments();
    res.json({ totalScans });
  } catch (err) {
    res.status(500).json({ error: "Stats failed" });
  }
});

app.listen(PORT, () => console.log(`🚀 Sentinel Backend running on ${PORT}`));
