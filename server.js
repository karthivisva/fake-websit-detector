const express = require("express");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

app.post("/analyze", (req, res) => {
    const { url } = req.body;

    if (!url) {
        return res.status(400).json({ error: "URL is required" });
    }

    // Basic risk analysis (you can improve this logic)
    let riskScore = Math.floor(Math.random() * 100); // Random risk score
    let status = riskScore > 50 ? "Suspicious" : "Safe";
    let reasons = [];

    if (url.includes("free") || url.includes("cheap") || url.includes("offer")) {
        reasons.push("Contains suspicious keywords (free, cheap, offer)");
    }
    if (url.includes("xyz") || url.endsWith(".tk") || url.endsWith(".ml")) {
        reasons.push("Uses a free or less common domain extension");
    }
    if (url.length > 30) {
        reasons.push("URL is unusually long");
    }
    if (reasons.length === 0) {
        reasons.push("No obvious suspicious activity detected.");
    }

    res.json({
        url,
        status,
        riskScore,
        reasons
    });
});

app.listen(5000, () => console.log("Server running on port 5000"));
