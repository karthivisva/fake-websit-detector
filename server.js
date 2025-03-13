const express = require("express");
const cors = require("cors");
const punycode = require("punycode/");

const app = express();
app.use(express.json());
app.use(cors());

const blacklistedDomains = ["phishing.com", "scam-site.tk", "fakebank.xyz"];
const suspiciousKeywords = ["login", "secure", "bank", "verify", "update", "free", "cheap", "offer"];
const riskyExtensions = [".tk", ".ml", ".cf", ".gq", ".xyz"];
const randomCharPattern = /^[a-z]{10,}\.com$/; // Detects nonsense domains (e.g., cfkyjstrxykdafoyhgblu.com)

app.post("/analyze", (req, res) => {
    const { url } = req.body;

    if (!url) {
        return res.status(400).json({ error: "URL is required" });
    }

    let riskScore = 0;
    let reasons = [];

    // Convert URL to lowercase for consistent analysis
    let normalizedUrl = url.toLowerCase();

    // Check if the URL is in a blacklist
    if (blacklistedDomains.some(domain => normalizedUrl.includes(domain))) {
        riskScore += 40;
        reasons.push("Domain appears in a known blacklist");
    }

    // Check for suspicious keywords in the URL
    suspiciousKeywords.forEach(keyword => {
        if (normalizedUrl.includes(keyword)) {
            riskScore += 10;
            reasons.push(`Contains suspicious keyword: "${keyword}"`);
        }
    });

    // Check for risky domain extensions
    riskyExtensions.forEach(ext => {
        if (normalizedUrl.endsWith(ext)) {
            riskScore += 20;
            reasons.push(`Uses a less common or free domain extension: "${ext}"`);
        }
    });

    // Check for random, unrecognizable character sequences
    const domainOnly = normalizedUrl.replace(/^https?:\/\//, "").split("/")[0]; // Extract domain part
    if (randomCharPattern.test(domainOnly)) {
        riskScore += 50;
        reasons.push("Domain name contains random, unrecognizable characters");
    }

    // Check if the URL is using an IP address instead of a domain
    const ipPattern = /^(http[s]?:\/\/)?(\d{1,3}\.){3}\d{1,3}(:\d+)?(\/.*)?$/;
    if (ipPattern.test(url)) {
        riskScore += 30;
        reasons.push("Uses direct IP address instead of domain");
    }

    // Check for too many subdomains (e.g., paypal.secure-login.com)
    const domainParts = domainOnly.split(".");
    if (domainParts.length > 3) {
        riskScore += 15;
        reasons.push("Too many subdomains, could be a phishing attempt");
    }

    // Detect Unicode Homoglyph attacks (e.g., g00gle.com)
    const decodedDomain = punycode.toUnicode(normalizedUrl);
    if (decodedDomain !== normalizedUrl) {
        riskScore += 25;
        reasons.push("URL contains potential homoglyph attack (lookalike characters)");
    }

    // If no specific reason found, add a generic one
    if (reasons.length === 0) {
        reasons.push("No obvious suspicious activity detected.");
    }

    // Determine final status based on risk score
    let status = riskScore > 50 ? "Suspicious" : "Safe";

    res.json({
        url,
        status,
        riskScore: Math.min(riskScore, 100), // Cap risk score at 100
        reasons
    });
});

app.listen(5000, () => console.log("Server running on port 5000"));
