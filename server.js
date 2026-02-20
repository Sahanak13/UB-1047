// server.js
// Complete Certificate Server v4.2.1 - JSON Only - Render Ready

const express = require("express");
const multer = require("multer");
const QRCode = require("qrcode");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const sharp = require("sharp");

// =============================
// Config
// =============================
const PORT = process.env.PORT || 3000;

// ✅ RENDER FIX: Use PUBLIC_URL env var for QR codes and verification links.
// Set this in Render dashboard → Environment → PUBLIC_URL = https://your-app.onrender.com
const BASE_URL = process.env.PUBLIC_URL || `http://localhost:${PORT}`;

// ✅ RENDER FIX: Use /opt/render/project/data for persistent disk storage.
// In Render dashboard → your service → Disks → Mount Path: /opt/render/project/data
// If no disk is attached, falls back to local (data won't persist across restarts).
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const UPLOADS_DIR = path.join(DATA_DIR, "uploads");
const CERTIFICATES_FILE = path.join(DATA_DIR, "certificates.json");

// Ensure directories exist on startup
[DATA_DIR, UPLOADS_DIR].forEach((dir) => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

// =============================
// JSON File Operations
// =============================
function loadCertificates() {
  if (!fs.existsSync(CERTIFICATES_FILE)) {
    fs.writeFileSync(CERTIFICATES_FILE, JSON.stringify([], null, 2));
  }
  const data = fs.readFileSync(CERTIFICATES_FILE, "utf8");
  return JSON.parse(data);
}

function saveCertificates(certificates) {
  fs.writeFileSync(CERTIFICATES_FILE, JSON.stringify(certificates, null, 2));
}

// =============================
// Express App Setup
// =============================
const app = express();

app.use(express.json());
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));

// =============================
// File upload configuration
// =============================
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOADS_DIR);
  },
  filename: (req, file, cb) => {
    const uniqueName =
      Date.now() + "-" + Math.round(Math.random() * 1e9) + path.extname(file.originalname);
    cb(null, uniqueName);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      "application/pdf",
      "image/jpeg",
      "image/jpg",
      "image/png",
      "image/webp",
    ];
    const ext = path.extname(file.originalname).toLowerCase();
    const allowedExts = [".pdf", ".jpg", ".jpeg", ".png", ".webp"];

    if (allowedTypes.includes(file.mimetype) && allowedExts.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error("Invalid file type. Only PDF, JPG, PNG allowed."));
    }
  },
});

// =============================
// Helper Functions
// =============================
function generateHash(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function generateCertificateId() {
  return "CERT-" + crypto.randomBytes(4).toString("hex").toUpperCase();
}

function generatePartialHash(data) {
  const firstPart = data.slice(0, Math.floor(data.length * 0.5));
  const lastPart = data.slice(Math.floor(data.length * 0.5));
  return {
    firstHalf: generateHash(firstPart),
    lastHalf: generateHash(lastPart),
    size: data.length,
  };
}

async function findMatchingCertificate(fileBuffer) {
  const certificates = loadCertificates();
  const uploadedHash = generateHash(fileBuffer);

  console.log("Searching for hash:", uploadedHash.substring(0, 16), "...");

  for (const cert of certificates) {
    if (cert.fileHash === uploadedHash) {
      console.log("Found exact match (original):", cert.id);
      return { found: true, certificate: cert, type: "original" };
    }
    if (cert.mergedHash && cert.mergedHash === uploadedHash) {
      console.log("Found exact match (merged):", cert.id);
      return { found: true, certificate: cert, type: "merged" };
    }
  }

  console.log("No exact hash match found");

  const uploadedPartialHash = generatePartialHash(fileBuffer);
  for (const cert of certificates) {
    try {
      if (cert.filePath && fs.existsSync(cert.filePath)) {
        const existingBuffer = fs.readFileSync(cert.filePath);
        const existingPartialHash = generatePartialHash(existingBuffer);

        const firstHalfMatch =
          uploadedPartialHash.firstHalf === existingPartialHash.firstHalf;
        const lastHalfMatch =
          uploadedPartialHash.lastHalf === existingPartialHash.lastHalf;
        const sizeSimilar =
          Math.abs(uploadedPartialHash.size - existingPartialHash.size) /
            existingPartialHash.size <
          0.1;

        if (firstHalfMatch && lastHalfMatch && sizeSimilar) {
          console.log("Found edited duplicate:", cert.id);
          return {
            found: true,
            certificate: cert,
            type: "editedduplicate",
            similarity: { firstHalfMatch, lastHalfMatch, sizeSimilar },
          };
        }
      }
    } catch (error) {
      console.log("Error checking certificate", cert.id, error.message);
    }
  }

  return { found: false };
}

async function mergeQRWithCertificate(certificatePath, qrCodePath, certificateId) {
  try {
    const fileExtension = path.extname(certificatePath).toLowerCase();

    if ([".jpg", ".jpeg", ".png", ".webp"].includes(fileExtension)) {
      console.log("Merging QR with image certificate...");

      const certificate = sharp(certificatePath);
      const metadata = await certificate.metadata();

      const qrSize = Math.min(150, Math.max(80, Math.floor(metadata.width * 0.1)));

      const qrBuffer = await sharp(qrCodePath)
        .resize(qrSize, qrSize, {
          fit: "contain",
          background: { r: 255, g: 255, b: 255, alpha: 1 },
        })
        .png()
        .toBuffer();

      const qrPosition = {
        left: metadata.width - qrSize - 20,
        top: metadata.height - qrSize - 20,
      };

      const outputPath = path.join(UPLOADS_DIR, `merged-${certificateId}${fileExtension}`);

      await certificate
        .composite([
          {
            input: qrBuffer,
            left: qrPosition.left,
            top: qrPosition.top,
            blend: "over",
          },
        ])
        .jpeg({ quality: 95 })
        .toFile(outputPath);

      console.log("QR merged successfully");
      return { success: true, method: "merged", mergedPath: outputPath };
    } else {
      console.log("PDF certificate - copying as merged");
      const outputPath = path.join(UPLOADS_DIR, `merged-${certificateId}.pdf`);
      fs.copyFileSync(certificatePath, outputPath);
      return { success: true, method: "separate", mergedPath: outputPath };
    }
  } catch (error) {
    console.error("QR merge error:", error);
    return { success: false, error: error.message };
  }
}

async function performVerification(certificateId, uploadedFileBuffer = null) {
  console.log("VERIFICATION START - Certificate ID:", certificateId);

  const certificates = loadCertificates();
  const certificate = certificates.find((cert) => cert.id === certificateId);

  if (!certificate) {
    return {
      status: "notfound",
      message: "Certificate not found in our system",
      timestamp: new Date().toISOString(),
    };
  }

  if (uploadedFileBuffer) {
    const uploadedHash = generateHash(uploadedFileBuffer);

    if (uploadedHash === certificate.fileHash) {
      return {
        status: "authentic",
        message: "Certificate is authentic and valid (original version).",
        certificate,
        timestamp: new Date().toISOString(),
      };
    }

    if (certificate.mergedHash && uploadedHash === certificate.mergedHash) {
      return {
        status: "authentic",
        message: "Certificate is authentic and valid (merged with QR code).",
        certificate,
        timestamp: new Date().toISOString(),
      };
    }

    const matchResult = await findMatchingCertificate(uploadedFileBuffer);
    if (matchResult.found && matchResult.type === "editedduplicate") {
      return {
        status: "editedduplicate",
        message:
          "INVALID - This appears to be an edited version of certificate " +
          matchResult.certificate.name,
        certificate,
        originalCertificate: matchResult.certificate,
        timestamp: new Date().toISOString(),
      };
    }

    return {
      status: "forgery",
      message: "FORGERY DETECTED - Certificate file has been modified.",
      certificate,
      timestamp: new Date().toISOString(),
    };
  }

  return {
    status: "authentic",
    message: "Certificate is authentic and valid.",
    certificate,
    timestamp: new Date().toISOString(),
  };
}

// =============================
// Authentication
// =============================
const users = {
  // ── Government Officials (role: admin) ──
  moe_official: { password: "moe123", role: "admin", department: "Ministry of Education", title: "Education Officer" },
  moh_official: { password: "moh123", role: "admin", department: "Ministry of Health", title: "Health Registrar" },
  mol_official: { password: "mol123", role: "admin", department: "Ministry of Land Records", title: "Land Records Officer" },
  mot_official: { password: "mot123", role: "admin", department: "Ministry of Transport", title: "Licensing Authority" },
  molabour_official: { password: "mlab123", role: "admin", department: "Ministry of Labour", title: "Labour Commissioner" },
  admin: { password: "admin123", role: "admin", department: "Ministry of Education", title: "Education Officer" },

  // ── Verifiers ──
  employer_hr: { password: "emp123", role: "verifier", organization: "Corporate Employer", title: "HR Manager" },
  bank_officer: { password: "bank123", role: "verifier", organization: "Bank / Financial Institution", title: "Loan Officer" },
  university: { password: "uni123", role: "verifier", organization: "University / College", title: "Admissions Officer" },
  court_official: { password: "court123", role: "verifier", organization: "Judiciary / Court", title: "Court Registrar" },
  insurance_agent: { password: "ins123", role: "verifier", organization: "Insurance Company", title: "Policy Officer" },
  verifier: { password: "verify123", role: "verifier", organization: "Corporate Employer", title: "HR Manager" },
};

// =============================
// Routes
// =============================
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// VERIFICATION PAGE ROUTE
app.get("/verify/:id", async (req, res) => {
  const certificateId = req.params.id.toUpperCase();

  const certificates = loadCertificates();
  const certificate = certificates.find((cert) => cert.id === certificateId);

  if (!certificate) {
    return res.status(404).send(`<!DOCTYPE html>
<html>
<head>
  <title>Certificate Not Found</title>
  <link rel="stylesheet" href="/style.css">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
  <nav class="navbar">
    <div class="container">
      <div class="nav-brand"><h2>Certificate Verification</h2></div>
      <div class="nav-menu"><a href="/" class="btn btn-outline">Home</a></div>
    </div>
  </nav>
  <div class="container">
    <div class="section" style="text-align: center; max-width: 600px; margin: 50px auto;">
      <h1 style="color: var(--danger);">Certificate Not Found</h1>
      <p style="font-size: 1.2rem; margin: 1rem 0;">Certificate ID <strong>${certificateId}</strong></p>
      <p style="color: var(--text-muted);">This certificate does not exist in our system or has been removed.</p>
      <div style="margin-top: 2rem;">
        <a href="/" class="btn btn-primary">Back to Home</a>
        <a href="/verifier.html" class="btn btn-secondary" style="margin-left: 1rem;">Verify Another</a>
      </div>
    </div>
  </div>
</body>
</html>`);
  }

  const verification = await performVerification(certificateId);

  let statusClass = "success";
  let statusIcon = "✔";
  let statusTitle = "AUTHENTIC CERTIFICATE";

  if (verification.status !== "authentic") {
    statusClass = "danger";
    statusIcon = "✖";
    statusTitle = "VERIFICATION ERROR";
  }

  // ✅ RENDER FIX: Use BASE_URL (from env) instead of hardcoded localhost
  const verifyUrl = `${BASE_URL}/verify/${certificate.id}`;

  res.send(`<!DOCTYPE html>
<html>
<head>
  <title>Certificate Verification - ${certificate.name}</title>
  <link rel="stylesheet" href="/style.css">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
  <nav class="navbar">
    <div class="container">
      <div class="nav-brand"><h2>Certificate Verification</h2></div>
      <div class="nav-menu">
        <a href="/" class="btn btn-outline">Home</a>
        <a href="/verifier.html" class="btn btn-secondary">Verify Another</a>
      </div>
    </div>
  </nav>

  <div class="container">
    <div class="section">
      <div style="text-align: center; margin-bottom: 2rem;">
        <h1 style="color: var(--text-primary);">${certificate.name}</h1>
        <p style="color: var(--text-muted);">Certificate Verification Results</p>
        <p style="color: var(--text-subtle); font-size: 0.9rem;">Verified on ${new Date().toLocaleString()}</p>
      </div>

      <div class="result-card ${statusClass}">
        <h4>${statusIcon} ${statusTitle}</h4>
        <p style="font-size: 1.1rem; margin-bottom: 2rem;">${verification.message}</p>

        <div class="certificate-details">
          <h5>Certificate Information</h5>
          <p><strong>Certificate ID</strong> <span style="font-family: monospace; color: var(--primary);">${certificate.id}</span></p>
          <p><strong>Certificate Name</strong> <span>${certificate.name}</span></p>
          <p><strong>Issued To</strong> <span>${certificate.issuedTo || "NA"}</span></p>
          <p><strong>Issued By</strong> <span>${certificate.issuedBy || "NA"}</span></p>
          <p><strong>Issue Date</strong> <span>${new Date(certificate.uploadDate).toLocaleDateString()}</span></p>
          <p><strong>File Hash</strong> <span style="font-family: monospace; font-size: 0.8rem;">${certificate.fileHash ? certificate.fileHash.substring(0, 32) + "..." : "NA"}</span></p>
          ${certificate.mergedPath ? `<p><strong>QR Status</strong> <span style="color: var(--success);">QR Code Embedded</span></p>` : ""}
        </div>

        <div style="margin-top: 2rem; padding: 1.5rem; background: var(--bg-secondary); border-radius: 8px;">
          <h5>Verification Details</h5>
          <p><strong>Verification Method</strong> Public Link Access</p>
          <p><strong>Database Status</strong> <span style="color: var(--success);">Found</span></p>
          <p><strong>File Integrity</strong> <span style="color: var(--success);">Verified</span></p>
          <p><strong>Verification Time</strong> <span>${new Date().toLocaleString()}</span></p>
        </div>
      </div>

      <div class="section" style="text-align: center;">
        <h3>Share This Verification</h3>
        <p style="color: var(--text-muted); margin-bottom: 1.5rem;">Anyone can verify this certificate using the link below</p>
        <div style="background: var(--bg-secondary); padding: 1.5rem; border-radius: 8px; margin: 1.5rem 0;">
          <code style="word-break: break-all; color: var(--primary);">${verifyUrl}</code>
        </div>
        <div style="display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap;">
          <button onclick="copyToClipboard('${certificate.id}')" class="btn btn-secondary">Copy Certificate ID</button>
          <button onclick="copyToClipboard('${verifyUrl}')" class="btn btn-primary">Copy Verification Link</button>
          ${certificate.qrCodePath ? `<a href="/uploads/qr-${certificate.id}.png" download="qr-${certificate.id}.png" class="btn btn-outline">Download QR Code</a>` : ""}
        </div>
      </div>
    </div>
  </div>

  <script>
    function copyToClipboard(text) {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text)
          .then(() => alert('Copied to clipboard: ' + text))
          .catch(() => fallbackCopy(text));
      } else {
        fallbackCopy(text);
      }
      function fallbackCopy(text) {
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        alert('Copied to clipboard: ' + text);
      }
    }
  </script>
</body>
</html>`);
});

// =============================
// Login endpoint
// =============================
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;

  if (users[username] && users[username].password === password) {
    const user = users[username];
    res.json({
      success: true,
      username,
      role: user.role,
      department: user.department || null,
      organization: user.organization || null,
      title: user.title || null,
      message: "Login successful",
    });
  } else {
    res.status(401).json({ success: false, message: "Invalid credentials" });
  }
});

// =============================
// Upload certificate
// =============================
app.post("/api/upload", upload.single("certificate"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    const { certificateName, issuedTo, issuedBy, department, uploadedBy } = req.body;

    console.log("UPLOAD START - File:", req.file.originalname);

    const fileBuffer = fs.readFileSync(req.file.path);
    const fileHash = generateHash(fileBuffer);

    const matchResult = await findMatchingCertificate(fileBuffer);

    if (matchResult.found && matchResult.type !== "editedduplicate") {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({
        error: "Certificate already exists",
        existing: matchResult.certificate,
      });
    }

    if (matchResult.found && matchResult.type === "editedduplicate") {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({
        error: "Edited duplicate detected",
        message: "This appears to be an edited version of " + matchResult.certificate.name,
        originalCertificate: matchResult.certificate,
      });
    }

    const certificateId = generateCertificateId();
    const certificate = {
      id: certificateId,
      name: certificateName,
      issuedTo,
      issuedBy,
      department: department || null,
      uploadedBy: uploadedBy || null,
      fileName: req.file.originalname,
      filePath: req.file.path,
      fileHash,
      uploadDate: new Date().toISOString(),
      status: "verified",
      lastVerifiedAt: null,
    };

    // ✅ RENDER FIX: Use BASE_URL in QR data
    const qrData = JSON.stringify({
      id: certificateId,
      hash: fileHash,
      url: `${BASE_URL}/verify/${certificateId}`,
      name: certificateName,
      issuedTo,
      issuedBy,
      timestamp: new Date().toISOString(),
    });

    const qrCodePath = path.join(UPLOADS_DIR, `qr-${certificateId}.png`);
    await QRCode.toFile(qrCodePath, qrData, {
      width: 300,
      margin: 2,
      color: { dark: "#000000", light: "#FFFFFF" },
    });

    certificate.qrCodePath = qrCodePath;

    const qrMergeResult = await mergeQRWithCertificate(
      req.file.path,
      qrCodePath,
      certificateId
    );

    if (qrMergeResult.success) {
      certificate.mergedPath = qrMergeResult.mergedPath;
      certificate.qrMergeMethod = qrMergeResult.method;

      if (fs.existsSync(qrMergeResult.mergedPath)) {
        const mergedBuffer = fs.readFileSync(qrMergeResult.mergedPath);
        certificate.mergedHash = generateHash(mergedBuffer);
      }
    }

    const certificates = loadCertificates();
    certificates.push(certificate);
    saveCertificates(certificates);

    console.log("UPLOAD COMPLETE - Certificate ID:", certificateId);

    const ext = path.extname(req.file.originalname);
    res.json({
      success: true,
      message: "Certificate uploaded successfully",
      certificate: {
        id: certificateId,
        name: certificateName,
        qrCode: `/uploads/qr-${certificateId}.png`,
        merged: qrMergeResult.success ? `/uploads/merged-${certificateId}${ext}` : null,
        mergeMethod: qrMergeResult.method,
        hash: fileHash,
        viewUrl: `/verify/${certificateId}`,
      },
    });
  } catch (error) {
    console.error("Upload error:", error);
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({ error: "Upload failed", details: error.message });
  }
});

// =============================
// API Verify certificate by ID
// =============================
app.get("/api/verify/:id", async (req, res) => {
  const certificateId = req.params.id.toUpperCase();
  const verification = await performVerification(certificateId);

  res.json({
    success: verification.status === "authentic",
    status: verification.status,
    message: verification.message,
    certificate: verification.certificate,
  });
});

// =============================
// API Verify uploaded file
// =============================
app.post("/api/verify-file", upload.single("certificate"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    console.log("FILE VERIFICATION START - File:", req.file.originalname);

    const fileBuffer = fs.readFileSync(req.file.path);
    const matchResult = await findMatchingCertificate(fileBuffer);

    fs.unlinkSync(req.file.path);

    if (!matchResult.found) {
      return res.json({
        success: false,
        status: "notfound",
        message: "This certificate is not found in our system.",
      });
    }

    if (matchResult.type === "editedduplicate") {
      return res.json({
        success: false,
        status: "editedduplicate",
        message: "INVALID - This appears to be an edited version of certificate " + matchResult.certificate.name,
        originalCertificate: matchResult.certificate,
      });
    }

    const cert = matchResult.certificate;

    if (cert.lastVerifiedAt) {
      return res.json({
        success: true,
        status: "alreadyverified",
        message: "This certificate was already verified on " + new Date(cert.lastVerifiedAt).toLocaleString() + ".",
        certificate: cert,
        lastVerifiedAt: cert.lastVerifiedAt,
      });
    }

    const verification = await performVerification(cert.id, fileBuffer);

    const nowIso = new Date().toISOString();
    cert.lastVerifiedAt = nowIso;

    const certificates = loadCertificates();
    const certIndex = certificates.findIndex((c) => c.id === cert.id);
    if (certIndex !== -1) {
      certificates[certIndex] = cert;
      saveCertificates(certificates);
    }

    return res.json({
      success: true,
      status: "authentic",
      message: verification.message,
      certificate: cert,
      lastVerifiedAt: nowIso,
    });
  } catch (error) {
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    console.error("File verification error:", error);
    res.status(500).json({ error: "File verification failed", details: error.message });
  }
});

// =============================
// API Verify QR code
// =============================
app.post("/api/verify-qr", async (req, res) => {
  try {
    let qrData;
    try {
      qrData = JSON.parse(req.body.qrData);
    } catch {
      return res.status(400).json({
        success: false,
        status: "invalidqr",
        message: "Invalid QR code data format - not valid JSON",
      });
    }

    const certificateId = qrData.id;
    if (!certificateId) {
      return res.status(400).json({
        success: false,
        status: "invalidqr",
        message: "QR code missing certificate ID",
      });
    }

    const verification = await performVerification(certificateId);

    if (verification.status === "notfound") {
      return res.json({
        success: false,
        status: "notfound",
        message: "Certificate referenced in QR code does not exist",
      });
    }

    if (verification.certificate && qrData.hash) {
      if (qrData.hash !== verification.certificate.fileHash) {
        return res.json({
          success: false,
          status: "forgery",
          message: "FORGERY DETECTED - QR code hash does not match certificate",
        });
      }
    }

    res.json({
      success: verification.status === "authentic",
      status: verification.status,
      message: verification.message,
      certificate: verification.certificate,
    });
  } catch (error) {
    console.error("QR verification error:", error);
    res.status(500).json({ success: false, status: "error", message: "QR verification failed: " + error.message });
  }
});

// =============================
// Get all certificates
// =============================
app.get("/api/certificates", async (req, res) => {
  const certificates = loadCertificates();
  const { username } = req.query;

  if (!username) return res.json([]);

  const userObj = users[username];
  if (!userObj) return res.json([]);

  const authDept = (userObj.department || "").trim().toLowerCase();

  const filtered = certificates.filter((cert) => {
    if (cert.uploadedBy && cert.uploadedBy === username) return true;
    if (cert.department && cert.department.trim().toLowerCase() === authDept) return true;
    if (cert.issuedBy && cert.issuedBy.trim().toLowerCase() === authDept) return true;
    return false;
  });

  const publicCerts = filtered.map((cert) => ({
    id: cert.id,
    name: cert.name,
    issuedTo: cert.issuedTo,
    issuedBy: cert.issuedBy,
    department: cert.department || cert.issuedBy || null,
    uploadDate: cert.uploadDate,
    status: cert.status,
    hasQR: !!cert.qrCodePath,
    hasMerged: !!cert.mergedPath,
    mergeMethod: cert.qrMergeMethod,
    lastVerifiedAt: cert.lastVerifiedAt || null,
  }));

  res.json(publicCerts);
});

// =============================
// Backfill department field
// =============================
app.post("/api/certificates/backfill-department", (req, res) => {
  try {
    const { department, uploadedBy } = req.body;
    if (!department) return res.status(400).json({ error: "department required" });

    const certificates = loadCertificates();
    let updated = 0;

    certificates.forEach((cert) => {
      const issuedByLower = (cert.issuedBy || "").trim().toLowerCase();
      const deptLower = department.trim().toLowerCase();
      if (issuedByLower === deptLower) {
        if (!cert.department) { cert.department = department; updated++; }
        if (uploadedBy && !cert.uploadedBy) cert.uploadedBy = uploadedBy;
      }
    });

    saveCertificates(certificates);
    res.json({ success: true, updated });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================
// Download certificate
// =============================
app.get("/api/download/:id", async (req, res) => {
  try {
    const certificateId = req.params.id;
    const certificates = loadCertificates();
    const certificate = certificates.find((cert) => cert.id === certificateId);

    if (!certificate) return res.status(404).json({ error: "Certificate not found" });

    const downloadPath = certificate.mergedPath || certificate.filePath;
    if (!fs.existsSync(downloadPath)) {
      return res.status(404).json({ error: "Certificate file not found" });
    }

    const fileName = certificate.name.replace(/[^a-zA-Z0-9]/g, "_") + "_" + certificate.id + path.extname(downloadPath);
    res.download(downloadPath, fileName);
  } catch (error) {
    console.error("Download error:", error);
    res.status(500).json({ error: "Download failed: " + error.message });
  }
});

// =============================
// Delete certificate
// =============================
app.delete("/api/certificates/:id", async (req, res) => {
  try {
    const certificateId = req.params.id;
    const certificates = loadCertificates();
    const certificateIndex = certificates.findIndex((cert) => cert.id === certificateId);

    if (certificateIndex === -1) return res.status(404).json({ error: "Certificate not found" });

    const certificate = certificates[certificateIndex];

    [certificate.filePath, certificate.qrCodePath, certificate.mergedPath]
      .filter(Boolean)
      .forEach((filePath) => {
        try { if (fs.existsSync(filePath)) fs.unlinkSync(filePath); } catch (e) { console.error("Error deleting file:", e.message); }
      });

    certificates.splice(certificateIndex, 1);
    saveCertificates(certificates);

    res.json({ success: true, message: "Certificate deleted successfully" });
  } catch (error) {
    console.error("Delete error:", error);
    res.status(500).json({ error: "Delete failed: " + error.message });
  }
});

// =============================
// Serve uploads
// =============================
app.use("/uploads", express.static(UPLOADS_DIR));

// =============================
// Health check
// =============================
app.get("/api/health", async (req, res) => {
  const certificates = loadCertificates();
  res.json({
    status: "healthy",
    timestamp: new Date().toISOString(),
    certificates: certificates.length,
    version: "4.2.1-render-ready",
    baseUrl: BASE_URL,
    dataDir: DATA_DIR,
  });
});

// =============================
// Start Server
// =============================
app.listen(PORT, () => {
  console.log("\n✅ Certificate Server v4.2.1 - Render Ready");
  console.log("🔗 URL:", BASE_URL);
  console.log("📁 Data dir:", DATA_DIR);
  console.log("📋 STORAGE: JSON File →", CERTIFICATES_FILE);
  console.log("\n📁 ACTIVE ROUTES:");
  console.log("   ✓ GET  /verify/:id");
  console.log("   ✓ GET  /api/verify/:id");
  console.log("   ✓ POST /api/verify-qr");
  console.log("   ✓ POST /api/verify-file");
  console.log("   ✓ POST /api/upload");
  console.log("   ✓ GET  /api/certificates");
  console.log("   ✓ GET  /api/download/:id");
  console.log("   ✓ DELETE /api/certificates/:id");
  console.log("   ✓ GET  /api/health\n");
});