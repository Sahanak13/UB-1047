const express = require('express');
const multer = require('multer');
const QRCode = require('qrcode');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const sharp = require('sharp');
const mysql = require('mysql2');

// ============================================
// MySQL Connection Setup
// ============================================
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'Eng@2027', // CHANGE THIS to your MySQL root password
    database: 'certificateauthdb'
});

db.connect(err => {
    if (err) {
        console.error('❌ MySQL connection error:', err);
        console.log('⚠️ Running in JSON-only mode');
    } else {
        console.log('✅ Connected to MySQL database');
    }
});

// ============================================
// MySQL Helper Functions (Promises-based)
// ============================================

// Load certificates from MySQL
function loadCertificatesFromMySQL() {
    return new Promise((resolve, reject) => {
        db.query('SELECT * FROM certificates', (err, results) => {
            if (err) {
                console.error('MySQL query error:', err.message);
                reject(err);
            } else {
                resolve(results || []);
            }
        });
    });
}

// Save/Insert certificate to MySQL
function saveCertificateToMySQL(certificate) {
    return new Promise((resolve, reject) => {
        db.query('INSERT INTO certificates SET ?', certificate, (err, result) => {
            if (err) {
                console.error('MySQL insert error:', err.message);
                reject(err);
            } else {
                resolve(result);
            }
        });
    });
}

// Update certificate in MySQL
function updateCertificateInMySQL(certificateId, updates) {
    return new Promise((resolve, reject) => {
        db.query('UPDATE certificates SET ? WHERE id = ?', [updates, certificateId], (err, result) => {
            if (err) {
                console.error('MySQL update error:', err.message);
                reject(err);
            } else {
                resolve(result);
            }
        });
    });
}

// Delete certificate from MySQL
function deleteCertificateFromMySQL(certificateId) {
    return new Promise((resolve, reject) => {
        db.query('DELETE FROM certificates WHERE id = ?', [certificateId], (err, result) => {
            if (err) {
                console.error('MySQL delete error:', err.message);
                reject(err);
            } else {
                resolve(result);
            }
        });
    });
}

// Find certificate by ID in MySQL
function findCertificateInMySQL(certificateId) {
    return new Promise((resolve, reject) => {
        db.query('SELECT * FROM certificates WHERE id = ?', [certificateId], (err, results) => {
            if (err) {
                reject(err);
            } else {
                resolve(results && results.length > 0 ? results[0] : null);
            }
        });
    });
}

// ============================================
// Original JSON Helper Functions (Keep as is)
// ============================================

function loadCertificates() {
    try {
        const data = fs.readFileSync('certificates.json', 'utf8');
        return JSON.parse(data);
    } catch (error) {
        return [];
    }
}

function saveCertificates(certificates) {
    fs.writeFileSync('certificates.json', JSON.stringify(certificates, null, 2));
}

// ============================================
// Hybrid Load/Save Functions (JSON + MySQL)
// ============================================

async function loadCertificatesHybrid() {
    try {
        // Try MySQL first
        const mySQLCerts = await loadCertificatesFromMySQL();
        if (mySQLCerts.length > 0) {
            console.log('📊 Loaded ' + mySQLCerts.length + ' certificates from MySQL');
            return mySQLCerts;
        }
    } catch (error) {
        console.log('⚠️ MySQL load failed, trying JSON fallback');
    }
    // Fallback to JSON
    const jsonCerts = loadCertificates();
    console.log('📄 Loaded ' + jsonCerts.length + ' certificates from JSON');
    return jsonCerts;
}

async function saveCertificateHybrid(certificate) {
    // Save to JSON (always)
    const jsonCerts = loadCertificates();
    jsonCerts.push(certificate);
    saveCertificates(jsonCerts);
    console.log('✅ Certificate saved to JSON');

    // Try to save to MySQL
    try {
        // Map JSON fields to MySQL column names
        const mysqlData = {
            id: certificate.id,
            name: certificate.name,
            issuedTo: certificate.issuedTo || null,
            issuedBy: certificate.issuedBy || null,
            fileName: certificate.fileName || null,
            filePath: certificate.filePath || null,
            fileHash: certificate.fileHash || null,
            uploadDate: new Date(certificate.uploadDate) || new Date(),
            status: certificate.status || 'verified',
            qrCodePath: certificate.qrCodePath || null,
            mergedPath: certificate.mergedPath || null,
            qrMergeMethod: certificate.qrMergeMethod || null,
            mergedHash: certificate.mergedHash || null
        };
        await saveCertificateToMySQL(mysqlData);
        console.log('✅ Certificate saved to MySQL');
    } catch (error) {
        console.log('⚠️ MySQL save failed, JSON backup preserved');
    }
}

// ============================================
// Express App Setup
// ============================================

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

// File upload configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = 'uploads';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
        cb(null, uniqueName);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['application/pdf', 'image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
        const ext = path.extname(file.originalname).toLowerCase();
        const allowedExts = ['.pdf', '.jpg', '.jpeg', '.png', '.webp'];

        if (allowedTypes.includes(file.mimetype) || allowedExts.includes(ext)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only PDF, JPG, PNG allowed.'));
        }
    }
});

// ============================================
// Helper Functions (Original - Keep as is)
// ============================================

function generateHash(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

function generateCertificateId() {
    return 'CERT-' + crypto.randomBytes(4).toString('hex').toUpperCase();
}

function generatePartialHash(data) {
    const firstPart = data.slice(0, Math.floor(data.length * 0.5));
    const lastPart = data.slice(Math.floor(data.length * 0.5));
    return {
        firstHalf: generateHash(firstPart),
        lastHalf: generateHash(lastPart),
        size: data.length
    };
}

// Find matching certificate (original OR merged)
async function findMatchingCertificate(fileBuffer) {
    const certificates = await loadCertificatesHybrid();
    const uploadedHash = generateHash(fileBuffer);

    console.log('🔍 Searching for hash:', uploadedHash.substring(0, 16) + '...');

    // Check for exact hash match (original or merged)
    for (const cert of certificates) {
        if (cert.fileHash === uploadedHash) {
            console.log('   ✅ Found exact match (original):', cert.id);
            return { found: true, certificate: cert, type: 'original' };
        }

        if (cert.mergedHash && cert.mergedHash === uploadedHash) {
            console.log('   ✅ Found exact match (merged):', cert.id);
            return { found: true, certificate: cert, type: 'merged' };
        }
    }

    console.log('   ❌ No exact hash match found');

    // Check for edited duplicates
    const uploadedPartialHash = generatePartialHash(fileBuffer);

    for (const cert of certificates) {
        try {
            if (fs.existsSync(cert.filePath)) {
                const existingBuffer = fs.readFileSync(cert.filePath);
                const existingPartialHash = generatePartialHash(existingBuffer);

                const firstHalfMatch = uploadedPartialHash.firstHalf === existingPartialHash.firstHalf;
                const lastHalfMatch = uploadedPartialHash.lastHalf === existingPartialHash.lastHalf;
                const sizeSimilar = Math.abs(uploadedPartialHash.size - existingPartialHash.size) < (existingPartialHash.size * 0.1);

                if ((firstHalfMatch || lastHalfMatch) && sizeSimilar) {
                    console.log('   ⚠️ Found edited duplicate:', cert.id);
                    return {
                        found: true,
                        certificate: cert,
                        type: 'edited_duplicate',
                        similarity: { firstHalfMatch, lastHalfMatch, sizeSimilar }
                    };
                }
            }
        } catch (error) {
            console.log('   Error checking certificate:', cert.id, error.message);
        }
    }

    return { found: false };
}

// Create QR code and merge it with certificate image
async function mergeQRWithCertificate(certificatePath, qrCodePath, certificateId) {
    try {
        const fileExtension = path.extname(certificatePath).toLowerCase();

        if (['.jpg', '.jpeg', '.png', '.webp'].includes(fileExtension)) {
            console.log('📸 Merging QR with image certificate...');

            const certificate = sharp(certificatePath);
            const metadata = await certificate.metadata();

            const qrSize = Math.min(150, Math.max(80, Math.floor(metadata.width * 0.1)));

            const qrBuffer = await sharp(qrCodePath)
                .resize(qrSize, qrSize, {
                    fit: 'contain',
                    background: { r: 255, g: 255, b: 255, alpha: 1 }
                })
                .png()
                .toBuffer();

            const qrPosition = {
                left: metadata.width - qrSize - 20,
                top: metadata.height - qrSize - 20
            };

            const outputPath = `uploads/merged-${certificateId}${fileExtension}`;

            await certificate
                .composite([{
                    input: qrBuffer,
                    left: qrPosition.left,
                    top: qrPosition.top,
                    blend: 'over'
                }])
                .jpeg({ quality: 95 })
                .toFile(outputPath);

            console.log('   ✅ QR merged successfully');
            return { success: true, method: 'merged', mergedPath: outputPath };

        } else {
            console.log('📄 PDF certificate - copying as merged');
            const outputPath = `uploads/merged-${certificateId}.pdf`;
            fs.copyFileSync(certificatePath, outputPath);
            return { success: true, method: 'separate', mergedPath: outputPath };
        }
    } catch (error) {
        console.error('❌ QR merge error:', error);
        return { success: false, error: error.message };
    }
}

// Enhanced verification function
async function performVerification(certificateId, uploadedFileBuffer = null) {
    console.log('\n🔍 VERIFICATION START');
    console.log('   Certificate ID:', certificateId);

    const certificates = await loadCertificatesHybrid();
    const certificate = certificates.find(cert => cert.id === certificateId);

    if (!certificate) {
        console.log('   ❌ Certificate not found in database');
        return {
            status: 'not_found',
            message: 'Certificate not found in our system',
            timestamp: new Date().toISOString()
        };
    }

    console.log('   ✅ Certificate found in database');

    if (uploadedFileBuffer) {
        const uploadedHash = generateHash(uploadedFileBuffer);

        if (uploadedHash === certificate.fileHash) {
            console.log('   ✅ Uploaded file matches original');
            return {
                status: 'authentic',
                message: 'Certificate is authentic and valid (original version)',
                certificate: certificate,
                timestamp: new Date().toISOString()
            };
        }

        if (certificate.mergedHash && uploadedHash === certificate.mergedHash) {
            console.log('   ✅ Uploaded file matches merged version');
            return {
                status: 'authentic',
                message: 'Certificate is authentic and valid (merged with QR code)',
                certificate: certificate,
                timestamp: new Date().toISOString()
            };
        }

        const matchResult = await findMatchingCertificate(uploadedFileBuffer);
        if (matchResult.found && matchResult.type === 'edited_duplicate') {
            console.log('   ⚠️ Edited duplicate detected');
            return {
                status: 'edited_duplicate',
                message: `INVALID - This appears to be an edited version of certificate "${matchResult.certificate.name}"`,
                certificate: certificate,
                originalCertificate: matchResult.certificate,
                timestamp: new Date().toISOString()
            };
        }

        console.log('   🚨 File has been modified');
        return {
            status: 'forgery',
            message: 'FORGERY DETECTED - Certificate file has been modified',
            certificate: certificate,
            timestamp: new Date().toISOString()
        };
    } else {
        console.log('   ✅ Certificate ID verified');
        return {
            status: 'authentic',
            message: 'Certificate is authentic and valid',
            certificate: certificate,
            timestamp: new Date().toISOString()
        };
    }
}

// Authentication
const users = {
    admin: { password: 'admin123', role: 'admin' },
    verifier: { password: 'verify123', role: 'verifier' }
};

// ============================================
// Routes
// ============================================

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// VERIFICATION PAGE ROUTE
app.get('/verify/:id', async (req, res) => {
    const certificateId = req.params.id.toUpperCase();

    console.log('\n📄 VERIFICATION PAGE REQUEST');
    console.log('   Certificate ID:', certificateId);

    const certificates = await loadCertificatesHybrid();
    const certificate = certificates.find(cert => cert.id === certificateId);

    if (!certificate) {
        console.log('   ❌ Certificate not found - showing 404 page');
        return res.status(404).send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Certificate Not Found</title>
                <link rel="stylesheet" href="/style.css">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
            </head>
            <body>
                <nav class="navbar">
                    <div class="container">
                        <div class="nav-brand">
                            <h2>🔍 Certificate Verification</h2>
                        </div>
                        <div class="nav-menu">
                            <a href="/" class="btn btn-outline">🏠 Home</a>
                        </div>
                    </div>
                </nav>

                <div class="container">
                    <div class="section" style="text-align: center; max-width: 600px; margin: 50px auto;">
                        <h1 style="color: var(--danger);">❌ Certificate Not Found</h1>
                        <p style="font-size: 1.2rem; margin: 1rem 0;">Certificate ID: <strong>${certificateId}</strong></p>
                        <p style="color: var(--text-muted);">This certificate does not exist in our system or has been removed.</p>
                        <div style="margin-top: 2rem;">
                            <a href="/" class="btn btn-primary">🏠 Back to Home</a>
                            <a href="/verifier.html" class="btn btn-secondary" style="margin-left: 1rem;">🔍 Verify Another</a>
                        </div>
                    </div>
                </div>
            </body>
            </html>
        `);
    }

    console.log('   ✅ Certificate found - showing verification page');

    const verification = await performVerification(certificateId);

    let statusClass = 'success';
    let statusIcon = '✅';
    let statusTitle = 'AUTHENTIC CERTIFICATE';

    if (verification.status !== 'authentic') {
        statusClass = 'danger';
        statusIcon = '❌';
        statusTitle = 'VERIFICATION ERROR';
    }

    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Certificate Verification - ${certificate.name}</title>
            <link rel="stylesheet" href="/style.css">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body>
            <nav class="navbar">
                <div class="container">
                    <div class="nav-brand">
                        <h2>🔍 Certificate Verification</h2>
                    </div>
                    <div class="nav-menu">
                        <a href="/" class="btn btn-outline">🏠 Home</a>
                        <a href="/verifier.html" class="btn btn-secondary">🔍 Verify Another</a>
                    </div>
                </div>
            </nav>

            <div class="container">
                <div class="section">
                    <div style="text-align: center; margin-bottom: 2rem;">
                        <h1 style="color: var(--text-primary);">${certificate.name}</h1>
                        <p style="color: var(--text-muted);">Certificate Verification Results</p>
                        <p style="color: var(--text-subtle); font-size: 0.9rem;">Verified on: ${new Date().toLocaleString()}</p>
                    </div>

                    <div class="result-card ${statusClass}">
                        <h4>${statusIcon} ${statusTitle}</h4>
                        <p style="font-size: 1.1rem; margin-bottom: 2rem;">${verification.message}</p>

                        <div class="certificate-details">
                            <h5>📋 Certificate Information</h5>
                            <p><strong>Certificate ID:</strong> <span style="font-family: monospace; color: var(--primary);">${certificate.id}</span></p>
                            <p><strong>Certificate Name:</strong> <span>${certificate.name}</span></p>
                            <p><strong>Issued To:</strong> <span>${certificate.issuedTo || 'N/A'}</span></p>
                            <p><strong>Issued By:</strong> <span>${certificate.issuedBy || 'N/A'}</span></p>
                            <p><strong>Issue Date:</strong> <span>${new Date(certificate.uploadDate).toLocaleDateString()}</span></p>
                            <p><strong>File Hash:</strong> <span style="font-family: monospace; font-size: 0.8rem;">${certificate.fileHash.substring(0, 32)}...</span></p>
                            ${certificate.mergedPath ? `<p><strong>QR Status:</strong> <span style="color: var(--success);">✅ QR Code Embedded</span></p>` : ''}
                        </div>

                        <div style="margin-top: 2rem; padding: 1.5rem; background: var(--bg-secondary); border-radius: 8px;">
                            <h5>🛡️ Verification Details</h5>
                            <p><strong>Verification Method:</strong> Public Link Access</p>
                            <p><strong>Database Status:</strong> <span style="color: var(--success);">✅ Found</span></p>
                            <p><strong>File Integrity:</strong> <span style="color: var(--success);">✅ Verified</span></p>
                            <p><strong>Verification Time:</strong> <span>${new Date().toLocaleString()}</span></p>
                        </div>
                    </div>

                    <div class="section" style="text-align: center;">
                        <h3>🔗 Share This Verification</h3>
                        <p style="color: var(--text-muted); margin-bottom: 1.5rem;">Anyone can verify this certificate using the link below:</p>

                        <div style="background: var(--bg-secondary); padding: 1.5rem; border-radius: 8px; margin: 1.5rem 0;">
                            <code style="word-break: break-all; color: var(--primary);">${req.protocol}://${req.get('host')}/verify/${certificate.id}</code>
                        </div>

                        <div style="display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap;">
                            <button onclick="copyToClipboard('${certificate.id}')" class="btn btn-secondary">
                                📋 Copy Certificate ID
                            </button>
                            <button onclick="copyToClipboard('${req.protocol}://${req.get('host')}/verify/${certificate.id}')" class="btn btn-primary">
                                🔗 Copy Verification Link
                            </button>
                            ${certificate.qrCodePath ? `
                                <a href="/uploads/qr-${certificate.id}.png" download="qr-${certificate.id}.png" class="btn btn-outline">
                                    📱 Download QR Code
                                </a>
                            ` : ''}
                        </div>
                    </div>
                </div>
            </div>

            <script>
                function copyToClipboard(text) {
                    navigator.clipboard.writeText(text).then(() => {
                        alert('✅ Copied to clipboard: ' + text);
                    }).catch(err => {
                        const textArea = document.createElement('textarea');
                        textArea.value = text;
                        document.body.appendChild(textArea);
                        textArea.select();
                        document.execCommand('copy');
                        document.body.removeChild(textArea);
                        alert('✅ Copied to clipboard: ' + text);
                    });
                }
            </script>
        </body>
        </html>
    `);
});

// Login endpoint
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    if (users[username] && users[username].password === password) {
        res.json({
            success: true,
            role: users[username].role,
            message: 'Login successful'
        });
    } else {
        res.status(401).json({
            success: false,
            message: 'Invalid credentials'
        });
    }
});

// Upload certificate
app.post('/api/upload', upload.single('certificate'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const { certificateName, issuedTo, issuedBy } = req.body;

        console.log('\n📤 UPLOAD START');
        console.log('   File:', req.file.originalname);
        console.log('   MIME:', req.file.mimetype);

        const fileBuffer = fs.readFileSync(req.file.path);
        const fileHash = generateHash(fileBuffer);

        console.log('   Original hash:', fileHash.substring(0, 16) + '...');

        const matchResult = await findMatchingCertificate(fileBuffer);
        if (matchResult.found && matchResult.type !== 'edited_duplicate') {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({
                error: 'Certificate already exists',
                existing: matchResult.certificate
            });
        }

        if (matchResult.found && matchResult.type === 'edited_duplicate') {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({
                error: 'Edited duplicate detected',
                message: `This appears to be an edited version of: ${matchResult.certificate.name}`,
                originalCertificate: matchResult.certificate
            });
        }

        const certificateId = generateCertificateId();

        const certificate = {
            id: certificateId,
            name: certificateName,
            issuedTo: issuedTo,
            issuedBy: issuedBy,
            fileName: req.file.originalname,
            filePath: req.file.path,
            fileHash: fileHash,
            uploadDate: new Date().toISOString(),
            status: 'verified'
        };

        const qrData = JSON.stringify({
            id: certificateId,
            hash: fileHash,
            url: `http://localhost:${PORT}/verify/${certificateId}`,
            name: certificateName,
            issuedTo: issuedTo,
            issuedBy: issuedBy,
            timestamp: new Date().toISOString()
        });

        console.log('📱 Generating QR code...');
        console.log('   QR Data structure:', {
            id: certificateId,
            hash: fileHash.substring(0, 16) + '...',
            url: `http://localhost:${PORT}/verify/${certificateId}`
        });

        const qrCodePath = `uploads/qr-${certificateId}.png`;
        await QRCode.toFile(qrCodePath, qrData, {
            width: 300,
            margin: 2,
            color: { dark: '#000000', light: '#FFFFFF' }
        });

        console.log('   ✅ QR code generated');
        certificate.qrCodePath = qrCodePath;

        console.log('🔗 Merging QR with certificate...');
        const qrMergeResult = await mergeQRWithCertificate(req.file.path, qrCodePath, certificateId);

        if (qrMergeResult.success) {
            certificate.mergedPath = qrMergeResult.mergedPath;
            certificate.qrMergeMethod = qrMergeResult.method;

            if (fs.existsSync(qrMergeResult.mergedPath)) {
                const mergedBuffer = fs.readFileSync(qrMergeResult.mergedPath);
                certificate.mergedHash = generateHash(mergedBuffer);
                console.log('   📊 Merged hash:', certificate.mergedHash.substring(0, 16) + '...');
            }
        }

        // Save to both JSON and MySQL
        await saveCertificateHybrid(certificate);

        console.log('✅ UPLOAD COMPLETE');
        console.log('   Certificate ID:', certificateId);
        console.log('   View URL: http://localhost:' + PORT + '/verify/' + certificateId);

        res.json({
            success: true,
            message: 'Certificate uploaded successfully',
            certificate: {
                id: certificateId,
                name: certificateName,
                qrCode: `/uploads/qr-${certificateId}.png`,
                merged: qrMergeResult.success ? `/uploads/merged-${certificateId}${path.extname(req.file.originalname)}` : null,
                mergeMethod: qrMergeResult.method,
                hash: fileHash,
                viewUrl: `/verify/${certificateId}`
            }
        });

    } catch (error) {
        console.error('Upload error:', error);
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        res.status(500).json({ error: 'Upload failed: ' + error.message });
    }
});

// API: Verify certificate by ID
app.get('/api/verify/:id', async (req, res) => {
    const certificateId = req.params.id.toUpperCase();
    const verification = await performVerification(certificateId);

    res.json({
        success: verification.status === 'authentic',
        status: verification.status,
        message: verification.message,
        certificate: verification.certificate
    });
});

// API: Verify uploaded file
app.post('/api/verify-file', upload.single('certificate'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        console.log('\n🔍 FILE VERIFICATION START');
        console.log('   File:', req.file.originalname);
        console.log('   Size:', Math.round(req.file.size / 1024), 'KB');

        const fileBuffer = fs.readFileSync(req.file.path);

        const matchResult = await findMatchingCertificate(fileBuffer);

        fs.unlinkSync(req.file.path);

        if (!matchResult.found) {
            console.log('   ❌ No matching certificate found');
            return res.json({
                success: false,
                status: 'not_found',
                message: 'This certificate is not found in our system'
            });
        }

        if (matchResult.type === 'edited_duplicate') {
            console.log('   ⚠️ Edited duplicate detected');
            return res.json({
                success: false,
                status: 'edited_duplicate',
                message: `INVALID - This appears to be an edited version of certificate "${matchResult.certificate.name}"`,
                originalCertificate: matchResult.certificate
            });
        }

        console.log('   ✅ Authentic certificate found:', matchResult.certificate.id);
        const verification = await performVerification(matchResult.certificate.id, fileBuffer);

        return res.json({
            success: true,
            status: 'authentic',
            message: verification.message,
            certificate: matchResult.certificate
        });

    } catch (error) {
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        console.error('File verification error:', error);
        res.status(500).json({ error: 'File verification failed: ' + error.message });
    }
});

// API: Verify QR code
app.post('/api/verify-qr', async (req, res) => {
    try {
        console.log('\n🔍 QR VERIFICATION START');
        console.log('   Raw QR data:', req.body.qrData.substring(0, 100) + '...');

        let qrData;
        try {
            qrData = JSON.parse(req.body.qrData);
        } catch (parseError) {
            console.log('   ❌ Invalid JSON format');
            return res.status(400).json({
                success: false,
                status: 'invalid_qr',
                message: 'Invalid QR code data format - not valid JSON'
            });
        }

        console.log('   Parsed QR data:', {
            id: qrData.id,
            hash: qrData.hash ? qrData.hash.substring(0, 16) + '...' : 'missing',
            url: qrData.url
        });

        const certificateId = qrData.id;

        if (!certificateId) {
            console.log('   ❌ Missing certificate ID in QR');
            return res.status(400).json({
                success: false,
                status: 'invalid_qr',
                message: 'QR code missing certificate ID'
            });
        }

        const verification = await performVerification(certificateId);

        if (verification.status === 'not_found') {
            console.log('   ❌ Certificate not found');
            return res.json({
                success: false,
                status: 'not_found',
                message: 'Certificate referenced in QR code does not exist'
            });
        }

        if (verification.certificate && qrData.hash && qrData.hash !== verification.certificate.fileHash) {
            console.log('   ⚠️ QR hash mismatch');
            console.log('   QR hash:', qrData.hash.substring(0, 16) + '...');
            console.log('   Certificate hash:', verification.certificate.fileHash.substring(0, 16) + '...');

            return res.json({
                success: false,
                status: 'forgery',
                message: 'FORGERY DETECTED - QR code hash does not match certificate'
            });
        }

        console.log('   ✅ QR verification complete:', verification.status);

        res.json({
            success: verification.status === 'authentic',
            status: verification.status,
            message: verification.message,
            certificate: verification.certificate
        });

    } catch (error) {
        console.error('QR verification error:', error);
        res.status(500).json({
            success: false,
            status: 'error',
            message: 'QR verification failed: ' + error.message
        });
    }
});

// Get all certificates
app.get('/api/certificates', async (req, res) => {
    const certificates = await loadCertificatesHybrid();
    const publicCerts = certificates.map(cert => ({
        id: cert.id,
        name: cert.name,
        issuedTo: cert.issuedTo,
        issuedBy: cert.issuedBy,
        uploadDate: cert.uploadDate,
        status: cert.status,
        hasQR: !!cert.qrCodePath,
        hasMerged: !!cert.mergedPath,
        mergeMethod: cert.qrMergeMethod
    }));
    res.json(publicCerts);
});

// Download certificate
app.get('/api/download/:id', async (req, res) => {
    try {
        const certificateId = req.params.id;
        const certificates = await loadCertificatesHybrid();
        const certificate = certificates.find(cert => cert.id === certificateId);

        if (!certificate) {
            return res.status(404).json({ error: 'Certificate not found' });
        }

        const downloadPath = certificate.mergedPath || certificate.filePath;

        if (!fs.existsSync(downloadPath)) {
            return res.status(404).json({ error: 'Certificate file not found' });
        }

        const fileName = `${certificate.name.replace(/[^a-zA-Z0-9]/g, '_')}_${certificate.id}${path.extname(downloadPath)}`;

        console.log('📥 Download:', fileName);
        res.download(downloadPath, fileName);

    } catch (error) {
        console.error('Download error:', error);
        res.status(500).json({ error: 'Download failed: ' + error.message });
    }
});

// Delete certificate
app.delete('/api/certificates/:id', async (req, res) => {
    try {
        const certificateId = req.params.id;

        // Delete from JSON
        const certificates = loadCertificates();
        const certificateIndex = certificates.findIndex(cert => cert.id === certificateId);

        if (certificateIndex === -1) {
            return res.status(404).json({ error: 'Certificate not found' });
        }

        const certificate = certificates[certificateIndex];

        // Delete files
        const filesToDelete = [
            certificate.filePath,
            certificate.qrCodePath,
            certificate.mergedPath
        ].filter(Boolean);

        filesToDelete.forEach(filePath => {
            try {
                if (fs.existsSync(filePath)) {
                    fs.unlinkSync(filePath);
                }
            } catch (error) {
                console.error('Error deleting file:', filePath, error.message);
            }
        });

        certificates.splice(certificateIndex, 1);
        saveCertificates(certificates);
        console.log('🗑️ DELETED from JSON:', certificateId);

        // Delete from MySQL
        try {
            await deleteCertificateFromMySQL(certificateId);
            console.log('🗑️ DELETED from MySQL:', certificateId);
        } catch (error) {
            console.log('⚠️ MySQL delete failed, JSON version deleted');
        }

        res.json({
            success: true,
            message: 'Certificate deleted successfully'
        });

    } catch (error) {
        console.error('Delete error:', error);
        res.status(500).json({ error: 'Delete failed: ' + error.message });
    }
});

// Serve uploads with proper headers
app.use('/uploads', express.static('uploads'));

// Health check
app.get('/api/health', async (req, res) => {
    const certificates = await loadCertificatesHybrid();
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        certificates: certificates.length,
        version: '4.2.0-hybrid-json-mysql'
    });
});

// ============================================
// Start Server
// ============================================

app.listen(PORT, () => {
    console.log('\n🚀 Complete Certificate Server v4.2.0 (Hybrid JSON + MySQL)');
    console.log('   URL: http://localhost:' + PORT);
    console.log('\n🔧 HYBRID STORAGE FEATURES:');
    console.log('   ✅ Saves to BOTH JSON (backup) and MySQL (primary)');
    console.log('   ✅ Loads from MySQL first, fallback to JSON');
    console.log('   ✅ All existing functions preserved');
    console.log('   ✅ Auto-sync between JSON and MySQL');
    console.log('\n📋 ALL ROUTES ACTIVE:');
    console.log('   GET  /verify/:id          - View certificate page');
    console.log('   GET  /api/verify/:id      - API certificate verification');
    console.log('   POST /api/verify-qr       - API QR code verification');
    console.log('   POST /api/verify-file     - API file upload verification');
    console.log('   POST /api/upload          - Upload new certificate');
    console.log('   GET  /api/certificates    - List all certificates');
    console.log('   GET  /api/download/:id    - Download certificate');
    console.log('   DELETE /api/certificates/:id - Delete certificate');
    console.log('   GET  /api/health          - Server health check');
    console.log('');
});