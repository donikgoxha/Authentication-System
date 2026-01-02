import express from "express";
import cors from "cors";
import fs from "fs";
import path from "path";
import https from "https";
import {fileURLToPath} from "url";
import {v4 as uuidv4} from "uuid";
import bcrypt from "bcrypt";
import nodemailer from "nodemailer";
import forge from "node-forge";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 5002;
const DB_FILE = "./data.json";
const CERT_DIR = "./certificates";
const SALT_ROUNDS = 10;

app.use(express.json());
app.use(cors({
    origin: ["https://localhost:5002", "http://localhost:5173"], credentials: true,
}));

if (!fs.existsSync(CERT_DIR)) {
    fs.mkdirSync(CERT_DIR, {recursive: true});
}

app.use(express.static(path.join(__dirname, 'build')));

let transporter;

async function createEmailTransporter() {
    let testAccount = await nodemailer.createTestAccount();

    transporter = nodemailer.createTransport({
        host: "smtp.ethereal.email", port: 587, secure: false, auth: {
            user: testAccount.user, pass: testAccount.pass,
        },
    });

    console.log("Email transporter created!");
    console.log("Test email account:", testAccount.user);
}

createEmailTransporter();

let db = {
    users: {}, roles: {
        admin: {name: "Administrator", permissions: ["read", "write", "delete", "manage_users", "manage_roles"]},
        manager: {name: "Manager", permissions: ["read", "write", "approve"]},
        user: {name: "Regular User", permissions: ["read"]}
    }, resources: {
        documents: {name: "Documents", requiredPermissions: ["read"]},
        reports: {name: "Reports", requiredPermissions: ["read", "write"]},
        admin_panel: {name: "Admin Panel", requiredPermissions: ["manage_users"]}
    }, certificates: {}
};

if (fs.existsSync(DB_FILE)) {
    try {
        const data = JSON.parse(fs.readFileSync(DB_FILE));
        db = {...db, ...data};
    } catch (e) {
        console.error("Error reading database file. Using defaults.");
    }
}

let sessions = {};
let twoFACodes = {};
let temporaryAccess = {};

function saveDB() {
    fs.writeFileSync(DB_FILE, JSON.stringify({
        users: db.users, roles: db.roles, resources: db.resources, certificates: db.certificates
    }, null, 2));
}

function isValidUsername(username) {
    return /^[a-zA-Z0-9_]{3,15}$/.test(username);
}

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isStrongPassword(password) {
    return (password.length >= 8 && /[A-Z]/.test(password) && /[a-z]/.test(password) && /\d/.test(password) && /[!@#$%^&*]/.test(password));
}

async function sendEmail2FA(email, username, code) {
    try {
        const info = await transporter.sendMail({
            from: '"Secure Auth System" <noreply@authsystem.com>',
            to: email,
            subject: "Your 2FA Verification Code",
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="background: #333; padding: 30px; border-radius: 10px 10px 0 0;">
                        <h1 style="color: white; margin: 0; text-align: center;">Authentication Code</h1>
                    </div>
                    <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px;">
                        <p style="font-size: 16px; color: #333;">Hello <strong>${username}</strong>,</p>
                        <p style="font-size: 14px; color: #666;">Your verification code is:</p>
                        <div style="background: white; padding: 20px; text-align: center; margin: 20px 0; border-radius: 8px; border: 2px dashed #000;">
                            <h1 style="color: #000; letter-spacing: 8px; margin: 0; font-size: 32px;">${code}</h1>
                        </div>
                        <p style="font-size: 14px; color: #666;">This code will expire in <strong>5 minutes</strong>.</p>
                        <p style="font-size: 14px; color: #666;">If you didn't request this code, please ignore this email.</p>
                    </div>
                </div>
            `,
        });

        console.log("Email sent: %s", info.messageId);
        return nodemailer.getTestMessageUrl(info);
    } catch (error) {
        console.error("Error sending email:", error);
        return null;
    }
}

function issue2FACode(username, email) {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 5 * 60 * 1000;
    twoFACodes[username] = {code, expiresAt};
    console.log(`2FA code for ${username}: ${code}`);
    sendEmail2FA(email, username, code).then(previewUrl => {
        if (previewUrl) console.log(`Email preview: ${previewUrl}`);
    });
    return code;
}

function verify2FA(username, code) {
    const entry = twoFACodes[username];
    if (!entry) return false;
    const valid = entry.code === code && Date.now() < entry.expiresAt;
    if (valid) delete twoFACodes[username];
    return valid;
}

function createSession(username) {
    const sessionId = uuidv4();
    sessions[sessionId] = {username, createdAt: Date.now(), expiresAt: Date.now() + 2 * 60 * 60 * 1000};
    return sessionId;
}

function validateSession(sessionId) {
    const session = sessions[sessionId];
    if (!session) return null;
    if (Date.now() > session.expiresAt) {
        delete sessions[sessionId];
        return null;
    }
    return session;
}

function hasPermission(username, permission) {
    const user = db.users[username];
    if (!user) return false;
    const role = db.roles[user.role];
    if (!role) return false;
    return role.permissions.includes(permission);
}

function canAccessResource(username, resourceName) {
    const user = db.users[username];
    const resource = db.resources[resourceName];
    if (!user || !resource) return false;
    const role = db.roles[user.role];
    if (!role) return false;
    return resource.requiredPermissions.every(perm => role.permissions.includes(perm));
}

function generateKeyPair() {
    return forge.pki.rsa.generateKeyPair(2048);
}

function createCertificate(subject, issuer, issuerKeys, isCA = false, pathLen = null) {
    const cert = forge.pki.createCertificate();
    cert.publicKey = subject.publicKey;
    cert.serialNumber = '01' + Date.now().toString(16);
    const notBefore = new Date();
    const notAfter = new Date();
    notAfter.setFullYear(notBefore.getFullYear() + 10);
    cert.validity.notBefore = notBefore;
    cert.validity.notAfter = notAfter;
    cert.setSubject(subject.attrs);
    cert.setIssuer(issuer.attrs);

    if (isCA) {
        cert.setExtensions([{name: 'basicConstraints', cA: true, pathLenConstraint: pathLen}, {
            name: 'keyUsage', keyCertSign: true, digitalSignature: true
        }]);
    } else {
        cert.setExtensions([{name: 'basicConstraints', cA: false}, {
            name: 'keyUsage', digitalSignature: true, keyEncipherment: true
        }, {name: 'subjectAltName', altNames: [{type: 2, value: 'localhost'}]}]);
    }
    cert.sign(issuerKeys.privateKey, forge.md.sha256.create());
    return cert;
}

function saveCertificate(name, cert, keys) {
    const certPem = forge.pki.certificateToPem(cert);
    const keyPem = forge.pki.privateKeyToPem(keys.privateKey);

    fs.writeFileSync(`${CERT_DIR}/${name}.crt`, certPem);
    fs.writeFileSync(`${CERT_DIR}/${name}.key`, keyPem);

    return {
        certificate: certPem, privateKey: keyPem
    };
}

app.post("/certificates/generate-hierarchy", (req, res) => {
    const sessionId = req.headers["x-session-id"];
    const session = validateSession(sessionId);

    if (!session) {
        return res.status(401).json({
            success: false, message: "Invalid or expired session."
        });
    }

    try {
        console.log("\n=== Generating PKI Hierarchy ===\n");

        console.log("1. Generating Root CA (FINKI CA)...");
        const rootKeys = generateKeyPair();
        const rootCert = createCertificate({
            publicKey: rootKeys.publicKey, attrs: [{name: 'commonName', value: 'FINKI CA'}, {
                name: 'countryName', value: 'MK'
            }, {name: 'organizationName', value: 'FINKI'}]
        }, {
            attrs: [{name: 'commonName', value: 'FINKI CA'}, {
                name: 'countryName', value: 'MK'
            }, {name: 'organizationName', value: 'FINKI'}]
        }, rootKeys, true, 2);
        saveCertificate('FINKI_CA', rootCert, rootKeys);
        console.log("✓ Root CA generated and saved");

        console.log("\n2. Generating IB CA (Intermediate)...");
        const ibKeys = generateKeyPair();
        const ibCert = createCertificate({
            publicKey: ibKeys.publicKey,
            attrs: [{name: 'commonName', value: 'IB CA'}, {name: 'countryName', value: 'MK'}, {
                name: 'organizationName', value: 'FINKI'
            }, {name: 'organizationalUnitName', value: 'Information Security'}]
        }, {
            attrs: [{name: 'commonName', value: 'FINKI CA'}, {
                name: 'countryName', value: 'MK'
            }, {name: 'organizationName', value: 'FINKI'}]
        }, rootKeys, true, 1);
        saveCertificate('IB_CA', ibCert, ibKeys);
        console.log("✓ IB CA generated and saved");

        console.log("\n3. Generating Lab CA (Intermediate)...");
        const labKeys = generateKeyPair();
        const labCert = createCertificate({
            publicKey: labKeys.publicKey, attrs: [{name: 'commonName', value: 'Lab CA'}, {
                name: 'countryName', value: 'MK'
            }, {name: 'organizationName', value: 'FINKI'}, {name: 'organizationalUnitName', value: 'Lab'}]
        }, {
            attrs: [{name: 'commonName', value: 'IB CA'}, {name: 'countryName', value: 'MK'}, {
                name: 'organizationName', value: 'FINKI'
            }, {name: 'organizationalUnitName', value: 'Information Security'}]
        }, ibKeys, true, 0);
        saveCertificate('Lab_CA', labCert, labKeys);
        console.log("✓ Lab CA generated and saved");

        console.log("\n4. Generating Server Certificate...");
        const serverKeys = generateKeyPair();
        const serverCert = createCertificate({
            publicKey: serverKeys.publicKey, attrs: [{name: 'commonName', value: `server-${session.username}`}, {
                name: 'countryName', value: 'MK'
            }, {name: 'organizationName', value: 'FINKI'}]
        }, {
            attrs: [{name: 'commonName', value: 'Lab CA'}, {
                name: 'countryName', value: 'MK'
            }, {name: 'organizationName', value: 'FINKI'}, {name: 'organizationalUnitName', value: 'Lab'}]
        }, labKeys, false);
        saveCertificate(`server_${session.username}`, serverCert, serverKeys);
        console.log("✓ Server certificate generated and saved");

        console.log("\n5. Generating Client Certificate...");
        const clientKeys = generateKeyPair();
        const clientCert = createCertificate({
            publicKey: clientKeys.publicKey, attrs: [{name: 'commonName', value: `client-${session.username}`}, {
                name: 'countryName', value: 'MK'
            }, {name: 'organizationName', value: 'FINKI'}]
        }, {
            attrs: [{name: 'commonName', value: 'Lab CA'}, {
                name: 'countryName', value: 'MK'
            }, {name: 'organizationName', value: 'FINKI'}, {name: 'organizationalUnitName', value: 'Lab'}]
        }, labKeys, false);
        saveCertificate(`client_${session.username}`, clientCert, clientKeys);
        console.log("✓ Client certificate generated and saved");

        console.log("\n=== PKI Hierarchy Generation Complete ===\n");

        db.certificates[session.username] = {
            generatedAt: new Date().toISOString(),
            certificates: ['FINKI_CA', 'IB_CA', 'Lab_CA', `server_${session.username}`, `client_${session.username}`]
        };
        saveDB();

        res.json({
            success: true, message: "PKI Hierarchy generated successfully!", certificates: {
                root: "FINKI_CA",
                intermediate1: "IB_CA",
                intermediate2: "Lab_CA",
                server: `server_${session.username}`,
                client: `client_${session.username}`
            }, location: CERT_DIR
        });

    } catch (error) {
        console.error("Certificate generation error:", error);
        res.status(500).json({
            success: false, message: "Error generating certificates"
        });
    }
});

app.get("/certificates/list", (req, res) => {
    const sessionId = req.headers["x-session-id"];
    const session = validateSession(sessionId);

    if (!session) {
        return res.status(401).json({
            success: false, message: "Invalid or expired session."
        });
    }

    try {
        const files = fs.readdirSync(CERT_DIR);
        const certificates = files.filter(f => f.endsWith('.crt'));

        res.json({
            success: true, certificates: certificates, userCertificates: db.certificates[session.username] || null
        });
    } catch (error) {
        res.json({
            success: true, certificates: [], userCertificates: null
        });
    }
});

app.get("/certificates/download/:filename", (req, res) => {
    const sessionId = req.headers["x-session-id"];
    const session = validateSession(sessionId);

    if (!session) {
        return res.status(401).json({
            success: false, message: "Invalid or expired session."
        });
    }

    const filename = req.params.filename;
    const filepath = `${CERT_DIR}/${filename}`;

    if (fs.existsSync(filepath)) {
        res.download(filepath);
    } else {
        res.status(404).json({
            success: false, message: "Certificate not found"
        });
    }
});

app.post("/register", async (req, res) => {
    try {
        const {username, email, password, confirm} = req.body;

        if (!username || !email || !password || !confirm) {
            return res.json({
                success: false, message: "All fields are required."
            });
        }

        if (password !== confirm) {
            return res.json({
                success: false, message: "Passwords do not match."
            });
        }

        if (!isValidUsername(username)) {
            return res.json({
                success: false, message: "Invalid username. Use 3-15 characters (letters, numbers, underscores only)."
            });
        }

        if (!isValidEmail(email)) {
            return res.json({
                success: false, message: "Invalid email format."
            });
        }

        if (!isStrongPassword(password)) {
            return res.json({
                success: false,
                message: "Password must be at least 8 characters with uppercase, lowercase, number, and special character (!@#$%^&*)."
            });
        }

        if (db.users[username]) {
            return res.json({
                success: false, message: "Username already exists."
            });
        }

        const emailExists = Object.values(db.users).some(user => user.email === email);
        if (emailExists) {
            return res.json({
                success: false, message: "Email already registered."
            });
        }

        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        db.users[username] = {
            email, password: hashedPassword, role: "user", twoFAEnabled: true, createdAt: new Date().toISOString()
        };

        saveDB();

        console.log(`New user registered: ${username} (${email}) with role: user`);

        return res.json({
            success: true, message: "Registration successful! Please log in."
        });

    } catch (err) {
        console.error("Register error:", err);
        return res.status(500).json({
            success: false, message: "Server error during registration."
        });
    }
});

app.post("/login", async (req, res) => {
    try {
        const {username, password} = req.body;

        if (!username || !password) {
            return res.json({
                success: false, message: "Username and password are required."
            });
        }

        if (!db.users[username]) {
            return res.json({
                success: false, message: "User not found."
            });
        }

        const passwordMatch = await bcrypt.compare(password, db.users[username].password);

        if (!passwordMatch) {
            return res.json({
                success: false, message: "Incorrect password."
            });
        }

        if (db.users[username].twoFAEnabled) {
            const code = issue2FACode(username, db.users[username].email);
            return res.json({
                success: true,
                twoFA: true,
                message: "2FA code sent to your email. Check server console for preview link.",
                code
            });
        }

        const sessionId = createSession(username);
        return res.json({
            success: true, message: `Welcome, ${username}!`, sessionId, user: {
                username, role: db.users[username].role, email: db.users[username].email
            }
        });

    } catch (err) {
        console.error("Login error:", err);
        return res.status(500).json({
            success: false, message: "Server error during login."
        });
    }
});

app.post("/verify-2fa", (req, res) => {
    try {
        const {username, code} = req.body;

        if (!db.users[username]) {
            return res.json({
                success: false, message: "User not found."
            });
        }

        if (!verify2FA(username, code)) {
            return res.json({
                success: false, message: "Invalid or expired verification code."
            });
        }

        const sessionId = createSession(username);
        return res.json({
            success: true, message: `Welcome, ${username}!`, sessionId, user: {
                username, role: db.users[username].role, email: db.users[username].email
            }
        });

    } catch (err) {
        console.error("2FA verification error:", err);
        return res.status(500).json({
            success: false, message: "Server error during verification."
        });
    }
});

app.post("/logout", (req, res) => {
    const sessionId = req.headers["x-session-id"];

    if (sessionId && sessions[sessionId]) {
        const username = sessions[sessionId].username;
        delete sessions[sessionId];
        console.log(`User logged out: ${username}`);
    }

    res.json({
        success: true, message: "Logged out successfully."
    });
});

app.get("/user/info", (req, res) => {
    const sessionId = req.headers["x-session-id"];
    const session = validateSession(sessionId);

    if (!session) {
        return res.status(401).json({
            success: false, message: "Invalid or expired session."
        });
    }

    const user = db.users[session.username];
    const role = db.roles[user.role];

    res.json({
        success: true, user: {
            username: session.username,
            email: user.email,
            role: user.role,
            roleName: role.name,
            permissions: role.permissions
        }
    });
});

app.post("/resource/request", (req, res) => {
    const sessionId = req.headers["x-session-id"];
    const session = validateSession(sessionId);

    if (!session) {
        return res.status(401).json({
            success: false, message: "Invalid or expired session."
        });
    }

    const {resourceName} = req.body;
    const resource = db.resources[resourceName];

    if (!resource) {
        return res.json({
            success: false, message: "Resource not found."
        });
    }

    const hasAccess = canAccessResource(session.username, resourceName);

    res.json({
        success: true,
        hasAccess,
        resource: {
            name: resource.name, requiredPermissions: resource.requiredPermissions
        },
        message: hasAccess ? `Access granted to ${resource.name}` : `Access denied. Required permissions: ${resource.requiredPermissions.join(", ")}`
    });
});

app.post("/resource/request-jit", (req, res) => {
    const sessionId = req.headers["x-session-id"];
    const session = validateSession(sessionId);

    if (!session) {
        return res.status(401).json({
            success: false, message: "Invalid or expired session."
        });
    }

    const {resourceName, duration} = req.body;
    const maxDuration = 60;

    if (duration > maxDuration) {
        return res.json({
            success: false, message: `Maximum duration is ${maxDuration} minutes.`
        });
    }

    const accessId = uuidv4();
    const expiresAt = Date.now() + duration * 60 * 1000;

    temporaryAccess[accessId] = {
        username: session.username, resourceName, expiresAt
    };

    console.log(`JIT access granted to ${session.username} for ${resourceName} (${duration} minutes)`);

    res.json({
        success: true, accessId, expiresAt, message: `Temporary access granted for ${duration} minutes`
    });
});

app.post("/resource/revoke-jit", (req, res) => {
    const sessionId = req.headers["x-session-id"];
    const session = validateSession(sessionId);

    if (!session) {
        return res.status(401).json({
            success: false, message: "Invalid or expired session."
        });
    }

    const {accessId} = req.body;

    if (temporaryAccess[accessId]) {
        delete temporaryAccess[accessId];
        console.log(`JIT access revoked for ${session.username}`);

        return res.json({
            success: true, message: "Temporary access revoked."
        });
    }

    res.json({
        success: false, message: "Access ID not found or already expired."
    });
});

app.get("/resources", (req, res) => {
    const sessionId = req.headers["x-session-id"];
    const session = validateSession(sessionId);

    if (!session) {
        return res.status(401).json({
            success: false, message: "Invalid or expired session."
        });
    }

    const resourceList = Object.entries(db.resources).map(([key, resource]) => ({
        id: key,
        name: resource.name,
        requiredPermissions: resource.requiredPermissions,
        hasAccess: canAccessResource(session.username, key)
    }));

    res.json({
        success: true, resources: resourceList
    });
});

app.post("/admin/update-role", (req, res) => {
    const sessionId = req.headers["x-session-id"];
    const session = validateSession(sessionId);

    if (!session) {
        return res.status(401).json({
            success: false, message: "Invalid or expired session."
        });
    }

    if (!hasPermission(session.username, "manage_users")) {
        return res.status(403).json({
            success: false, message: "Insufficient permissions."
        });
    }

    const {username, newRole} = req.body;

    if (!db.users[username]) {
        return res.json({
            success: false, message: "User not found."
        });
    }

    if (!db.roles[newRole]) {
        return res.json({
            success: false, message: "Invalid role."
        });
    }

    db.users[username].role = newRole;
    saveDB();

    console.log(`Role updated: ${username} -> ${newRole}`);

    res.json({
        success: true, message: `User ${username} role updated to ${newRole}`
    });
});

app.get("/admin/users", (req, res) => {
    const sessionId = req.headers["x-session-id"];
    const session = validateSession(sessionId);

    if (!session) {
        return res.status(401).json({
            success: false, message: "Invalid or expired session."
        });
    }

    if (!hasPermission(session.username, "manage_users")) {
        return res.status(403).json({
            success: false, message: "Insufficient permissions. Only administrators can view all users."
        });
    }

    const userList = Object.entries(db.users).map(([username, userData]) => ({
        username,
        email: userData.email,
        role: userData.role,
        roleName: db.roles[userData.role]?.name || "Unknown",
        createdAt: userData.createdAt
    }));

    res.json({
        success: true, users: userList
    });
});

app.get('*', (req, res) => {
    if (!req.path.startsWith('/api') && !req.path.startsWith('/certificates')) {
        const indexPath = path.join(__dirname, 'build', 'index.html');
        if (fs.existsSync(indexPath)) {
            res.sendFile(indexPath);
        } else {
            res.status(404).send("Frontend build not found.");
        }
    }
});

function startHTTPSServer(username) {
    const serverCertPath = path.join(CERT_DIR, `server_${username}.crt`);
    const serverKeyPath = path.join(CERT_DIR, `server_${username}.key`);

    if (!fs.existsSync(serverCertPath) || !fs.existsSync(serverKeyPath)) {
        console.error('\n❌ ERROR: Server certificates not found!');
        console.error(`Looking for: server_${username}.crt`);
        console.error('Please generate certificates first using the app.\n');
        process.exit(1);
    }

    try {
        const options = {
            key: fs.readFileSync(serverKeyPath), cert: fs.readFileSync(serverCertPath),
        };

        const server = https.createServer(options, app);

        server.listen(PORT, () => {
            console.log('\n🔒 ============================================');
            console.log(`✅ HTTPS Server running on https://localhost:${PORT}`);
            console.log(`📜 Certificate: server_${username}.crt`);
            console.log('============================================\n');
        });

    } catch (error) {
        console.error('\n❌ Failed to start HTTPS server:', error.message);
        process.exit(1);
    }
}

const usernameArg = process.argv[2];

if (!usernameArg) {
    console.log('\n⚠️  WARNING: No username provided.');
    console.log('   Usage: node server.js <username>');
    process.exit(1);
} else {
    startHTTPSServer(usernameArg);
}