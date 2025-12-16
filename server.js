import express from "express";
import cors from "cors";
import fs from "fs";
import {v4 as uuidv4} from "uuid";
import bcrypt from "bcrypt";
import nodemailer from "nodemailer";

const app = express();
const PORT = 5002;
const DB_FILE = "./data.json";
const SALT_ROUNDS = 10;

app.use(express.json());
app.use(cors({
    origin: "http://localhost:5173", credentials: true,
}));

// Email transporter setup
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

// Database structure
let db = {
    users: {}, roles: {
        admin: {
            name: "Administrator", permissions: ["read", "write", "delete", "manage_users", "manage_roles"]
        }, manager: {
            name: "Manager", permissions: ["read", "write", "approve"]
        }, user: {
            name: "Regular User", permissions: ["read"]
        }
    }, resources: {
        documents: {
            name: "Documents", requiredPermissions: ["read"]
        }, reports: {
            name: "Reports", requiredPermissions: ["read", "write"]
        }, admin_panel: {
            name: "Admin Panel", requiredPermissions: ["manage_users"]
        }
    }
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
        users: db.users, roles: db.roles, resources: db.resources
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
    const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes
    twoFACodes[username] = {code, expiresAt};

    console.log(`2FA code for ${username}: ${code} (expires in 5 minutes)`);

    sendEmail2FA(email, username, code).then(previewUrl => {
        if (previewUrl) {
            console.log(`Email preview: ${previewUrl}`);
        }
    });

    return code;
}

function verify2FA(username, code) {
    const entry = twoFACodes[username];
    if (!entry) return false;

    const valid = entry.code === code && Date.now() < entry.expiresAt;
    if (valid) {
        delete twoFACodes[username];
    }
    return valid;
}

function createSession(username) {
    const sessionId = uuidv4();
    sessions[sessionId] = {
        username, createdAt: Date.now(), expiresAt: Date.now() + 2 * 60 * 60 * 1000 // 2 hours
    };
    console.log(`Session created for ${username}: ${sessionId}`);
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

// REGISTRATION ENDPOINT
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

// LOGIN ENDPOINT
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
                code // For demo purposes
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

// 2FA VERIFICATION ENDPOINT
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

// LOGOUT ENDPOINT
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

// GET USER INFO
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

// REQUEST RESOURCE ACCESS
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

// REQUEST JIT (JUST-IN-TIME) ACCESS
app.post("/resource/request-jit", (req, res) => {
    const sessionId = req.headers["x-session-id"];
    const session = validateSession(sessionId);

    if (!session) {
        return res.status(401).json({
            success: false, message: "Invalid or expired session."
        });
    }

    const {resourceName, duration} = req.body; // duration in minutes
    const maxDuration = 60; // 1 hour max

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

// REVOKE JIT ACCESS
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

// GET AVAILABLE RESOURCES
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

// ADMIN: Update user role
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

// ADMIN: Get all users
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

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Registered users: ${Object.keys(db.users).length}`);
    console.log(`Active sessions: ${Object.keys(sessions).length}`);
    console.log(`Available roles: ${Object.keys(db.roles).join(", ")}`);
});
