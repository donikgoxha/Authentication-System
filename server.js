import express from "express";
import cors from "cors";
import fs from "fs";
import {v4 as uuidv4} from "uuid";
import bcrypt from "bcrypt";

const app = express();
const PORT = 5000;
const DB_FILE = "./data.json";
const SALT_ROUNDS = 10;

app.use(express.json());
app.use(cors({
    origin: "http://localhost:5173", credentials: true,
}));

// Load or initialize database
let users = {};
if (fs.existsSync(DB_FILE)) {
    try {
        users = JSON.parse(fs.readFileSync(DB_FILE));
    } catch (e) {
        console.error("Error reading database file. Resetting users.");
        users = {};
    }
}

// In-memory storage for sessions and 2FA codes
let sessions = {};
let twoFACodes = {};

// Save users to database
function saveUsers() {
    fs.writeFileSync(DB_FILE, JSON.stringify(users, null, 2));
}

// Validation functions
function isValidUsername(username) {
    return /^[a-zA-Z0-9_]{3,15}$/.test(username);
}

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isStrongPassword(password) {
    return (password.length >= 8 && /[A-Z]/.test(password) && /[a-z]/.test(password) && /\d/.test(password) && /[!@#$%^&*]/.test(password));
}

// Generate 6-digit 2FA code
function issue2FACode(username) {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes
    twoFACodes[username] = {code, expiresAt};
    console.log(`2FA code for ${username}: ${code} (expires in 5 minutes)`);
    return code;
}

// Verify 2FA code
function verify2FA(username, code) {
    const entry = twoFACodes[username];
    if (!entry) return false;

    const valid = entry.code === code && Date.now() < entry.expiresAt;
    if (valid) {
        delete twoFACodes[username];
    }
    return valid;
}

// Create session for user
function createSession(username) {
    const sessionId = uuidv4();
    sessions[sessionId] = {
        username, createdAt: Date.now()
    };
    console.log(`Session created for ${username}: ${sessionId}`);
    return sessionId;
}

// --- REGISTER ENDPOINT ---
app.post("/register", async (req, res) => {
    try {
        const {username, email, password, confirm} = req.body;

        // Check if all fields are provided
        if (!username || !email || !password || !confirm) {
            return res.json({
                success: false, message: "All fields are required."
            });
        }

        // Check if passwords match
        if (password !== confirm) {
            return res.json({
                success: false, message: "Passwords do not match."
            });
        }

        // Validate username format
        if (!isValidUsername(username)) {
            return res.json({
                success: false, message: "Invalid username. Use 3-15 characters (letters, numbers, underscores only)."
            });
        }

        // Validate email format
        if (!isValidEmail(email)) {
            return res.json({
                success: false, message: "Invalid email format."
            });
        }

        // Check password strength
        if (!isStrongPassword(password)) {
            return res.json({
                success: false,
                message: "Password must be at least 8 characters with uppercase, lowercase, number, and special character (!@#$%^&*)."
            });
        }

        // Check if username already exists
        if (users[username]) {
            return res.json({
                success: false, message: "Username already exists."
            });
        }

        // Check if email already exists
        const emailExists = Object.values(users).some(user => user.email === email);
        if (emailExists) {
            return res.json({
                success: false, message: "Email already registered."
            });
        }

        // Hash password with bcrypt
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        // Create new user
        users[username] = {
            email, password: hashedPassword, twoFAEnabled: true, createdAt: new Date().toISOString()
        };

        saveUsers();

        console.log(`New user registered: ${username} (${email})`);

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

// --- LOGIN ENDPOINT ---
app.post("/login", async (req, res) => {
    try {
        const {username, password} = req.body;

        // Check if user exists
        if (!users[username]) {
            return res.json({
                success: false, message: "User not found."
            });
        }

        // Verify password with bcrypt
        const passwordMatch = await bcrypt.compare(password, users[username].password);

        if (!passwordMatch) {
            return res.json({
                success: false, message: "Incorrect password."
            });
        }

        // If 2FA is enabled, send code
        if (users[username].twoFAEnabled) {
            const code = issue2FACode(username);
            return res.json({
                success: true, twoFA: true, message: "2FA required. Check browser console for code.", code // Sent to frontend to display in console
            });
        }

        // Create session if no 2FA
        const sessionId = createSession(username);
        return res.json({
            success: true, message: `Welcome, ${username}!`, sessionId
        });

    } catch (err) {
        console.error("Login error:", err);
        return res.status(500).json({
            success: false, message: "Server error during login."
        });
    }
});

// --- VERIFY 2FA ENDPOINT ---
app.post("/verify-2fa", (req, res) => {
    try {
        const {username, code} = req.body;

        if (!users[username]) {
            return res.json({
                success: false, message: "User not found."
            });
        }

        if (!verify2FA(username, code)) {
            return res.json({
                success: false, message: "Invalid or expired verification code."
            });
        }

        // Create session after successful 2FA
        const sessionId = createSession(username);
        return res.json({
            success: true, message: `Welcome, ${username}!`, sessionId
        });

    } catch (err) {
        console.error("2FA verification error:", err);
        return res.status(500).json({
            success: false, message: "Server error during verification."
        });
    }
});

// --- LOGOUT ENDPOINT ---
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

// --- GET SESSION INFO (for debugging) ---
app.get("/session-info", (req, res) => {
    const sessionId = req.headers["x-session-id"];

    if (!sessionId || !sessions[sessionId]) {
        return res.json({
            success: false, message: "No active session."
        });
    }

    return res.json({
        success: true, sessionId, username: sessions[sessionId].username, createdAt: sessions[sessionId].createdAt
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error("Uncaught error:", err);
    res.status(500).json({
        success: false, message: "Unexpected server error."
    });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Current users: ${Object.keys(users).length}`);
    console.log(`Active sessions: ${Object.keys(sessions).length}`);
});