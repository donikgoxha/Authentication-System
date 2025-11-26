import express from "express";
import cors from "cors";
import fs from "fs";
import {v4 as uuidv4} from "uuid";
import bcrypt from "bcrypt";

const app = express();
const PORT = 5002;
const DB_FILE = "./data.json";
const SALT_ROUNDS = 10;

app.use(express.json());
app.use(cors({
    origin: "http://localhost:5173", credentials: true,
}));

let users = {};
if (fs.existsSync(DB_FILE)) {
    try {
        users = JSON.parse(fs.readFileSync(DB_FILE));
    } catch (e) {
        console.error("Error reading database file. Resetting users.");
        users = {};
    }
}

let sessions = {};
let twoFACodes = {};

function saveUsers() {
    fs.writeFileSync(DB_FILE, JSON.stringify(users, null, 2));
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

function issue2FACode(username) {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes
    twoFACodes[username] = {code, expiresAt};
    console.log(`2FA code for ${username}: ${code} (expires in 5 minutes)`);
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
        username, createdAt: Date.now()
    };
    console.log(`Session created for ${username}: ${sessionId}`);
    return sessionId;
}

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

        if (users[username]) {
            return res.json({
                success: false, message: "Username already exists."
            });
        }

        const emailExists = Object.values(users).some(user => user.email === email);
        if (emailExists) {
            return res.json({
                success: false, message: "Email already registered."
            });
        }

        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

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

app.post("/login", async (req, res) => {
    try {
        const {username, password} = req.body;

        if (!users[username]) {
            return res.json({
                success: false, message: "User not found."
            });
        }

        const passwordMatch = await bcrypt.compare(password, users[username].password);

        if (!passwordMatch) {
            return res.json({
                success: false, message: "Incorrect password."
            });
        }

        if (users[username].twoFAEnabled) {
            const code = issue2FACode(username);
            return res.json({
                success: true, twoFA: true, message: "2FA required. Check browser console for code.", code // Sent to frontend to display in console
            });
        }

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

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Current users: ${Object.keys(users).length}`);
    console.log(`Active sessions: ${Object.keys(sessions).length}`);
});