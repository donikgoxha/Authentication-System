import express from "express";
import fs from "fs";
import bcrypt from "bcrypt";
import cors from "cors";

const app = express();
const PORT = 5000;
const DB_FILE = "./data.json";

app.use(express.json());
app.use(
    cors({
        origin: "http://localhost:5173",
        credentials: true,
    })
);

let users = fs.existsSync(DB_FILE)
    ? JSON.parse(fs.readFileSync(DB_FILE))
    : {};

function saveUsers() {
    fs.writeFileSync(DB_FILE, JSON.stringify(users, null, 2));
}

// Simulate a simple "logged-in user" variable (just memory)
let currentUser = null;

// Register
app.post("/register", async (req, res) => {
    const {username, password} = req.body;
    if (!username || !password)
        return res.send("Please enter username and password");
    if (users[username]) return res.send("Username already exists");

    const hash = await bcrypt.hash(password, 10);
    users[username] = {password: hash};
    saveUsers();
    res.send("Registered successfully");
});

// Login
app.post("/login", async (req, res) => {
    const {username, password} = req.body;
    if (!users[username]) return res.send("User not found");

    const match = await bcrypt.compare(password, users[username].password);
    if (!match) return res.send("Wrong password");

    currentUser = username; // store who is logged in
    res.send(`Welcome, ${username}!`);
});

// Protected route for admin only
app.get("/users", (req, res) => {
    if (currentUser !== "admin") {
        return res.send("Access denied. Only admin can view users.");
    }
    res.json(users);
});

app.listen(PORT, () =>
    console.log(`Server running on http://localhost:${PORT}`)
);