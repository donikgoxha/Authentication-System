import React, {useState} from "react";

function App() {
    // Page state: "login" or "register"
    const [page, setPage] = useState("login");

    // Form fields
    const [username, setUsername] = useState("");
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [confirm, setConfirm] = useState("");
    const [code, setCode] = useState("");

    // UI state
    const [message, setMessage] = useState("");
    const [twoFA, setTwoFA] = useState(false);
    const [loggedIn, setLoggedIn] = useState(null);
    const [sessionId, setSessionId] = useState(null);

    // Clear all form fields
    function clearFields() {
        setUsername("");
        setEmail("");
        setPassword("");
        setConfirm("");
        setCode("");
        setMessage("");
    }

    // Frontend validation for registration
    function validateRegistration() {
        if (!username || !email || !password || !confirm) {
            setMessage("All fields are required.");
            return false;
        }

        if (!/^[a-zA-Z0-9_]{3,15}$/.test(username)) {
            setMessage("Username must be 3-15 characters (letters, numbers, underscores only).");
            return false;
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            setMessage("Invalid email format.");
            return false;
        }

        if (password !== confirm) {
            setMessage("Passwords do not match.");
            return false;
        }

        if (password.length < 8) {
            setMessage("Password must be at least 8 characters long.");
            return false;
        }

        if (!/[A-Z]/.test(password) || !/[a-z]/.test(password)) {
            setMessage("Password must contain uppercase and lowercase letters.");
            return false;
        }

        if (!/\d/.test(password)) {
            setMessage("Password must contain at least one number.");
            return false;
        }

        if (!/[!@#$%^&*]/.test(password)) {
            setMessage("Password must contain at least one special character (!@#$%^&*).");
            return false;
        }

        return true;
    }

    // Register new user
    async function register() {
        if (!validateRegistration()) return;

        try {
            const res = await fetch("http://localhost:5000/register", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({username, email, password, confirm}),
            });

            const data = await res.json();
            setMessage(data.message);

            if (data.success) {
                console.log(`Registration successful for: ${username}`);
                // Switch to login page and clear fields
                setTimeout(() => {
                    setPage("login");
                    clearFields();
                    setMessage("Registration successful! Please log in.");
                }, 1500);
            }
        } catch (error) {
            console.error("Registration error:", error);
            setMessage("Server connection error.");
        }
    }

    // Login user
    async function login() {
        if (!username || !password) {
            setMessage("Username and password are required.");
            return;
        }

        try {
            const res = await fetch("http://localhost:5000/login", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({username, password}),
            });

            const data = await res.json();

            if (data.twoFA) {
                setTwoFA(true);
                // Print 2FA code to browser console (F12 Console)
                console.log(`Your 2FA code is: ${data.code}. Code expires in 5 minutes`);
                setMessage("2FA code sent! Check browser console (F12).");
            } else if (data.success && data.sessionId) {
                setLoggedIn(username);
                setSessionId(data.sessionId);
                console.log(`Logged in successfully!`);
                console.log(`Session ID: ${data.sessionId}`);
                setMessage(data.message);
                setPassword(""); // Clear password
            } else {
                setMessage(data.message);
            }
        } catch (error) {
            console.error("Login error:", error);
            setMessage("Server connection error.");
        }
    }

    // Verify 2FA code
    async function verify2FA() {
        if (!code) {
            setMessage("Please enter the 2FA code.");
            return;
        }

        try {
            const res = await fetch("http://localhost:5000/verify-2fa", {
                method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({username, code}),
            });

            const data = await res.json();
            setMessage(data.message);

            if (data.success) {
                setLoggedIn(username);
                setSessionId(data.sessionId);
                setTwoFA(false);
                console.log(`2FA verification successful!`);
                console.log(`Session ID: ${data.sessionId}`);
                setPassword("");
                setCode("");
            }
        } catch (error) {
            console.error("2FA verification error:", error);
            setMessage("Server connection error.");
        }
    }

    // Logout user
    async function logout() {
        try {
            await fetch("http://localhost:5000/logout", {
                method: "POST", headers: {"x-session-id": sessionId},
            });

            console.log(`Logged out successfully`);
            setLoggedIn(null);
            setSessionId(null);
            clearFields();
            setTwoFA(false);
            setMessage("Logged out successfully.");
        } catch (error) {
            console.error("Logout error:", error);
        }
    }

    // Handle Enter key press
    function handleKeyPress(e, action) {
        if (e.key === "Enter") {
            action();
        }
    }

    return (<div style={{
        minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", //background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
        background: "white", fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif", padding: "20px"
    }}>
        <div style={{
            background: "white",
            borderRadius: "20px",
            boxShadow: "0 20px 60px rgba(0,0,0,0.3)",
            padding: "20px 20px",
            maxWidth: "300px",
            width: "100%"
        }}>
            <h2 style={{
                textAlign: "center", color: "#333", marginBottom: "30px", fontSize: "24px"
            }}>
                Authentication System
            </h2>

            {!loggedIn ? (<>
                {page === "login" ? (// LOGIN PAGE
                    <div>
                        <h3 style={{textAlign: "center", color: "#555", marginBottom: "18px"}}>
                            Login
                        </h3>

                        <input
                            style={inputStyle}
                            placeholder="Username"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            onKeyPress={(e) => handleKeyPress(e, login)}
                        />

                        <input
                            style={inputStyle}
                            type="password"
                            placeholder="Password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            onKeyPress={(e) => handleKeyPress(e, login)}
                        />

                        {twoFA && (<div style={{marginTop: "15px"}}>
                            <input
                                style={inputStyle}
                                placeholder="Enter 6-digit 2FA code"
                                value={code}
                                onChange={(e) => setCode(e.target.value)}
                                onKeyPress={(e) => handleKeyPress(e, verify2FA)}
                                maxLength={6}
                            />
                            <button style={buttonStyle} onClick={verify2FA}>
                                Verify 2FA Code
                            </button>
                        </div>)}

                        {!twoFA && (<>
                            <button style={buttonStyle} onClick={login}>
                                Login
                            </button>
                            <button
                                style={{...buttonStyle, background: "#6c757d"}}
                                onClick={() => {
                                    setPage("register");
                                    clearFields();
                                }}
                            >
                                Create Account
                            </button>
                        </>)}
                    </div>) : (// REGISTRATION PAGE
                    <div>
                        <h3 style={{textAlign: "center", color: "#555", marginBottom: "20px"}}>
                            Create Account
                        </h3>

                        <input
                            style={inputStyle}
                            placeholder="Username (3-15 characters)"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                        />

                        <input
                            style={inputStyle}
                            type="email"
                            placeholder="Email"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                        />

                        <input
                            style={inputStyle}
                            type="password"
                            placeholder="Password (minimum 8 characters)"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                        />
                        <input
                            style={inputStyle}
                            type="password"
                            placeholder="Confirm Password"
                            value={confirm}
                            onChange={(e) => setConfirm(e.target.value)}
                            onKeyPress={(e) => handleKeyPress(e, register)}
                        />

                        <div style={{
                            fontSize: "12px", color: "#666", marginBottom: "15px", lineHeight: "1.5"
                        }}>
                            Password must contain:
                            <br/>• At least 8 characters
                            <br/>• Uppercase and lowercase letters
                            <br/>• At least one number
                            <br/>• Special character (!@#$%^&*)
                        </div>

                        <button style={buttonStyle} onClick={register}>
                            Register
                        </button>

                        <button
                            style={{...buttonStyle, background: "#6c757d"}}
                            onClick={() => {
                                setPage("login");
                                clearFields();
                            }}
                        >
                            Back to Login
                        </button>
                    </div>)}
            </>) : (// LOGGED IN VIEW
                <div style={{textAlign: "center"}}>
                    <h3 style={{color: "#28a745", marginBottom: "20px"}}>
                        Welcome, {loggedIn}!
                    </h3>
                    <div style={{
                        background: "#f8f9fa",
                        padding: "15px",
                        borderRadius: "10px",
                        marginBottom: "20px",
                        fontSize: "14px",
                        color: "#555"
                    }}>
                        <strong>Session ID:</strong>
                        <br/>
                        <code style={{
                            fontSize: "12px", wordBreak: "break-all", display: "block", marginTop: "5px"
                        }}>
                            {sessionId}
                        </code>
                        <div style={{marginTop: "10px", fontSize: "12px", color: "#666"}}>
                            This session ID is also logged in the browser console (F12)
                        </div>
                    </div>
                    <button
                        style={{...buttonStyle, background: "#dc3545"}}
                        onClick={logout}
                    >
                        Logout
                    </button>
                </div>)}

            {message && (<p style={{
                marginTop: "20px",
                padding: "12px",
                background: message.includes("error") || message.includes("Invalid") || message.includes("not") || message.includes("must") ? "#ffe6e6" : "#e6f7e6",
                color: message.includes("error") || message.includes("Invalid") || message.includes("not") || message.includes("must") ? "#d32f2f" : "#2e7d32",
                borderRadius: "8px",
                fontSize: "14px",
                textAlign: "center"
            }}>
                {message}
            </p>)}
        </div>
    </div>);
}

// Styles
const inputStyle = {
    width: "100%",
    padding: "12px 15px",
    marginBottom: "15px",
    border: "2px solid #e0e0e0",
    borderRadius: "8px",
    fontSize: "14px",
    boxSizing: "border-box",
    outline: "none",
    transition: "border-color 0.3s"
};

const buttonStyle = {
    width: "100%",
    padding: "12px",
    marginBottom: "10px",
    background: "#667eea",
    color: "white",
    border: "none",
    borderRadius: "8px",
    fontSize: "16px",
    fontWeight: "600",
    cursor: "pointer",
    transition: "background 0.3s",
    outline: "none"
};

export default App;