import React, {useState, useEffect} from "react";

function App() {
    const [page, setPage] = useState("login");
    const [username, setUsername] = useState("");
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [confirm, setConfirm] = useState("");
    const [code, setCode] = useState("");
    const [message, setMessage] = useState("");
    const [twoFA, setTwoFA] = useState(false);
    const [loggedIn, setLoggedIn] = useState(null);
    const [sessionId, setSessionId] = useState(null);
    const [userInfo, setUserInfo] = useState(null);
    const [resources, setResources] = useState([]);
    const [selectedResource, setSelectedResource] = useState(null);
    const [jitDuration, setJitDuration] = useState(30);
    const [showAdminPanel, setShowAdminPanel] = useState(false);
    const [allUsers, setAllUsers] = useState([]);
    const [selectedUser, setSelectedUser] = useState("");
    const [selectedRole, setSelectedRole] = useState("");

    const API_URL = "http://localhost:5002";

    useEffect(() => {
        if (loggedIn && sessionId) {
            fetchUserInfo();
            fetchResources();
        }
    }, [loggedIn, sessionId]);

    function clearFields() {
        setUsername("");
        setEmail("");
        setPassword("");
        setConfirm("");
        setCode("");
        setMessage("");
    }

    async function fetchUserInfo() {
        try {
            const res = await fetch(`${API_URL}/user/info`, {
                headers: {"x-session-id": sessionId}
            });
            const data = await res.json();
            if (data.success) {
                setUserInfo(data.user);
            }
        } catch (error) {
            console.error("Error fetching user info:", error);
        }
    }

    async function fetchResources() {
        try {
            const res = await fetch(`${API_URL}/resources`, {
                headers: {"x-session-id": sessionId}
            });
            const data = await res.json();
            if (data.success) {
                setResources(data.resources);
            }
        } catch (error) {
            console.error("Error fetching resources:", error);
        }
    }

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

    async function register() {
        if (!validateRegistration()) return;

        try {
            const res = await fetch(`${API_URL}/register`, {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({username, email, password, confirm}),
            });

            const data = await res.json();
            setMessage(data.message);

            if (data.success) {
                console.log(`Registration successful for: ${username}`);
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

    async function login() {
        if (!username || !password) {
            setMessage("Username and password are required.");
            return;
        }

        try {
            const res = await fetch(`${API_URL}/login`, {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({username, password}),
            });

            const data = await res.json();

            if (data.twoFA) {
                setTwoFA(true);
                console.log(`Email sent! Check console for preview link.`);
                console.log(`Code expires in 5 minutes`);
                setMessage("2FA code sent! Check email.");
            } else if (data.success && data.sessionId) {
                setLoggedIn(username);
                setSessionId(data.sessionId);
                setUserInfo(data.user);
                console.log(`Logged in successfully!`);
                console.log(`Session ID: ${data.sessionId}`);
                setMessage(data.message);
                setPassword("");
            } else {
                setMessage(data.message);
            }
        } catch (error) {
            console.error("Login error:", error);
            setMessage("Server connection error.");
        }
    }

    async function verify2FA() {
        if (!code) {
            setMessage("Please enter the 2FA code.");
            return;
        }

        try {
            const res = await fetch(`${API_URL}/verify-2fa`, {
                method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({username, code}),
            });

            const data = await res.json();
            setMessage(data.message);

            if (data.success) {
                setLoggedIn(username);
                setSessionId(data.sessionId);
                setUserInfo(data.user);
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

    async function logout() {
        try {
            await fetch(`${API_URL}/logout`, {
                method: "POST", headers: {"x-session-id": sessionId},
            });

            console.log(`Logged out successfully`);
            setLoggedIn(null);
            setSessionId(null);
            setUserInfo(null);
            setResources([]);
            clearFields();
            setTwoFA(false);
            setMessage("Logged out successfully.");
        } catch (error) {
            console.error("Logout error:", error);
        }
    }

    async function requestResourceAccess(resourceName) {
        try {
            const res = await fetch(`${API_URL}/resource/request`, {
                method: "POST", headers: {
                    "Content-Type": "application/json", "x-session-id": sessionId
                }, body: JSON.stringify({resourceName})
            });

            const data = await res.json();
            setMessage(data.message);
            setSelectedResource(data);
        } catch (error) {
            console.error("Resource request error:", error);
            setMessage("Server connection error.");
        }
    }

    async function requestJITAccess(resourceName) {
        try {
            const res = await fetch(`${API_URL}/resource/request-jit`, {
                method: "POST", headers: {
                    "Content-Type": "application/json", "x-session-id": sessionId
                }, body: JSON.stringify({
                    resourceName, duration: jitDuration
                })
            });

            const data = await res.json();
            setMessage(data.message);

            if (data.success) {
                console.log(`JIT Access ID: ${data.accessId}`);
                console.log(`Expires at: ${new Date(data.expiresAt).toLocaleString()}`);
            }
        } catch (error) {
            console.error("JIT access request error:", error);
            setMessage("Server connection error.");
        }
    }

    async function fetchAllUsers() {
        try {
            const res = await fetch(`${API_URL}/admin/users`, {
                headers: {"x-session-id": sessionId}
            });
            const data = await res.json();
            if (data.success) {
                setAllUsers(data.users);
            } else {
                setMessage(data.message);
            }
        } catch (error) {
            console.error("Error fetching users:", error);
            setMessage("Server connection error.");
        }
    }

    async function updateUserRole() {
        if (!selectedUser || !selectedRole) {
            setMessage("Please select both a user and a role.");
            return;
        }

        try {
            const res = await fetch(`${API_URL}/admin/update-role`, {
                method: "POST", headers: {
                    "Content-Type": "application/json", "x-session-id": sessionId
                }, body: JSON.stringify({
                    username: selectedUser, newRole: selectedRole
                })
            });

            const data = await res.json();
            setMessage(data.message);

            if (data.success) {
                fetchAllUsers(); // Refresh user list
                setSelectedUser("");
                setSelectedRole("");
            }
        } catch (error) {
            console.error("Error updating role:", error);
            setMessage("Server connection error.");
        }
    }

    function openAdminPanel() {
        setShowAdminPanel(true);
        fetchAllUsers();
    }

    function handleKeyPress(e, action) {
        if (e.key === "Enter") {
            action();
        }
    }

    const getRoleColor = (role) => {
        switch (role) {
            case "admin":
                return "#e74c3c";
            case "manager":
                return "#3498db";
            case "user":
                return "#2ecc71";
            default:
                return "#95a5a6";
        }
    };

    return (<div style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "#999",
        fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
        padding: "20px"
    }}>
        <div style={{
            background: "#fff",
            borderRadius: "20px",
            boxShadow: "0 20px 60px rgba(0,0,0,0.3)",
            padding: "40px 30px",
            maxWidth: loggedIn ? "800px" : "400px",
            width: "100%"
        }}>
            <div style={{textAlign: "center"}}>
                <div style={{fontSize: "40px"}}>
                    Authentication System
                </div>
            </div>

            {!loggedIn ? (<>
                {page === "login" ? (<div>
                    <h3 style={{
                        textAlign: "center", color: "#000", marginBottom: "25px", fontWeight: "500"
                    }}>
                        Sign In
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

                    {twoFA && (<div style={{marginTop: "5px"}}>
                        <div style={{
                            padding: "15px", marginBottom: "5px", textAlign: "center"
                        }}>
                            <p style={{
                                margin: "0", fontSize: "16px", color: "#000", fontWeight: "500"
                            }}>
                                Check your email for the verification code
                            </p>
                        </div>
                        <input
                            style={{
                                ...inputStyle, fontSize: "15px", textAlign: "center",
                            }}
                            value={code}
                            onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                            onKeyPress={(e) => handleKeyPress(e, verify2FA)}
                            maxLength={6}
                        />
                        <button style={buttonStyle} onClick={verify2FA}>
                            Verify Code
                        </button>
                        <button
                            style={{...buttonStyle, background: "#6c757d"}}
                            onClick={() => {
                                setTwoFA(false);
                                setCode("");
                                setMessage("");
                            }}
                        >
                            Cancel
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
                </div>) : (<div>
                    <h3 style={{
                        textAlign: "center", color: "#555", marginBottom: "25px", fontWeight: "500"
                    }}>
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
                        placeholder="Email Address"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                    />

                    <input
                        style={inputStyle}
                        type="password"
                        placeholder="Password"
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
                        fontSize: "12px",
                        color: "#666",
                        marginBottom: "20px",
                        lineHeight: "1.6",
                        background: "#f8f9fa",
                        padding: "12px",
                        borderRadius: "8px"
                    }}>
                        <strong>Password Requirements:</strong>
                        <br/>✓ Minimum 8 characters
                        <br/>✓ Uppercase & lowercase letters
                        <br/>✓ At least one number
                        <br/>✓ Special character (!@#$%^&*)
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
            </>) : (<div>
                <div style={{textAlign: "center", marginBottom: "30px"}}>
                    <h3 style={{
                        color: "#28a745", marginBottom: "10px", fontWeight: "600"
                    }}>
                        Welcome, {loggedIn}!
                    </h3>
                    {userInfo && (<div style={{
                        display: "inline-block",
                        background: getRoleColor(userInfo.role),
                        color: "white",
                        padding: "8px 20px",
                        borderRadius: "20px",
                        fontSize: "14px",
                        fontWeight: "600",
                        marginTop: "10px"
                    }}>
                        {userInfo.roleName}
                    </div>)}
                </div>

                {/* Admin Panel Button */}
                {userInfo && userInfo.permissions && userInfo.permissions.includes("manage_users") && (<button
                    style={{
                        ...buttonStyle, background: "#e74c3c", marginBottom: "20px"
                    }}
                    onClick={openAdminPanel}
                >
                    Admin Panel - Manage Users
                </button>)}

                {/* Admin Panel */}
                {showAdminPanel && userInfo && userInfo.permissions && userInfo.permissions.includes("manage_users") && (
                    <div style={{
                        background: "#fff",
                        padding: "20px",
                        borderRadius: "10px",
                        marginBottom: "20px",
                        border: "2px solid #000"
                    }}>
                        <div style={{
                            display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "15px"
                        }}>
                            <h4 style={{margin: "0", color: "#000"}}>
                                Administrator Panel
                            </h4>
                            <button
                                style={{
                                    background: "transparent",
                                    border: "none",
                                    fontSize: "20px",
                                    cursor: "pointer",
                                    color: "#000"
                                }}
                                onClick={() => setShowAdminPanel(false)}
                            >
                                X
                            </button>
                        </div>

                        <div style={{
                            background: "white", padding: "15px", borderRadius: "8px", marginBottom: "15px"
                        }}>
                            <h5 style={{margin: "0 0 10px 0", color: "#000"}}>
                                Change User Role
                            </h5>

                            <select
                                style={{
                                    ...inputStyle, marginBottom: "10px"
                                }}
                                value={selectedUser}
                                onChange={(e) => setSelectedUser(e.target.value)}
                            >
                                <option value="">Select User</option>
                                {allUsers.map((user) => (<option key={user.username} value={user.username}>
                                    {user.username} - Current: {user.roleName}
                                </option>))}
                            </select>

                            <select
                                style={{
                                    ...inputStyle, marginBottom: "10px"
                                }}
                                value={selectedRole}
                                onChange={(e) => setSelectedRole(e.target.value)}
                            >
                                <option value="">Select New Role</option>
                                <option value="admin">Administrator</option>
                                <option value="manager">Manager</option>
                                <option value="user">Regular User</option>
                            </select>

                            <button
                                style={{
                                    ...buttonStyle, background: "#28a745", marginBottom: "0"
                                }}
                                onClick={updateUserRole}
                            >
                                Update Role
                            </button>
                        </div>

                        <div style={{
                            background: "white", padding: "15px", borderRadius: "8px"
                        }}>
                            <h5 style={{margin: "0 0 10px 0", color: "#333"}}>
                                All Users ({allUsers.length})
                            </h5>
                            <div style={{maxHeight: "200px", overflowY: "auto"}}>
                                {allUsers.map((user) => (<div
                                    key={user.username}
                                    style={{
                                        display: "flex",
                                        justifyContent: "space-between",
                                        alignItems: "center",
                                        background: "white",
                                        padding: "15px",
                                        marginBottom: "10px",
                                        borderRadius: "8px",
                                        border: "1px solid #000",
                                    }}
                                >
                                    <div>
                                        <strong>{user.username}</strong>
                                        <br/>
                                        <small style={{color: "#666"}}>
                                            {user.email}
                                        </small>
                                    </div>
                                    <div
                                        style={{
                                            background: getRoleColor(user.role),
                                            color: "white",
                                            padding: "5px 12px",
                                            borderRadius: "12px",
                                            fontSize: "12px",
                                            fontWeight: "600"
                                        }}
                                    >
                                        {user.roleName}
                                    </div>
                                </div>))}
                            </div>
                        </div>
                    </div>)}

                <div style={{
                    background: "#fff",
                    padding: "20px",
                    borderRadius: "10px",
                    marginBottom: "20px",
                    border: "2px solid #000",

                }}>
                    <h4 style={{margin: "0 0 15px 0", color: "#000"}}>
                        Available Resources
                    </h4>
                    {resources.map((resource) => (<div key={resource.id} style={{
                        background: "white",
                        padding: "15px",
                        marginBottom: "10px",
                        borderRadius: "8px",
                        border: `1px solid ${resource.hasAccess ? "#28a745" : "#dc3545"}`
                    }}>
                        <div style={{
                            display: "flex", justifyContent: "space-between", alignItems: "center"
                        }}>
                            <div>
                                <h5 style={{margin: "0 0 5px 0"}}>
                                    {resource.hasAccess ? "ACCESS GRANTED: " : "ACCESS DENIED: "} {resource.name}
                                </h5>
                                <p style={{
                                    margin: "0", fontSize: "12px", color: "#666"
                                }}>
                                    Required: {resource.requiredPermissions.join(", ")}
                                </p>
                            </div>
                            <div>
                                <button
                                    style={{
                                        ...buttonStyle, marginBottom: "5px", padding: "8px 16px", fontSize: "12px"
                                    }}
                                    onClick={() => requestResourceAccess(resource.id)}
                                >
                                    Request Access
                                </button>
                                {!resource.hasAccess && (<button
                                    style={{
                                        ...buttonStyle,
                                        background: "#f39c12",
                                        marginBottom: "0",
                                        padding: "8px 16px",
                                        fontSize: "12px"
                                    }}
                                    onClick={() => requestJITAccess(resource.id)}
                                >
                                    Request JIT ({jitDuration}m)
                                </button>)}
                            </div>
                        </div>
                    </div>))}
                </div>

                <button
                    style={{...buttonStyle, background: "#dc3545"}}
                    onClick={logout}
                >
                    Logout
                </button>
            </div>)}

            {message && (<div style={{
                marginTop: "20px",
                padding: "15px",
                background: message.includes("error") || message.includes("Invalid") || message.includes("not") || message.includes("denied") || message.includes("must") || message.includes("required") ? "#fee" : "#e8f5e9",
                color: message.includes("error") || message.includes("Invalid") || message.includes("not") || message.includes("denied") || message.includes("must") || message.includes("required") ? "#c62828" : "#2e7d32",
                borderRadius: "10px",
                fontSize: "14px",
                textAlign: "center",
                borderLeft: `4px solid ${message.includes("error") || message.includes("Invalid") || message.includes("not") || message.includes("denied") || message.includes("must") || message.includes("required") ? "#c62828" : "#2e7d32"}`
            }}>
                {message}
            </div>)}
        </div>
    </div>);
}

const inputStyle = {
    width: "100%",
    border: "1px solid #000",
    fontSize: "14px",
    boxSizing: "border-box",
    outline: "none",
    transition: "all 0.3s",
    fontFamily: "inherit",
    background: "white",
    padding: "15px",
    marginBottom: "10px",
    borderRadius: "8px",
};

const buttonStyle = {
    width: "100%",
    padding: "14px",
    marginBottom: "12px",
    background: "#000",
    color: "white",
    border: "none",
    borderRadius: "10px",
    fontSize: "16px",
    fontWeight: "600",
    cursor: "pointer",
    transition: "all 0.3s",
    outline: "none",
    boxShadow: "0 4px 12px rgba(102, 126, 234, 0.3)"
};

export default App;