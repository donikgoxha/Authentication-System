import React, {useState} from "react";

function App() {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [message, setMessage] = useState("");
    const [users, setUsers] = useState([]);
    const [loggedIn, setLoggedIn] = useState(null);

    async function send(path) {
        const res = await fetch(`http://localhost:5000${path}`, {
            method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({username, password}),
        });
        const text = await res.text();
        setMessage(text);
        if (text.startsWith("Welcome")) setLoggedIn(username);
    }

    async function viewUsers() {
        const res = await fetch("http://localhost:5000/users");
        if (!res.ok) {
            setMessage("Access denied or session expired");
            return;
        }
        const data = await res.json();
        setUsers(data);
        setMessage("Fetched users successfully!");
    }

    return (<div
        style={{
            textAlign: "center",
            marginTop: "60px",
            fontFamily: "Segoe UI, sans-serif",
            backgroundColor: "white",
            minHeight: "100vh",
            paddingTop: "40px",
        }}
    >
        <div
            style={{
                display: "inline-block",
                padding: "30px 60px",
                background: "white",
                borderRadius: "20px",
                boxShadow: "0 20px 15px rgba(0.5, 0.5, 0.5, 0.5)",
            }}
        >
            <h2 style={{color: "black", marginBottom: "25px"}}>Authentication System</h2>

            {!loggedIn ? (<>
                <input
                    placeholder="Username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    style={{
                        padding: "4px 10px",
                        marginBottom: "12px",
                        borderRadius: "8px",
                        border: "1px solid #ccc",
                        width: "200px",
                    }}
                />
                <br/>
                <input
                    type="password"
                    placeholder="Password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    style={{
                        padding: "4px 10px",
                        marginBottom: "12px",
                        borderRadius: "8px",
                        border: "1px solid #ccc",
                        width: "200px",
                    }}
                />
                <br/>
                <button
                    onClick={() => send("/register")}
                    style={{
                        margin: "5px",
                        padding: "4px 10px",
                        borderRadius: "8px",
                        border: "none",
                        backgroundColor: "#0078d7",
                        color: "white",
                        cursor: "pointer",
                    }}
                >
                    Register
                </button>
                <button
                    onClick={() => send("/login")}
                    style={{
                        margin: "5px",
                        padding: "4px 10px",
                        borderRadius: "8px",
                        border: "none",
                        backgroundColor: "#28a745",
                        color: "white",
                        cursor: "pointer",
                    }}
                >
                    Login
                </button>
            </>) : (<>
                <h3 style={{color: "#222"}}>Welcome, {loggedIn}!</h3>
                {loggedIn === "admin" && (<button
                    onClick={viewUsers}
                    style={{
                        margin: "5px",
                        padding: "8px 16px",
                        borderRadius: "8px",
                        border: "none",
                        backgroundColor: "#ffb300",
                        color: "white",
                        cursor: "pointer",
                    }}
                >
                    View All Users
                </button>)}
                <br/>
                <button
                    onClick={() => {
                        setLoggedIn(null);
                        setUsers([]);
                        setMessage("");
                    }}
                    style={{
                        marginTop: "10px",
                        padding: "8px 16px",
                        borderRadius: "8px",
                        border: "none",
                        backgroundColor: "#dc3545",
                        color: "white",
                        cursor: "pointer",
                    }}
                >
                    Logout
                </button>
            </>)}

            <p style={{marginTop: "20px", color: "#444"}}>{message}</p>

            {loggedIn === "admin" && users.length > 0 && (<div
                style={{
                    marginTop: "20px", textAlign: "center",
                }}
            >
                <h3 style={{color: "#222"}}>Registered Users</h3>
                <ul style={{listStyle: "none", padding: 0, fontSize: "16px"}}>
                    {users.map((user, i) => (<li
                        key={i}
                        style={{
                            background: "#f1f1f1",
                            margin: "6px auto",
                            padding: "2px 6px",
                            borderRadius: "8px",
                            width: "180px",
                            textAlign: "center",
                        }}
                    >
                        {user}
                    </li>))}
                </ul>
            </div>)}
        </div>
    </div>);
}

export default App;
