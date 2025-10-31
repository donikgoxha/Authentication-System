import React, {useState} from "react";

function App() {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [message, setMessage] = useState("");
    const [users, setUsers] = useState({});
    const [loggedIn, setLoggedIn] = useState(null);

    async function send(path) {
        const res = await fetch(`http://localhost:5000${path}`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({username, password}),
        });
        const text = await res.text();
        setMessage(text);
        if (text.startsWith("Welcome")) setLoggedIn(username);
    }

    async function viewUsers() {
        const res = await fetch("http://localhost:5000/users");
        const data = await res.json();
        setUsers(data);
        setMessage("Fetched users successfully!");
    }

    return (
        <div style={{textAlign: "center", marginTop: "50px"}}>
            <h2>Simple Auth</h2>

            {!loggedIn ? (
                <>
                    <input
                        placeholder="Username"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                    /><br/><br/>

                    <input
                        type="password"
                        placeholder="Password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                    /><br/><br/>

                    <button onClick={() => send("/register")}>Register</button>
                    <br></br>
                    <button onClick={() => send("/login")}>Login</button>
                </>
            ) : (
                <>
                    <h3>Welcome, {loggedIn}!</h3>
                    {loggedIn === "admin" && (
                        <button onClick={viewUsers}>View All Users</button>
                    )}
                    <br></br>
                    <button onClick={() => setLoggedIn(null)}>Logout</button>
                </>
            )}

            <p style={{marginTop: "20px", color: "black"}}>{message}</p>

            {/* Show users list only for admin */}
            {loggedIn === "admin" && Object.keys(users).length > 0 && (
                <div style={{marginTop: "20px"}}>
                    <h3>Registered Users</h3>
                    <ul style={{listStyle: "none"}}>
                        {Object.keys(users).map((user) => (
                            <li key={user}>{user}</li>
                        ))}
                    </ul>
                </div>
            )}
        </div>
    );
}

export default App;