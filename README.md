# 🔐 Authentication System

A simple full-stack authentication system built using **Node.js**, **Express**, and **React** — with user data stored locally in a JSON file.

## 🚀 Features
- User registration (with password hashing using bcrypt)
- User login with session management
- Simple JSON-based local database (`data.json`)
- React frontend for registration & login
- Single command to start both frontend and backend

---

## 🧩 Project Structure
Authentication-System/
├── client/ # React frontend
│ ├── src/ # React components
│ ├── public/ # Static files
│ └── package.json # Frontend dependencies
├── server.js # Express backend
├── data.json # Local JSON database
├── package.json # Backend dependencies + concurrently setup
└── .gitignore # Ignore unnecessary files

---

## ⚙️ Installation & Setup

### 1️⃣ Clone the repository
```bash
git clone https://github.com/donikgoxha/Authentication-System.git
cd Authentication-System
