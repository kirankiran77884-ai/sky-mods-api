require("dotenv").config();
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const db = new Database(process.env.DB_FILE || "./data/skyking.db");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user',
 enabled INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);
const username = process.env.ADMIN_USERNAME || "admin";
const password = process.env.ADMIN_PASSWORD || "ChangeThisAdminPassword";
const exists = db.prepare("SELECT id FROM users WHERE username=?").get(username);
if (!exists) {
  db.prepare("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)")
    .run(username,bcrypt.hashSync(password,12),"admin");
  console.log(`Created admin user: ${username}`);
} else {
  console.log(`Admin user already exists: ${username}`);
}
console.log("Database initialized.");
