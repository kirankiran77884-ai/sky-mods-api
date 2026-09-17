require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const Database = require("better-sqlite3");

const app = express();
const PORT = Number(process.env.PORT || 8080);
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_IN_ENV";
const DB_FILE = process.env.DB_FILE || "./data/skyking.db";

const db = new Database(DB_FILE);
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key_hash TEXT UNIQUE NOT NULL,
  key_preview TEXT NOT NULL,
  name TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  device_id TEXT,
  device_limit INTEGER NOT NULL DEFAULT 1,
  activated_at TEXT,
  expires_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token_hash TEXT UNIQUE NOT NULL,
  expires_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}
function makeKey() {
  const raw = crypto.randomBytes(12).toString("hex").toUpperCase();
  return `SKY-KING-${raw.slice(0,4)}-${raw.slice(4,8)}-${raw.slice(8,12)}`;
}
function authToken(req) {
  const h = req.headers.authorization || "";
  return h.startsWith("Bearer ") ? h.slice(7) : null;
}
function requireAuth(req, res, next) {
  const token = authToken(req);
  if (!token) return res.status(401).json({ok:false,error:"Missing bearer token"});
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const session = db.prepare("SELECT * FROM sessions WHERE token_hash=? AND revoked=0").get(sha256(token));
    if (!session || new Date(session.expires_at) <= new Date())
      return res.status(401).json({ok:false,error:"Session expired or revoked"});
    const user = db.prepare("SELECT id,username,role,enabled FROM users WHERE id=?").get(payload.sub);
    if (!user || !user.enabled) return res.status(401).json({ok:false,error:"User disabled"});
    req.user = user;
    req.token = token;
    next();
  } catch {
    return res.status(401).json({ok:false,error:"Invalid token"});
  }
}
function requireAdmin(req,res,next) {
  requireAuth(req,res,()=> {
    if (req.user.role !== "admin") return res.status(403).json({ok:false,error:"Admin access required"});
    next();
  });
}
function keyRecord(rawKey) {
  return db.prepare("SELECT * FROM keys WHERE key_hash=?").get(sha256(rawKey));
}
function keyValid(record) {
  if (!record) return {ok:false,error:"Invalid key"};
  if (record.status !== "active") return {ok:false,error:`Key is ${record.status}`};
  if (record.expires_at && new Date(record.expires_at) <= new Date()) {
    db.prepare("UPDATE keys SET status='expired' WHERE id=?").run(record.id);
    return {ok:false,error:"Key expired"};
  }
  return {ok:true};
}

app.use(helmet());
app.use(cors({origin: process.env.CORS_ORIGIN || "*"}));
app.use(express.json({limit:"32kb"}));

app.get("/api/health", (req,res)=>res.json({ok:true,service:"SKY KING OFC API",time:new Date().toISOString()}));

app.post("/api/auth/login", (req,res)=>{
  const {username,password} = req.body || {};
  if (!username || !password) return res.status(400).json({ok:false,error:"Username and password are required"});
  const user = db.prepare("SELECT * FROM users WHERE username=?").get(username);
  if (!user || !user.enabled || !bcrypt.compareSync(password,user.password_hash))
    return res.status(401).json({ok:false,error:"Invalid username or password"});
  const expires = new Date(Date.now()+24*60*60*1000).toISOString();
  const token = jwt.sign({sub:user.id,role:user.role},JWT_SECRET,{expiresIn:"24h"});
  db.prepare("INSERT INTO sessions(user_id,token_hash,expires_at) VALUES(?,?,?)")
    .run(user.id,sha256(token),expires);
  res.json({ok:true,token,expiresAt:expires,user:{id:user.id,username:user.username,role:user.role}});
});

app.post("/api/auth/logout", requireAuth, (req,res)=>{
  db.prepare("UPDATE sessions SET revoked=1 WHERE token_hash=?").run(sha256(req.token));
  res.json({ok:true,message:"Logged out"});
});

app.get("/api/auth/status", requireAuth, (req,res)=>{
  res.json({ok:true,authenticated:true,user:req.user});
});

app.post("/api/auth/activate", (req,res)=>{
  const {key,deviceId} = req.body || {};
  if (!key || !deviceId) return res.status(400).json({ok:false,error:"key and deviceId are required"});
  const record = keyRecord(key);
  const valid = keyValid(record);
  if (!valid.ok) return res.status(401).json(valid);
  if (record.device_id && record.device_id !== deviceId)
    return res.status(403).json({ok:false,error:"Key is bound to another device"});
  if (!record.device_id) {
    db.prepare("UPDATE keys SET device_id=?,activated_at=? WHERE id=?")
      .run(deviceId,new Date().toISOString(),record.id);
  }
  db.prepare("UPDATE keys SET last_used_at=? WHERE id=?").run(new Date().toISOString(),record.id);
  const fresh = db.prepare("SELECT * FROM keys WHERE id=?").get(record.id);
  res.json({ok:true,message:"Key activated",keyId:fresh.id,expiresAt:fresh.expires_at,deviceId:fresh.device_id});
});

app.post("/api/auth/validate-key", (req,res)=>{
  const {key,deviceId} = req.body || {};
  if (!key) return res.status(400).json({ok:false,error:"key is required"});
  const record = keyRecord(key);
  const valid = keyValid(record);
  if (!valid.ok) return res.status(401).json(valid);
  if (record.device_id && deviceId && record.device_id !== deviceId)
    return res.status(403).json({ok:false,error:"Device mismatch"});
  db.prepare("UPDATE keys SET last_used_at=? WHERE id=?").run(new Date().toISOString(),record.id);
  res.json({ok:true,valid:true,status:"active",expiresAt:record.expires_at,deviceBound:!!record.device_id});
});

app.get("/api/admin/keys", requireAdmin, (req,res)=>{
  const rows = db.prepare("SELECT id,key_preview,name,status,device_id,device_limit,activated_at,expires_at,created_at,last_used_at FROM keys ORDER BY id DESC").all();
  res.json({ok:true,keys:rows});
});

app.get("/api/admin/keys/:id", requireAdmin, (req,res)=>{
  const row = db.prepare("SELECT id,key_preview,name,status,device_id,device_limit,activated_at,expires_at,created_at,last_used_at FROM keys WHERE id=?").get(req.params.id);
  if (!row) return res.status(404).json({ok:false,error:"Key not found"});
  res.json({ok:true,key:row});
});

app.post("/api/admin/keys", requireAdmin, (req,res)=>{
  const {name="",durationDays=30,deviceLimit=1} = req.body || {};
  const raw = makeKey();
  const days = Number(durationDays);
  const expires = days > 0 ? new Date(Date.now()+days*86400000).toISOString() : null;
  const preview = raw.slice(0,13)+"••••";
  const info = db.prepare("INSERT INTO keys(key_hash,key_preview,name,device_limit,expires_at) VALUES(?,?,?,?,?)")
    .run(sha256(raw),preview,String(name),Math.max(1,Number(deviceLimit)||1),expires);
  res.status(201).json({ok:true,id:info.lastInsertRowid,key:raw,name,expiresAt:expires,deviceLimit:Math.max(1,Number(deviceLimit)||1)});
});

app.post("/api/admin/keys/:id/revoke", requireAdmin, (req,res)=>{
  const info = db.prepare("UPDATE keys SET status='revoked' WHERE id=? AND status!='revoked'").run(req.params.id);
  if (!info.changes) return res.status(404).json({ok:false,error:"Key not found or already revoked"});
  res.json({ok:true,message:"Key revoked"});
});

app.post("/api/admin/keys/:id/restore", requireAdmin, (req,res)=>{
  const row = db.prepare("SELECT expires_at FROM keys WHERE id=?").get(req.params.id);
  if (!row) return res.status(404).json({ok:false,error:"Key not found"});
  if (row.expires_at && new Date(row.expires_at) <= new Date()) return res.status(409).json({ok:false,error:"Expired key cannot be restored"});
  db.prepare("UPDATE keys SET status='active' WHERE id=?").run(req.params.id);
  res.json({ok:true,message:"Key restored"});
});

app.get("/api/admin/users", requireAdmin, (req,res)=>{
  const rows = db.prepare("SELECT id,username,role,enabled,created_at FROM users ORDER BY id DESC").all();
  res.json({ok:true,users:rows});
});

app.post("/api/admin/users", requireAdmin, (req,res)=>{
  const {username,password,role="user"} = req.body || {};
  if (!username || !password || password.length < 8)
    return res.status(400).json({ok:false,error:"Username and password (8+ characters) are required"});
  if (!["user","admin"].includes(role)) return res.status(400).json({ok:false,error:"Invalid role"});
  try {
    const hash = bcrypt.hashSync(password,12);
    const info = db.prepare("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)").run(username,hash,role);
    res.status(201).json({ok:true,id:info.lastInsertRowid,username,role});
  } catch {
    res.status(409).json({ok:false,error:"Username already exists"});
  }
});

app.patch("/api/admin/users/:id", requireAdmin, (req,res)=>{
  const {enabled,password,role} = req.body || {};
  const user = db.prepare("SELECT * FROM users WHERE id=?").get(req.params.id);
  if (!user) return res.status(404).json({ok:false,error:"User not found"});
  if (typeof enabled === "boolean") db.prepare("UPDATE users SET enabled=? WHERE id=?").run(enabled?1:0,req.params.id);
  if (password) {
    if (password.length < 8) return res.status(400).json({ok:false,error:"Password must be 8+ characters"});
    db.prepare("UPDATE users SET password_hash=? WHERE id=?").run(bcrypt.hashSync(password,12),req.params.id);
  }
  if (role && ["user","admin"].includes(role)) db.prepare("UPDATE users SET role=? WHERE id=?").run(role,req.params.id);
  res.json({ok:true,message:"User updated"});
});

app.use((req,res)=>res.status(404).json({ok:false,error:"Endpoint not found"}));

app.listen(PORT,()=>console.log(`SKY KING OFC API running on port ${PORT}`));
