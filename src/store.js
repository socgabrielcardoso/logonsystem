import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import { config } from "./config.js";

fs.mkdirSync(path.dirname(config.dbPath), { recursive: true });

const db = new Database(config.dbPath);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.pragma("busy_timeout = 5000");

db.exec(
  "CREATE TABLE IF NOT EXISTS users (" +
  "id INTEGER PRIMARY KEY AUTOINCREMENT," +
  "display_name TEXT NOT NULL," +
  "email TEXT NOT NULL UNIQUE," +
  "password_hash TEXT NOT NULL," +
  "role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user', 'blue_team_admin'))," +
  "failed_logins INTEGER NOT NULL DEFAULT 0," +
  "locked_until TEXT," +
  "created_at TEXT NOT NULL," +
  "last_login_at TEXT" +
  ");" +
  "CREATE TABLE IF NOT EXISTS sessions (" +
  "id TEXT PRIMARY KEY," +
  "user_id INTEGER NOT NULL," +
  "csrf_token TEXT NOT NULL," +
  "ip_hash TEXT NOT NULL," +
  "user_agent TEXT NOT NULL," +
  "created_at TEXT NOT NULL," +
  "expires_at TEXT NOT NULL," +
  "FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE" +
  ");" +
  "CREATE TABLE IF NOT EXISTS auth_events (" +
  "id INTEGER PRIMARY KEY AUTOINCREMENT," +
  "user_id INTEGER," +
  "identity_hash TEXT NOT NULL," +
  "event_type TEXT NOT NULL," +
  "outcome TEXT NOT NULL," +
  "severity TEXT NOT NULL," +
  "risk_score INTEGER NOT NULL DEFAULT 0," +
  "ip_hash TEXT NOT NULL," +
  "user_agent TEXT NOT NULL," +
  "details TEXT NOT NULL DEFAULT '{}'," +
  "created_at TEXT NOT NULL," +
  "FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL" +
  ");" +
  "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);" +
  "CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);" +
  "CREATE INDEX IF NOT EXISTS idx_events_user_created ON auth_events(user_id, created_at DESC);" +
  "CREATE INDEX IF NOT EXISTS idx_events_created ON auth_events(created_at DESC);" +
  "CREATE INDEX IF NOT EXISTS idx_events_identity ON auth_events(identity_hash, created_at DESC);"
);

const insertUser = db.prepare(
  "INSERT INTO users (display_name, email, password_hash, role, created_at) " +
  "VALUES (@displayName, @email, @passwordHash, @role, @createdAt)"
);

const insertSession = db.prepare(
  "INSERT INTO sessions (id, user_id, csrf_token, ip_hash, user_agent, created_at, expires_at) " +
  "VALUES (@id, @userId, @csrfToken, @ipHash, @userAgent, @createdAt, @expiresAt)"
);

const insertEvent = db.prepare(
  "INSERT INTO auth_events (" +
  "user_id, identity_hash, event_type, outcome, severity, risk_score, ip_hash, user_agent, details, created_at" +
  ") VALUES (" +
  "@userId, @identityHash, @eventType, @outcome, @severity, @riskScore, @ipHash, @userAgent, @details, @createdAt" +
  ")"
);

export const store = {
  createUser(input) {
    const result = insertUser.run(input);
    return this.findUserById(Number(result.lastInsertRowid));
  },

  findUserByEmail(email) {
    return db.prepare("SELECT * FROM users WHERE email = ?").get(email) || null;
  },

  findUserById(id) {
    return db.prepare("SELECT * FROM users WHERE id = ?").get(id) || null;
  },

  setFailureState(userId, failedLogins, lockedUntil) {
    db.prepare(
      "UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?"
    ).run(failedLogins, lockedUntil, userId);
  },

  markLoginSuccess(userId, at) {
    db.prepare(
      "UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = ? WHERE id = ?"
    ).run(at, userId);
  },

  createSession(input) {
    insertSession.run(input);
  },

  findSession(sessionId) {
    return db.prepare(
      "SELECT " +
      "s.id AS session_id, s.csrf_token, s.ip_hash AS session_ip_hash, " +
      "s.user_agent AS session_user_agent, s.created_at AS session_created_at, " +
      "s.expires_at AS session_expires_at, u.id AS user_id, u.display_name, " +
      "u.email, u.role, u.failed_logins, u.last_login_at, u.created_at AS user_created_at " +
      "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?"
    ).get(sessionId) || null;
  },

  deleteSession(sessionId) {
    db.prepare("DELETE FROM sessions WHERE id = ?").run(sessionId);
  },

  deleteExpiredSessions(nowIso) {
    db.prepare("DELETE FROM sessions WHERE expires_at <= ?").run(nowIso);
  },

  logEvent(input) {
    insertEvent.run({
      ...input,
      details: JSON.stringify(input.details || {})
    });
  },

  eventsForUser(userId, limit = 40) {
    return db.prepare(
      "SELECT id, event_type, outcome, severity, risk_score, ip_hash, user_agent, details, created_at " +
      "FROM auth_events WHERE user_id = ? ORDER BY created_at DESC LIMIT ?"
    ).all(userId, limit);
  },

  eventsAll(limit = 80) {
    return db.prepare(
      "SELECT e.id, e.user_id, u.display_name, u.email, e.event_type, e.outcome, " +
      "e.severity, e.risk_score, e.ip_hash, e.user_agent, e.details, e.created_at " +
      "FROM auth_events e LEFT JOIN users u ON u.id = e.user_id " +
      "ORDER BY e.created_at DESC LIMIT ?"
    ).all(limit);
  },

  overviewForUser(userId, sinceIso) {
    return db.prepare(
      "SELECT COUNT(*) AS total_events, " +
      "SUM(CASE WHEN event_type = 'LOGIN_FAILURE' THEN 1 ELSE 0 END) AS failed_logins, " +
      "SUM(CASE WHEN event_type = 'LOGIN_BLOCKED' THEN 1 ELSE 0 END) AS blocked_logins, " +
      "MAX(risk_score) AS max_risk " +
      "FROM auth_events WHERE user_id = ? AND created_at >= ?"
    ).get(userId, sinceIso);
  },

  overviewAll(sinceIso) {
    return db.prepare(
      "SELECT COUNT(*) AS total_events, " +
      "SUM(CASE WHEN event_type = 'LOGIN_FAILURE' THEN 1 ELSE 0 END) AS failed_logins, " +
      "SUM(CASE WHEN event_type = 'LOGIN_BLOCKED' THEN 1 ELSE 0 END) AS blocked_logins, " +
      "MAX(risk_score) AS max_risk FROM auth_events WHERE created_at >= ?"
    ).get(sinceIso);
  }
};

export function closeStore() {
  db.close();
}
