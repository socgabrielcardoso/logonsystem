import path from "node:path";

const isProduction = process.env.NODE_ENV === "production";

if (isProduction && !process.env.IP_HASH_SECRET) {
  throw new Error("IP_HASH_SECRET is required in production");
}

export const config = Object.freeze({
  nodeEnv: process.env.NODE_ENV || "development",
  isProduction,
  port: Number(process.env.PORT || 3000),
  dbPath: path.resolve(process.env.DB_PATH || "./data/logonsystem.db"),
  ipHashSecret: process.env.IP_HASH_SECRET || "local-development-only-secret",
  adminEmail: (process.env.ADMIN_EMAIL || "").trim().toLowerCase(),
  trustProxy: process.env.TRUST_PROXY === "1",
  sessionCookie: "logonsystem_session",
  sessionTtlMs: 8 * 60 * 60 * 1000,
  maxFailedLogins: 5,
  lockoutMs: 15 * 60 * 1000
});
