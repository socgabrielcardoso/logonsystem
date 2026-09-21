import { inspectPassword } from "./password-policy.js";
import {
  createHmac,
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual
} from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

export function isValidEmail(value) {
  const email = normalizeEmail(value);
  return email.length <= 254 && EMAIL_PATTERN.test(email);
}

export function validatePassword(password, identity = "") {
  const value = String(password || "");
  const checks = {
    length: value.length >= 12 && value.length <= 128,
    lowercase: /[a-z]/.test(value),
    uppercase: /[A-Z]/.test(value),
    number: /\d/.test(value),
    special: /[^A-Za-z0-9\s]/.test(value),
    noSpaces: !/\s/.test(value)
  };

  const advanced = inspectPassword(value, identity);

  return {
    valid: Object.values(checks).every(Boolean) && advanced.acceptable,
    checks,
    advanced
  };
}

export async function hashPassword(password) {
  const salt = randomBytes(16);
  const derived = await scrypt(String(password), salt, 64, {
    N: 16384,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024
  });

  return salt.toString("hex") + "." + Buffer.from(derived).toString("hex");
}

export async function verifyPassword(password, storedHash) {
  try {
    const [saltHex, hashHex] = String(storedHash || "").split(".");
    if (!saltHex || !hashHex) return false;

    const expected = Buffer.from(hashHex, "hex");
    const actual = await scrypt(String(password), Buffer.from(saltHex, "hex"), expected.length, {
      N: 16384,
      r: 8,
      p: 1,
      maxmem: 64 * 1024 * 1024
    });

    const actualBuffer = Buffer.from(actual);
    return actualBuffer.length === expected.length && timingSafeEqual(actualBuffer, expected);
  } catch {
    return false;
  }
}

export function randomToken(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}

export function hashIp(ip, secret) {
  return createHmac("sha256", secret)
    .update(String(ip || "unknown"))
    .digest("hex")
    .slice(0, 24);
}

export function hashIdentity(value, secret) {
  return createHmac("sha256", secret)
    .update(normalizeEmail(value) || "unknown")
    .digest("hex")
    .slice(0, 24);
}

export function sanitizeUserAgent(value) {
  return String(value || "unknown")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .slice(0, 240);
}

export function eventSeverity(type, context = {}) {
  if (type === "LOGIN_BLOCKED" || context.locked) return "high";
  if (type === "LOGIN_FAILURE" && Number(context.failedAttempts || 0) >= 3) return "medium";
  if (type === "PASSWORD_POLICY_REJECTED") return "low";
  return "info";
}

export function riskScore(type, context = {}) {
  let score = 0;

  if (type === "LOGIN_FAILURE") score += 20;
  if (type === "LOGIN_BLOCKED") score += 70;
  if (context.newUserAgent) score += 15;
  score += Math.min(Number(context.failedAttempts || 0) * 8, 40);

  return Math.min(score, 100);
}

export function safeEqualText(left, right) {
  const a = Buffer.from(String(left || ""));
  const b = Buffer.from(String(right || ""));
  return a.length === b.length && timingSafeEqual(a, b);
}
