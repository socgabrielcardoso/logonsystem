import test from "node:test";
import assert from "node:assert/strict";
import {
  hashPassword,
  isValidEmail,
  normalizeEmail,
  riskScore,
  validatePassword,
  verifyPassword
} from "../src/security.js";

test("normalizes and validates email addresses", () => {
  assert.equal(normalizeEmail("  Analyst@Example.COM "), "analyst@example.com");
  assert.equal(isValidEmail("analyst@example.com"), true);
  assert.equal(isValidEmail("not-an-email"), false);
});

test("password policy requires strength and a special character", () => {
  const weak = validatePassword("Password1234");
  const strong = validatePassword("BlueTeam!2026");

  assert.equal(weak.valid, false);
  assert.equal(weak.checks.special, false);
  assert.equal(strong.valid, true);
});

test("password hashes verify without storing plaintext", async () => {
  const password = "Telemetry!2026";
  const hash = await hashPassword(password);

  assert.notEqual(hash, password);
  assert.equal(await verifyPassword(password, hash), true);
  assert.equal(await verifyPassword("Wrong!2026Password", hash), false);
});

test("risk score increases for repeated failed authentication", () => {
  const first = riskScore("LOGIN_FAILURE", { failedAttempts: 1 });
  const repeated = riskScore("LOGIN_FAILURE", { failedAttempts: 4 });
  const blocked = riskScore("LOGIN_BLOCKED", { failedAttempts: 5 });

  assert.ok(repeated > first);
  assert.ok(blocked > repeated);
  assert.ok(blocked <= 100);
});
