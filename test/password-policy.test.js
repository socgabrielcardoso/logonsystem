import test from "node:test";
import assert from "node:assert/strict";
import { inspectPassword } from "../src/password-policy.js";

test("rejects passwords derived from common patterns", () => {
  const result = inspectPassword("Welcome!Security2026", "analyst@example.com");
  assert.equal(result.acceptable, false);
  assert.equal(result.flags.commonPattern, true);
});

test("rejects password containing account identity", () => {
  const result = inspectPassword("Analyst!Blue2026", "analyst@example.com");
  assert.equal(result.acceptable, false);
  assert.equal(result.flags.containsIdentity, true);
});

test("accepts a stronger unrelated password", () => {
  const result = inspectPassword("Falcon!Mosaic7River", "analyst@example.com");
  assert.equal(result.acceptable, true);
});
