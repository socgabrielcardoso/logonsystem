import test from "node:test";
import assert from "node:assert/strict";
import { eventToCef, eventToJsonLine } from "../src/exporters.js";

const sample = {
  createdAt: "2026-09-21T00:00:00.000Z",
  type: "LOGIN_FAILURE",
  outcome: "denied",
  severity: "medium",
  riskScore: 44,
  identityHash: "identity123",
  ipHash: "source456",
  userAgent: "Browser",
  details: { failedAttempts: 3 }
};

test("exports valid JSONL event", () => {
  const parsed = JSON.parse(eventToJsonLine(sample));
  assert.equal(parsed.type, "LOGIN_FAILURE");
  assert.equal(parsed.riskScore, 44);
});

test("exports CEF event with identity telemetry", () => {
  const cef = eventToCef(sample);
  assert.match(cef, /^CEF:0\|LogonSystem\|IdentityDefense\|1\.0\|/);
  assert.match(cef, /cs1=identity123/);
  assert.match(cef, /cn1=44/);
});
