import test from "node:test";
import assert from "node:assert/strict";
import { analyzeAuthWindow } from "../src/detection.js";

function event(type, identityHash, ipHash, offset = 0) {
  return {
    type,
    identityHash,
    ipHash,
    createdAt: new Date(1_700_000_000_000 + offset).toISOString()
  };
}

test("detects repeated failures against one identity", () => {
  const events = Array.from({ length: 5 }, (_, index) =>
    event("LOGIN_FAILURE", "identity-a", "source-" + index, index)
  );

  const findings = analyzeAuthWindow(events);
  assert.ok(findings.some((item) => item.rule === "AUTH-BRUTEFORCE-001"));
});

test("detects password spray from one source", () => {
  const events = Array.from({ length: 8 }, (_, index) =>
    event("LOGIN_FAILURE", "identity-" + index, "shared-source", index)
  );

  const findings = analyzeAuthWindow(events);
  assert.ok(findings.some((item) => item.rule === "AUTH-SPRAY-001"));
});
