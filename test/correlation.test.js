import test from "node:test";
import assert from "node:assert/strict";
import {
  countByType,
  distinctValues,
  failuresByIdentity,
  recentWindow
} from "../src/correlation.js";

test("groups authentication failures by identity", () => {
  const events = [
    { type: "LOGIN_FAILURE", identityHash: "a" },
    { type: "LOGIN_FAILURE", identityHash: "a" },
    { type: "LOGIN_SUCCESS", identityHash: "a" }
  ];

  assert.equal(failuresByIdentity(events).get("a").length, 2);
  assert.equal(countByType(events).LOGIN_FAILURE, 2);
});

test("counts distinct values and time windows", () => {
  const now = 1_700_000_000_000;
  const events = [
    { ipHash: "a", createdAt: new Date(now - 1000).toISOString() },
    { ipHash: "b", createdAt: new Date(now - 2000).toISOString() },
    { ipHash: "b", createdAt: new Date(now - 100000).toISOString() }
  ];

  assert.equal(distinctValues(events, "ipHash"), 2);
  assert.equal(recentWindow(events, 5000, now).length, 2);
});
