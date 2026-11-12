import test from "node:test";
import assert from "node:assert/strict";
import { inspectPassword } from "../src/password-policy.js";
import { normalizeEventDetails } from "../src/event-schema.js";
import { assessSessionContext } from "../src/session-risk.js";

test("Reject reversed numeric password sequences", () => {
  assert.equal(inspectPassword("A1!9876543Random").flags.sequentialCharacters, true);
});

test("Reject reversed alphabet sequences", () => {
  assert.equal(inspectPassword("A1!zyxwvRandom").flags.sequentialCharacters, true);
});

test("Detect predictable asdf keyboard walks", () => {
  assert.equal(inspectPassword("A1!asdfghRandom").flags.commonPattern, true);
});

test("Detect common iloveyou word fragments", () => {
  assert.equal(inspectPassword("A1!iloveyouRandom").flags.commonPattern, true);
});

test("Normalize identity whitespace before checking password leakage", () => {
  assert.equal(inspectPassword("Analyst!Unique2026", "  analyst@example.org  ").flags.containsIdentity, true);
});

test("Reject null event metadata without throwing", () => {
  assert.deepEqual(normalizeEventDetails(null), {});
});

test("Bound event payload attributes to 32", () => {
  const meta=Object.fromEntries(Array.from({length:40},(_,i)=>["key"+i,i])); assert.equal(Object.keys(normalizeEventDetails(meta)).length,32);
});

