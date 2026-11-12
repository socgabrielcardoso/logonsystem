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

