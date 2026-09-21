import test from "node:test";
import assert from "node:assert/strict";
import {
  assessSessionContext,
  shouldTerminateSession
} from "../src/session-risk.js";

test("stable session context has zero risk", () => {
  const assessment = assessSessionContext({
    sessionIpHash: "ip-a",
    requestIpHash: "ip-a",
    sessionUserAgent: "ua-a",
    requestUserAgent: "ua-a"
  });

  assert.equal(assessment.score, 0);
  assert.equal(assessment.suspicious, false);
});

test("combined network and user agent drift terminates session", () => {
  const assessment = assessSessionContext({
    sessionIpHash: "ip-a",
    requestIpHash: "ip-b",
    sessionUserAgent: "ua-a",
    requestUserAgent: "ua-b"
  });

  assert.equal(assessment.score, 80);
  assert.equal(shouldTerminateSession(assessment), true);
});
