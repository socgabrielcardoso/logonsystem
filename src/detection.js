import {
  distinctValues,
  failuresByIdentity,
  failuresBySource
} from "./correlation.js";

function finding(rule, severity, title, evidence) {
  return { rule, severity, title, evidence };
}

export function analyzeAuthWindow(events) {
  const findings = [];
  const identityGroups = failuresByIdentity(events);
  const sourceGroups = failuresBySource(events);

  for (const [identityHash, attempts] of identityGroups) {
    if (identityHash === "unknown") continue;

    if (attempts.length >= 5) {
      findings.push(finding(
        "AUTH-BRUTEFORCE-001",
        "high",
        "Repeated authentication failures against one identity",
        {
          identityHash,
          attempts: attempts.length,
          distinctSources: distinctValues(attempts, "ipHash")
        }
      ));
    } else if (attempts.length >= 3) {
      findings.push(finding(
        "AUTH-BRUTEFORCE-002",
        "medium",
        "Elevated authentication failures against one identity",
        {
          identityHash,
          attempts: attempts.length,
          distinctSources: distinctValues(attempts, "ipHash")
        }
      ));
    }
  }

  for (const [ipHash, attempts] of sourceGroups) {
    if (ipHash === "unknown") continue;
    const identities = distinctValues(attempts, "identityHash");

    if (attempts.length >= 8 && identities >= 5) {
      findings.push(finding(
        "AUTH-SPRAY-001",
        "high",
        "Password spray pattern across multiple identities",
        {
          ipHash,
          attempts: attempts.length,
          distinctIdentities: identities
        }
      ));
    }
  }

  const blocked = (events || []).filter((event) => event.type === "LOGIN_BLOCKED");
  if (blocked.length >= 3) {
    findings.push(finding(
      "AUTH-LOCKOUT-001",
      "high",
      "Multiple account lockout events detected",
      {
        blockedEvents: blocked.length,
        distinctIdentities: distinctValues(blocked, "identityHash")
      }
    ));
  }

  const successes = (events || []).filter((event) => event.type === "LOGIN_SUCCESS");
  for (const success of successes) {
    const previousFailures = (events || []).filter((event) =>
      event.identityHash === success.identityHash &&
      (event.type === "LOGIN_FAILURE" || event.type === "LOGIN_BLOCKED") &&
      new Date(event.createdAt).getTime() <= new Date(success.createdAt).getTime()
    );

    if (previousFailures.length >= 4) {
      findings.push(finding(
        "AUTH-SUCCESS-AFTER-FAIL-001",
        "medium",
        "Successful sign in followed repeated failures",
        {
          identityHash: success.identityHash,
          previousFailures: previousFailures.length,
          sourceChanged: previousFailures.some((event) => event.ipHash !== success.ipHash)
        }
      ));
    }
  }

  return findings;
}

export function highestFindingSeverity(findings) {
  const weight = { info: 0, low: 1, medium: 2, high: 3 };
  return (findings || []).reduce(
    (highest, item) => weight[item.severity] > weight[highest] ? item.severity : highest,
    "info"
  );
}
