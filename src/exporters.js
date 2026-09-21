function cefEscape(value) {
  return String(value ?? "")
    .replace(/\\/g, "\\\\")
    .replace(/\|/g, "\\|")
    .replace(/=/g, "\\=");
}

function safeJson(value) {
  return JSON.stringify(value, (_, item) => {
    if (typeof item === "string") return item.replace(/[\u0000-\u001f\u007f]/g, "");
    return item;
  });
}

export function eventToJsonLine(event) {
  return safeJson({
    timestamp: event.createdAt,
    type: event.type,
    outcome: event.outcome,
    severity: event.severity,
    riskScore: event.riskScore,
    identityHash: event.identityHash,
    sourceFingerprint: event.ipHash,
    userAgent: event.userAgent,
    details: event.details || {}
  });
}

export function eventsToJsonLines(events) {
  return (events || []).map(eventToJsonLine).join("\n");
}

export function eventToCef(event) {
  const severityMap = { info: 1, low: 3, medium: 6, high: 9 };
  const extension = [
    "rt=" + cefEscape(event.createdAt),
    "outcome=" + cefEscape(event.outcome),
    "cs1Label=IdentityHash",
    "cs1=" + cefEscape(event.identityHash),
    "cs2Label=SourceFingerprint",
    "cs2=" + cefEscape(event.ipHash),
    "cn1Label=RiskScore",
    "cn1=" + cefEscape(event.riskScore ?? 0)
  ].join(" ");

  return [
    "CEF:0",
    "LogonSystem",
    "IdentityDefense",
    "1.0",
    cefEscape(event.type),
    cefEscape(event.type),
    severityMap[event.severity] ?? 1,
    extension
  ].join("|");
}

export function eventsToCef(events) {
  return (events || []).map(eventToCef).join("\n");
}
