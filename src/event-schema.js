export const AUTH_EVENTS = Object.freeze({
  REGISTER_SUCCESS: "REGISTER_SUCCESS",
  LOGIN_SUCCESS: "LOGIN_SUCCESS",
  LOGIN_FAILURE: "LOGIN_FAILURE",
  LOGIN_BLOCKED: "LOGIN_BLOCKED",
  LOGOUT: "LOGOUT",
  PASSWORD_POLICY_REJECTED: "PASSWORD_POLICY_REJECTED",
  SESSION_ANOMALY: "SESSION_ANOMALY",
  RATE_LIMITED: "RATE_LIMITED"
});

export const EVENT_OUTCOMES = Object.freeze({
  SUCCESS: "success",
  DENIED: "denied",
  BLOCKED: "blocked",
  OBSERVED: "observed"
});

export const EVENT_SEVERITIES = Object.freeze(["info", "low", "medium", "high"]);

export function isKnownAuthEvent(type) {
  return Object.values(AUTH_EVENTS).includes(type);
}

export function isKnownSeverity(value) {
  return EVENT_SEVERITIES.includes(value);
}

export function normalizeEventDetails(details = {}) {
  const safe = {};
  for (const [key, value] of Object.entries(details)) {
    if (value === undefined) continue;
    if (typeof value === "string") safe[key] = value.slice(0, 240);
    else if (typeof value === "number" || typeof value === "boolean" || value === null) safe[key] = value;
    else if (Array.isArray(value)) safe[key] = value.slice(0, 20).map((item) => String(item).slice(0, 120));
  }
  return safe;
}
