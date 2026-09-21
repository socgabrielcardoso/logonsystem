function keyOf(event, field) {
  return String(event?.[field] || "unknown");
}

export function groupEvents(events, field) {
  const groups = new Map();

  for (const event of events || []) {
    const key = keyOf(event, field);
    const current = groups.get(key) || [];
    current.push(event);
    groups.set(key, current);
  }

  return groups;
}

export function failuresByIdentity(events) {
  return groupEvents(
    (events || []).filter((event) => event.type === "LOGIN_FAILURE" || event.type === "LOGIN_BLOCKED"),
    "identityHash"
  );
}

export function failuresBySource(events) {
  return groupEvents(
    (events || []).filter((event) => event.type === "LOGIN_FAILURE" || event.type === "LOGIN_BLOCKED"),
    "ipHash"
  );
}

export function distinctValues(events, field) {
  return new Set((events || []).map((event) => keyOf(event, field))).size;
}

export function recentWindow(events, windowMs, now = Date.now()) {
  const floor = now - windowMs;
  return (events || []).filter((event) => {
    const time = new Date(event.createdAt).getTime();
    return Number.isFinite(time) && time >= floor && time <= now;
  });
}

export function countByType(events) {
  const counts = {};
  for (const event of events || []) {
    const type = String(event.type || "UNKNOWN");
    counts[type] = (counts[type] || 0) + 1;
  }
  return counts;
}
