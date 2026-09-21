const authPanel = document.querySelector("#authPanel");
const dashboard = document.querySelector("#dashboard");
const loginTab = document.querySelector("#loginTab");
const registerTab = document.querySelector("#registerTab");
const loginForm = document.querySelector("#loginForm");
const registerForm = document.querySelector("#registerForm");
const authStatus = document.querySelector("#authStatus");
const registerPassword = document.querySelector("#registerPassword");
const logoutButton = document.querySelector("#logoutButton");
const scopeControl = document.querySelector("#scopeControl");
const eventRows = document.querySelector("#eventRows");
const findingRows = document.querySelector("#findingRows");
const detectionSeverity = document.querySelector("#detectionSeverity");
const exportJsonButton = document.querySelector("#exportJsonButton");
const exportCefButton = document.querySelector("#exportCefButton");

let csrfToken = "";
let currentUser = null;
let currentScope = "self";

function setStatus(message, type = "") {
  authStatus.textContent = message;
  authStatus.className = "status" + (type ? " " + type : "");
}

function setMode(mode) {
  const login = mode === "login";
  loginTab.classList.toggle("active", login);
  registerTab.classList.toggle("active", !login);
  loginTab.setAttribute("aria-selected", String(login));
  registerTab.setAttribute("aria-selected", String(!login));
  loginForm.classList.toggle("hidden", !login);
  registerForm.classList.toggle("hidden", login);
  setStatus("");
}

function passwordChecks(value) {
  return {
    length: value.length >= 12 && value.length <= 128,
    lowercase: /[a-z]/.test(value),
    uppercase: /[A-Z]/.test(value),
    number: /\d/.test(value),
    special: /[^A-Za-z0-9\s]/.test(value),
    noSpaces: !/\s/.test(value)
  };
}

function updatePasswordPolicy() {
  const checks = passwordChecks(registerPassword.value);
  document.querySelectorAll("#passwordPolicy [data-check]").forEach((item) => {
    item.classList.toggle("pass", Boolean(checks[item.dataset.check]));
  });
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body && !headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }
  if (csrfToken && options.method && options.method !== "GET") {
    headers.set("x-csrf-token", csrfToken);
  }

  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers
  });

  if (response.status === 204) return null;

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload.error || "Request failed.");
    error.payload = payload;
    throw error;
  }

  return payload;
}

function showDashboard(user) {
  currentUser = user;
  authPanel.classList.add("hidden");
  dashboard.classList.remove("hidden");
  document.querySelector("#welcomeName").textContent = user.displayName;
  document.querySelector("#roleBadge").textContent =
    user.role === "blue_team_admin" ? "Blue Team Admin" : "User";
  scopeControl.classList.toggle("hidden", user.role !== "blue_team_admin");
}

function showAuth() {
  currentUser = null;
  csrfToken = "";
  currentScope = "self";
  dashboard.classList.add("hidden");
  authPanel.classList.remove("hidden");
  setMode("login");
}

function formatTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown";
  return date.toLocaleString([], {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  });
}

function labelEvent(type) {
  const labels = {
    REGISTER_SUCCESS: "Account registered",
    LOGIN_SUCCESS: "Sign in success",
    LOGIN_FAILURE: "Sign in failure",
    LOGIN_BLOCKED: "Sign in blocked",
    LOGOUT: "Logout",
    PASSWORD_POLICY_REJECTED: "Password policy blocked"
  };
  return labels[type] || type.replaceAll("_", " ");
}

function renderEvents(events) {
  eventRows.replaceChildren();

  if (!events.length) {
    const tr = document.createElement("tr");
    tr.className = "empty-row";
    const td = document.createElement("td");
    td.colSpan = 6;
    td.textContent = "No authentication events recorded yet.";
    tr.appendChild(td);
    eventRows.appendChild(tr);
    return;
  }

  for (const event of events) {
    const tr = document.createElement("tr");

    const time = document.createElement("td");
    time.textContent = formatTime(event.createdAt);

    const name = document.createElement("td");
    name.className = "event-name";
    name.textContent = labelEvent(event.type);

    const outcome = document.createElement("td");
    outcome.textContent = event.outcome;

    const severity = document.createElement("td");
    const severityBadge = document.createElement("span");
    severityBadge.className = "badge " + event.severity;
    severityBadge.textContent = event.severity;
    severity.appendChild(severityBadge);

    const risk = document.createElement("td");
    const riskBar = document.createElement("div");
    riskBar.className = "risk-bar";
    riskBar.title = String(event.riskScore) + "/100";
    const fill = document.createElement("span");
    fill.style.width = String(Math.max(0, Math.min(100, event.riskScore))) + "%";
    riskBar.appendChild(fill);
    risk.appendChild(riskBar);

    const source = document.createElement("td");
    source.textContent = event.ipHash;

    tr.append(time, name, outcome, severity, risk, source);
    eventRows.appendChild(tr);
  }
}

function renderFindings(detections) {
  const findings = detections?.findings || [];
  findingRows.replaceChildren();

  detectionSeverity.className = "badge " + (detections?.severity || "info");
  detectionSeverity.textContent = detections?.severity || "info";

  if (!findings.length) {
    const empty = document.createElement("p");
    empty.className = "finding-empty";
    empty.textContent = "No suspicious authentication pattern detected.";
    findingRows.appendChild(empty);
    return;
  }

  for (const finding of findings) {
    const article = document.createElement("article");
    article.className = "finding";

    const heading = document.createElement("div");
    heading.className = "finding-heading";

    const title = document.createElement("strong");
    title.textContent = finding.title;

    const rule = document.createElement("code");
    rule.textContent = finding.rule;

    heading.append(title, rule);

    const evidence = document.createElement("pre");
    evidence.textContent = JSON.stringify(finding.evidence, null, 2);

    article.append(heading, evidence);
    findingRows.appendChild(article);
  }
}

function triggerExport(format) {
  const params = new URLSearchParams({
    scope: currentScope,
    format
  });
  window.location.assign("/api/export?" + params.toString());
}

async function loadTelemetry(scope = currentScope) {
  const payload = await api("/api/telemetry?scope=" + encodeURIComponent(scope));
  currentScope = payload.scope;

  document.querySelector("#failedLogins").textContent = payload.overview.failedLogins;
  document.querySelector("#blockedLogins").textContent = payload.overview.blockedLogins;
  document.querySelector("#maxRisk").textContent = payload.overview.maxRisk;

  document.querySelectorAll("[data-scope]").forEach((button) => {
    button.classList.toggle("active", button.dataset.scope === currentScope);
  });

  renderEvents(payload.events);
  renderFindings(payload.detections);
}

loginTab.addEventListener("click", () => setMode("login"));
registerTab.addEventListener("click", () => setMode("register"));
registerPassword.addEventListener("input", updatePasswordPolicy);

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = loginForm.querySelector("button[type='submit']");
  button.disabled = true;
  setStatus("Checking credentials...");

  try {
    const payload = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({
        email: document.querySelector("#loginEmail").value,
        password: document.querySelector("#loginPassword").value
      })
    });

    csrfToken = payload.csrfToken;
    showDashboard(payload.user);
    loginForm.reset();
    await loadTelemetry();
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    button.disabled = false;
  }
});

registerForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = registerForm.querySelector("button[type='submit']");
  button.disabled = true;
  setStatus("Creating account...");

  try {
    const payload = await api("/api/register", {
      method: "POST",
      body: JSON.stringify({
        displayName: document.querySelector("#registerName").value,
        email: document.querySelector("#registerEmail").value,
        password: registerPassword.value
      })
    });

    csrfToken = payload.csrfToken;
    showDashboard(payload.user);
    registerForm.reset();
    updatePasswordPolicy();
    await loadTelemetry();
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    button.disabled = false;
  }
});

logoutButton.addEventListener("click", async () => {
  logoutButton.disabled = true;
  try {
    await api("/api/logout", { method: "POST" });
  } catch {
  } finally {
    logoutButton.disabled = false;
    showAuth();
    setStatus("Session closed.", "success");
  }
});

exportJsonButton.addEventListener("click", () => triggerExport("jsonl"));
exportCefButton.addEventListener("click", () => triggerExport("cef"));

scopeControl.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-scope]");
  if (!button) return;

  try {
    await loadTelemetry(button.dataset.scope);
  } catch {
    showAuth();
  }
});

async function restoreSession() {
  try {
    const payload = await api("/api/session");
    if (!payload.authenticated) {
      showAuth();
      return;
    }

    csrfToken = payload.csrfToken;
    showDashboard(payload.user);
    await loadTelemetry();
  } catch {
    showAuth();
  }
}

restoreSession();
