import express from "express";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import { rateLimit } from "express-rate-limit";
import { config } from "./config.js";
import { store } from "./store.js";
import { analyzeAuthWindow, highestFindingSeverity } from "./detection.js";
import { eventsToCef, eventsToJsonLines } from "./exporters.js";
import { healthSnapshot } from "./health.js";
import { assessSessionContext, shouldTerminateSession } from "./session-risk.js";
import {
  eventSeverity,
  hashIdentity,
  hashIp,
  hashPassword,
  isValidEmail,
  normalizeEmail,
  randomToken,
  riskScore,
  safeEqualText,
  sanitizeUserAgent,
  validatePassword,
  verifyPassword
} from "./security.js";

const dummyHashPromise = hashPassword(randomToken(24));

function nowIso() {
  return new Date().toISOString();
}

function clientContext(req) {
  return {
    ipHash: hashIp(req.ip, config.ipHashSecret),
    userAgent: sanitizeUserAgent(req.get("user-agent"))
  };
}

function publicUser(user) {
  return {
    id: user.user_id ?? user.id,
    displayName: user.display_name,
    email: user.email,
    role: user.role,
    lastLoginAt: user.last_login_at || null
  };
}

function setSessionCookie(res, sessionId) {
  res.cookie(config.sessionCookie, sessionId, {
    httpOnly: true,
    secure: config.isProduction,
    sameSite: "strict",
    path: "/",
    maxAge: config.sessionTtlMs
  });
}

function clearSessionCookie(res) {
  res.clearCookie(config.sessionCookie, {
    httpOnly: true,
    secure: config.isProduction,
    sameSite: "strict",
    path: "/"
  });
}

function sameOrigin(req, res, next) {
  const origin = req.get("origin");
  if (!origin) return next();

  try {
    const parsed = new URL(origin);
    if (parsed.host === req.get("host")) return next();
  } catch {}

  return res.status(403).json({ error: "Origin rejected." });
}

function requireAuth(req, res, next) {
  if (!req.auth) {
    return res.status(401).json({ error: "Authentication required." });
  }
  next();
}

function requireCsrf(req, res, next) {
  const token = req.get("x-csrf-token");
  if (!safeEqualText(token, req.auth.csrf_token)) {
    return res.status(403).json({ error: "Invalid request token." });
  }
  next();
}

function createSessionFor(user, req, res) {
  const sessionId = randomToken(32);
  const csrfToken = randomToken(24);
  const createdAt = nowIso();
  const expiresAt = new Date(Date.now() + config.sessionTtlMs).toISOString();
  const context = clientContext(req);

  store.createSession({
    id: sessionId,
    userId: user.id,
    csrfToken,
    ipHash: context.ipHash,
    userAgent: context.userAgent,
    createdAt,
    expiresAt
  });

  setSessionCookie(res, sessionId);
  return { csrfToken, createdAt, context };
}

function recordEvent({
  req,
  userId = null,
  email = "",
  eventType,
  outcome,
  context = {},
  details = {}
}) {
  const requestContext = clientContext(req);
  store.logEvent({
    userId,
    identityHash: hashIdentity(email, config.ipHashSecret),
    eventType,
    outcome,
    severity: eventSeverity(eventType, context),
    riskScore: riskScore(eventType, context),
    ipHash: requestContext.ipHash,
    userAgent: requestContext.userAgent,
    details,
    createdAt: nowIso()
  });
}

function parseEvent(row) {
  let details = {};
  try {
    details = JSON.parse(row.details || "{}");
  } catch {
    details = {};
  }

  return {
    id: row.id,
    userId: row.user_id,
    displayName: row.display_name,
    email: row.email,
    identityHash: row.identity_hash,
    type: row.event_type,
    outcome: row.outcome,
    severity: row.severity,
    riskScore: row.risk_score,
    ipHash: row.ip_hash,
    userAgent: row.user_agent,
    details,
    createdAt: row.created_at
  };
}

export function createApp() {
  const app = express();

  if (config.trustProxy) app.set("trust proxy", 1);

  app.disable("x-powered-by");
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"]
      }
    },
    referrerPolicy: { policy: "no-referrer" }
  }));
  app.use(express.json({ limit: "16kb" }));
  app.use(cookieParser());

  app.use((req, res, next) => {
    store.deleteExpiredSessions(nowIso());

    const sessionId = req.cookies[config.sessionCookie];
    if (!sessionId) return next();

    const session = store.findSession(sessionId);
    if (!session) {
      clearSessionCookie(res);
      return next();
    }

    if (new Date(session.session_expires_at).getTime() <= Date.now()) {
      store.deleteSession(sessionId);
      clearSessionCookie(res);
      return next();
    }

    const requestContext = clientContext(req);
    const assessment = assessSessionContext({
      sessionIpHash: session.session_ip_hash,
      requestIpHash: requestContext.ipHash,
      sessionUserAgent: session.session_user_agent,
      requestUserAgent: requestContext.userAgent
    });

    if (shouldTerminateSession(assessment)) {
      req.auth = session;
      recordEvent({
        req,
        userId: session.user_id,
        email: session.email,
        eventType: "SESSION_ANOMALY",
        outcome: "blocked",
        context: { locked: true },
        details: assessment.signals
      });
      store.deleteSession(sessionId);
      clearSessionCookie(res);
      req.auth = null;
      return next();
    }

    req.auth = session;
    req.sessionAssessment = assessment;
    next();
  });

  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: { error: "Too many sign in attempts. Try again later." }
  });

  const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: 8,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: { error: "Too many registration attempts. Try again later." }
  });

  app.get("/api/health", (req, res) => {
    const snapshot = healthSnapshot();
    res.status(snapshot.status === "ok" ? 200 : 503).json(snapshot);
  });

  app.get("/api/session", (req, res) => {
    if (!req.auth) {
      return res.json({ authenticated: false });
    }

    return res.json({
      authenticated: true,
      user: publicUser(req.auth),
      csrfToken: req.auth.csrf_token,
      session: {
        createdAt: req.auth.session_created_at,
        expiresAt: req.auth.session_expires_at,
        risk: req.sessionAssessment || { suspicious: false, score: 0, signals: {} }
      }
    });
  });

  app.post("/api/register", sameOrigin, registerLimiter, async (req, res, next) => {
    try {
      const displayName = String(req.body?.displayName || "").trim();
      const email = normalizeEmail(req.body?.email);
      const password = String(req.body?.password || "");
      const policy = validatePassword(password, email);

      if (displayName.length < 2 || displayName.length > 60) {
        return res.status(400).json({ error: "Name must contain 2 to 60 characters." });
      }

      if (!isValidEmail(email)) {
        return res.status(400).json({ error: "Enter a valid email address." });
      }

      if (!policy.valid) {
        recordEvent({
          req,
          email,
          eventType: "PASSWORD_POLICY_REJECTED",
          outcome: "blocked",
          details: { failedChecks: Object.keys(policy.checks).filter((key) => !policy.checks[key]) }
        });
        return res.status(400).json({
          error: "Password does not meet the security policy.",
          checks: policy.checks
        });
      }

      if (store.findUserByEmail(email)) {
        return res.status(409).json({ error: "An account already exists for this email." });
      }

      const passwordHash = await hashPassword(password);
      const role = config.adminEmail && email === config.adminEmail
        ? "blue_team_admin"
        : "user";
      const createdAt = nowIso();

      const user = store.createUser({
        displayName,
        email,
        passwordHash,
        role,
        createdAt
      });

      const session = createSessionFor(user, req, res);

      recordEvent({
        req,
        userId: user.id,
        email,
        eventType: "REGISTER_SUCCESS",
        outcome: "success",
        details: { role }
      });

      return res.status(201).json({
        user: publicUser(user),
        csrfToken: session.csrfToken
      });
    } catch (error) {
      if (String(error?.message || "").includes("UNIQUE constraint failed")) {
        return res.status(409).json({ error: "An account already exists for this email." });
      }
      next(error);
    }
  });

  app.post("/api/login", sameOrigin, loginLimiter, async (req, res, next) => {
    try {
      const email = normalizeEmail(req.body?.email);
      const password = String(req.body?.password || "");

      if (!isValidEmail(email) || !password) {
        return res.status(400).json({ error: "Email and password are required." });
      }

      const user = store.findUserByEmail(email);

      if (!user) {
        await verifyPassword(password, await dummyHashPromise);
        recordEvent({
          req,
          email,
          eventType: "LOGIN_FAILURE",
          outcome: "denied",
          context: { failedAttempts: 1 },
          details: { reason: "invalid_credentials" }
        });
        return res.status(401).json({ error: "Invalid email or password." });
      }

      if (user.locked_until && new Date(user.locked_until).getTime() > Date.now()) {
        recordEvent({
          req,
          userId: user.id,
          email,
          eventType: "LOGIN_BLOCKED",
          outcome: "blocked",
          context: { locked: true, failedAttempts: user.failed_logins },
          details: { lockedUntil: user.locked_until }
        });
        return res.status(423).json({
          error: "Account temporarily locked after repeated failed sign in attempts."
        });
      }

      const validPassword = await verifyPassword(password, user.password_hash);

      if (!validPassword) {
        const failedAttempts = Number(user.failed_logins || 0) + 1;
        const locked = failedAttempts >= config.maxFailedLogins;
        const lockedUntil = locked
          ? new Date(Date.now() + config.lockoutMs).toISOString()
          : null;

        store.setFailureState(user.id, failedAttempts, lockedUntil);

        recordEvent({
          req,
          userId: user.id,
          email,
          eventType: locked ? "LOGIN_BLOCKED" : "LOGIN_FAILURE",
          outcome: "denied",
          context: { locked, failedAttempts },
          details: {
            reason: "invalid_credentials",
            failedAttempts,
            lockedUntil
          }
        });

        return res.status(401).json({
          error: locked
            ? "Account temporarily locked after repeated failed sign in attempts."
            : "Invalid email or password."
        });
      }

      const signedInAt = nowIso();
      store.markLoginSuccess(user.id, signedInAt);
      const session = createSessionFor(user, req, res);

      recordEvent({
        req,
        userId: user.id,
        email,
        eventType: "LOGIN_SUCCESS",
        outcome: "success",
        details: { previousFailures: Number(user.failed_logins || 0) }
      });

      const refreshedUser = store.findUserById(user.id);
      return res.json({
        user: publicUser(refreshedUser),
        csrfToken: session.csrfToken
      });
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/logout", sameOrigin, requireAuth, requireCsrf, (req, res) => {
    recordEvent({
      req,
      userId: req.auth.user_id,
      email: req.auth.email,
      eventType: "LOGOUT",
      outcome: "success"
    });

    store.deleteSession(req.auth.session_id);
    clearSessionCookie(res);
    return res.status(204).end();
  });

  app.get("/api/telemetry", requireAuth, (req, res) => {
    const wantsGlobal = req.query.scope === "all";
    const isAdmin = req.auth.role === "blue_team_admin";
    const globalScope = wantsGlobal && isAdmin;
    const sinceIso = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

    const rows = globalScope
      ? store.eventsAll(80)
      : store.eventsForUser(req.auth.user_id, 40);

    const overview = globalScope
      ? store.overviewAll(sinceIso)
      : store.overviewForUser(req.auth.user_id, sinceIso);

    return res.json({
      scope: globalScope ? "all" : "self",
      overview: {
        totalEvents: Number(overview.total_events || 0),
        failedLogins: Number(overview.failed_logins || 0),
        blockedLogins: Number(overview.blocked_logins || 0),
        maxRisk: Number(overview.max_risk || 0)
      },
      events: rows.map(parseEvent),
      detections: (() => {
        const parsed = rows.map(parseEvent);
        const findings = analyzeAuthWindow(parsed);
        return {
          severity: highestFindingSeverity(findings),
          findings
        };
      })()
    });
  });

  app.get("/api/export", requireAuth, (req, res) => {
    const wantsGlobal = req.query.scope === "all";
    const isAdmin = req.auth.role === "blue_team_admin";
    const globalScope = wantsGlobal && isAdmin;
    const format = String(req.query.format || "jsonl").toLowerCase();

    const rows = globalScope
      ? store.eventsAll(250)
      : store.eventsForUser(req.auth.user_id, 250);

    const events = rows.map(parseEvent).map((event) => ({
      ...event,
      identityHash: event.identityHash || "unknown"
    }));

    if (format === "cef") {
      res.type("text/plain");
      res.setHeader("Content-Disposition", 'attachment; filename="logonsystem-events.cef"');
      return res.send(eventsToCef(events));
    }

    res.type("application/x-ndjson");
    res.setHeader("Content-Disposition", 'attachment; filename="logonsystem-events.jsonl"');
    return res.send(eventsToJsonLines(events));
  });

  app.use(express.static("public", {
    index: "index.html",
    maxAge: config.isProduction ? "1h" : 0
  }));

  app.use((req, res, next) => {
    if (req.path.startsWith("/api/")) {
      return res.status(404).json({ error: "Route not found." });
    }
    next();
  });

  app.use((error, req, res, next) => {
    console.error(error);
    if (res.headersSent) return next(error);
    res.status(500).json({ error: "Unexpected server error." });
  });

  return app;
}
