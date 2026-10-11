# Secure deployment — logonsystem

## Preconditions
This Node/Express + SQLite authentication lab must not be exposed to real user credentials until authentication, CSRF controls, session expiry, brute-force handling and abuse tests are completed.

## Configuration
- TLS at a trusted reverse proxy; configure forwarded headers only when the proxy is controlled.
- Set Secure, HttpOnly and appropriate SameSite attributes on session cookies; rotate session IDs on privilege changes.
- Protect the SQLite data directory with minimal OS permissions and encrypted backups.
- Never serve the database, logs, .env, or internal reports under the static public path.
- Validate CORS/origin and rate-limit by account and network identifier.
- Use secrets manager; review the Dependabot PRs before release.

## Release evidence
Run `npm test` and `python3 scripts/security_guard.py`; perform negative tests on password attempts, cookie flags, session timeout and log sanitization. Inspect response headers on the deployed URL. Record SHA, command, runtime version, exit code and reviewer.

**Status:** procedural baseline; not an attestation that the deployed service passes every check.
