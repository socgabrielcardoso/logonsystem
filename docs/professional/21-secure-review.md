# Secure Code Review

Review authentication changes for:
- secret handling;
- failure behavior;
- session impact;
- authorization assumptions;
- logging;
- rate limiting;
- error disclosure;
- test coverage.

Small login changes can alter the security boundary significantly.