# Session Creation

Create authenticated session state only after credential verification succeeds.

Rotate any pre-authentication identifier to reduce fixation risk.

Session creation should emit an auditable event without exposing the session secret.