# Session Cookie

For browser sessions, consider:
- Secure;
- HttpOnly;
- appropriate SameSite;
- narrow Path;
- controlled lifetime.

Cookie flags are one layer. The server still needs authorization, expiration and revocation logic.