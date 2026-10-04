# Logout

Logout should invalidate server-side session state when applicable and clear the client cookie.

For high-risk account changes, consider invalidating other active sessions as part of the response.