# Password Reset

Reset tokens should be random, short-lived and single-use.

After successful reset:
- invalidate token;
- consider revoking existing sessions;
- notify the account owner;
- record audit event.

Recovery should not be weaker than the risk profile of the account.