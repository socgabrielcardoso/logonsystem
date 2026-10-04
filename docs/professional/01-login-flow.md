# Login Flow

A secure login flow:
1. receives normalized identifier;
2. validates input shape;
3. loads account safely;
4. verifies credential using secure hash;
5. applies throttling/risk controls;
6. creates or rotates session;
7. emits audit event;
8. returns generic external result.

Authorization remains a separate step after login.