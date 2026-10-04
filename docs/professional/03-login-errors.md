# Login Errors

External login failures should avoid revealing whether username or password was wrong.

Use a generic message while internal logs record a safe failure category.

Do not include submitted passwords or full session material in logs.