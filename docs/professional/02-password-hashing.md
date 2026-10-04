# Password Hashing

Passwords must be stored using a password-specific hashing function with salt and an appropriate work factor.

Never store plaintext, reversible encryption or unsalted fast hashes.

The application should rely on established libraries rather than custom cryptography.