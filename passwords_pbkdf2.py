"""
BLOCK: Passwords — PBKDF2 with a random salt
SLOT:  passwords      (every app needs exactly one passwords block)

*** THIS IS THE ONE TO BUILD YOUR FINAL APPLICATION WITH. ***

It fixes both problems in the SHA-256 block, using only Python's standard
library so there is nothing to install.

HOW IT FIXES THEM
    SALT     Every user gets their own random value, mixed in before hashing
             and stored alongside the result. Two users with the same password
             now get completely different stored values, and a precomputed
             table is useless because it would have to be rebuilt per salt.

    SLOWNESS PBKDF2 repeats the hash many times over — 480,000 here. A single
             login still feels instant, but an attacker trying billions of
             guesses now needs 480,000 times the work for each one.

WHAT TO SAY ABOUT IT IN YOUR REPORT
    Name the algorithm, the iteration count and why a high count is the point.
    Mention that the salt is not a secret — it is stored in plain sight next
    to the hash, and that is fine, because its job is to be *different*, not
    hidden. If you want to go further, read about Argon2 and bcrypt, which are
    designed to resist custom hardware in ways PBKDF2 does not.
"""

import hashlib
import hmac
import os

BLOCK_NAME = "Passwords: PBKDF2-HMAC-SHA256, random salt, 480,000 iterations"

ITERATIONS = 480_000          # Python allows _ in numbers purely for readability
SALT_BYTES = 16


def hash_password(plain):
    """Produce the string we will store for this user.

    The result looks like:   pbkdf2_sha256$480000$<salt>$<hash>

    Packing the algorithm and the iteration count into the stored value means
    that when you raise ITERATIONS next year, existing users can still log in:
    their record says how it was made. Real systems rely on this.
    """
    # PRINCIPLE: Open design — the security rests on the secret (the password)
    # and the algorithm's cost, not on hiding how it works. The salt is stored
    # in plain sight and that is fine; its job is to be different, not hidden.
    salt = os.urandom(SALT_BYTES)       # cryptographically random, unlike random.random()
    digest = hashlib.pbkdf2_hmac("sha256", plain.encode("utf-8"), salt, ITERATIONS)
    return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(plain, stored):
    """Check a typed password against a stored record."""
    try:
        algorithm, iterations, salt_hex, digest_hex = stored.split("$")
    except ValueError:
        # PRINCIPLE: Fail securely — an unreadable record denies access. The
        # tempting alternative, "if we cannot check it, let them in", is how
        # authentication bypasses happen.
        # The stored value is not in our format — perhaps it was written by a
        # different passwords block. Fail closed: refuse the login.
        return False
    if algorithm != "pbkdf2_sha256":
        return False

    # Re-run the same calculation using the salt and iteration count we stored.
    candidate = hashlib.pbkdf2_hmac(
        "sha256", plain.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations))

    # compare_digest instead of ==, and this genuinely matters.
    #
    # == stops at the first character that differs, so a wrong guess beginning
    # with the right character takes measurably longer to reject than one that
    # is wrong immediately. Over many attempts an attacker can measure that
    # difference and recover the value one character at a time. That is a
    # TIMING ATTACK. compare_digest always takes the same time regardless.
    return hmac.compare_digest(candidate.hex(), digest_hex)
