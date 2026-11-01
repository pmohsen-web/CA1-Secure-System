"""
BLOCK: Authentication — register and log in, with account lockout
SLOT:  auth           (every app needs exactly one auth block)

Same job as auth_simple, plus: after a number of consecutive failures the
account refuses attempts for a while.

THE TRADE-OFF YOU MUST DISCUSS IF YOU USE THIS BLOCK
    Lockout stops online password guessing. It also hands an attacker a
    denial-of-service tool: they can lock any account they can name, just by
    failing to log in a few times. You cannot have one without the other.

    Common mitigations, any of which is worth a paragraph:
      - lock for minutes, not forever, so it self-heals (what this block does)
      - count failures per IP address as well as per account
      - slow each attempt down instead of blocking outright
      - require a second factor rather than locking

STORAGE NOTE
    This block needs two extra fields on the user record, failed_attempts and
    locked_until. The JSON storage block takes new fields happily. The SQLite
    block already has columns for them. If you write your own storage block,
    it must cope with these.
"""

from datetime import datetime, timedelta, timezone

import storage
import passwords
import validate
import audit

BLOCK_NAME = "Auth: register + login with lockout"

# PRINCIPLE: Psychological acceptability — a control people route around is
# not a control. Fifteen minutes stops automated guessing while letting a real
# user who mistyped their password get back in without raising a ticket. A
# permanent lock would be stronger and would be disabled within a week.
#
# *** THIS IS THE SECURITY-USABILITY CONFLICT YOUR BRIEF ASKS YOU TO DISCUSS. ***
# Raise MAX_ATTEMPTS and you help attackers; lower it and you lock out
# legitimate users. Whatever you choose, say what you traded and why.
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


def _now():
    """Current time, in UTC and timezone-aware.

    Always compare aware datetimes with aware ones. Mixing aware and naive
    raises TypeError in Python, and it is one of the most common ways date
    handling breaks in real code.
    """
    return datetime.now(timezone.utc)


def register(username_value, password_value):
    ok, msg = validate.username(username_value)
    if not ok:
        return False, msg
    ok, msg = validate.password(password_value)
    if not ok:
        return False, msg

    record = passwords.hash_password(password_value)
    if not storage.create_user(username_value, record):
        audit.record("register_failed", username_value, "username taken")
        return False, "That username is not available."

    storage.update_user(username_value, failed_attempts=0, locked_until=None)
    audit.record("register_success", username_value)
    return True, "Account created. You can now log in."


def login(username_value, password_value):
    user = storage.get_user(username_value)
    if user is None:
        audit.record("login_failed", username_value, "no such user")
        return False, "Username or password is incorrect."

    # ---- is the account currently locked?
    locked_until = user.get("locked_until")
    if locked_until:
        # Stored as text, so parse it back into a datetime to compare.
        until = datetime.fromisoformat(locked_until)
        if until.tzinfo is None:
            # Defensive: some storage layers hand back a naive datetime even
            # though an aware one went in. Assume UTC rather than crash.
            until = until.replace(tzinfo=timezone.utc)
        if _now() < until:
            audit.record("login_blocked", username_value, "account locked")
            remaining = int((until - _now()).total_seconds() // 60) + 1
            return False, f"Account locked. Try again in about {remaining} minute(s)."

    # ---- check the password
    if not passwords.verify_password(password_value, user["password"]):
        attempts = int(user.get("failed_attempts") or 0) + 1
        if attempts >= MAX_ATTEMPTS:
            until = _now() + timedelta(minutes=LOCKOUT_MINUTES)
            storage.update_user(username_value,
                                failed_attempts=attempts,
                                locked_until=until.isoformat())
            audit.record("account_locked", username_value, f"{attempts} failures")
            return False, "Account locked after too many attempts."
        storage.update_user(username_value, failed_attempts=attempts)
        audit.record("login_failed", username_value, f"attempt {attempts}")
        return False, "Username or password is incorrect."

    # ---- success: clear the counter, or the user stays one failure from a lock
    storage.update_user(username_value, failed_attempts=0, locked_until=None)
    audit.record("login_success", username_value)
    return True, "Signed in."
