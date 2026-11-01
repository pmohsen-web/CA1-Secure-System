"""
BLOCK: Validation — allow-list rules
SLOT:  validate       (every app needs exactly one validate block)

Checks input before the app does anything with it.

THE PRINCIPLE WORTH LEARNING HERE
    There are two ways to validate. You can list what is forbidden (a
    "block-list" / "deny-list"), or list what is permitted (an "allow-list").

    Allow-lists win, nearly always. A block-list has to anticipate every bad
    input anyone will ever invent, and it only takes one you did not think of.
    An allow-list says what good looks like and rejects everything else, so
    the thing you failed to imagine is rejected by default.

    The username rule below is an allow-list: letters, digits, underscore,
    between 3 and 32 characters. Everything else is refused without the code
    needing to know why it might be dangerous.

WHAT TO SAY ABOUT IT IN YOUR REPORT
    Validation is a useful first line, but it is NOT what makes you safe from
    injection. Parameterised queries do that, and output encoding handles XSS.
    If your report claims validation prevents SQL injection, that is the kind
    of claim a marker will push on. Validation reduces the attack surface; it
    does not replace the defence at the point of use.
"""

import re

BLOCK_NAME = "Validation: allow-list rules"

# re.compile builds the pattern once. ^ means start, $ means end, so the WHOLE
# string must match, not just part of it. Forgetting ^ and $ is a classic bug:
# without them, "bad name!!!" would pass because "badname" appears inside it.
# PRINCIPLE: Secure defaults — the rule states what is allowed and refuses
# everything else, so an input nobody anticipated is rejected rather than
# accepted by omission.
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,32}$")

MIN_PASSWORD_LENGTH = 12
MAX_ITEM_LENGTH = 1000


def username(value):
    if not USERNAME_PATTERN.match(value or ""):
        return False, ("Username must be 3-32 characters, using only letters, "
                       "numbers and underscore.")
    return True, ""


def password(value):
    """Length first, because length beats complexity rules.

    Modern guidance (NIST SP 800-63B) prefers long passphrases over forced
    mixtures of symbols, which mostly produce P@ssw0rd1 and a sticky note.
    Worth a sentence in your report if you choose a different rule.
    """
    if value is None or len(value) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    return True, ""


def item_text(value):
    if not value or not value.strip():
        return False, "The note cannot be empty."
    if len(value) > MAX_ITEM_LENGTH:
        return False, f"The note must be under {MAX_ITEM_LENGTH} characters."
    return True, ""
