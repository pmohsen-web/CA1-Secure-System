"""
BLOCK: Audit log — append to a file
SLOT:  audit          (every app needs exactly one audit block)

Writes one line per security-relevant event to audit.log.

WHAT IT DELIBERATELY DOES NOT RECORD
    Passwords. Not the right one, not the wrong one, not a hash of the
    attempt. Logging a failed password is a classic accident: people mistype
    their password into the username box, and now the log is a credential
    file. The same goes for session tokens.

WHAT TO SAY ABOUT IT IN YOUR REPORT
    This log can be edited or deleted by anyone who can reach the file, so it
    proves nothing against an attacker who gains that access. Real systems
    ship logs to somewhere the application itself cannot rewrite. Also think
    about retention: a log of who used the system and when is personal data
    under GDPR, so keeping it forever is its own problem.
"""

import os
from datetime import datetime, timezone

BLOCK_NAME = "Audit log: append-only file (audit.log)"

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit.log")


def record(event, username, detail=""):
    """Append one timestamped line.

    "a" means append — open the file and add to the end. Using "w" instead
    would silently erase the whole log every time. That is worth remembering.

    Timestamps are UTC. Local time looks friendlier and becomes ambiguous
    twice a year when the clocks change.
    """
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    safe_user = (username or "-").replace("\n", " ").replace("\r", " ")
    safe_detail = (detail or "").replace("\n", " ").replace("\r", " ")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{stamp}\t{event}\t{safe_user}\t{safe_detail}\n")
