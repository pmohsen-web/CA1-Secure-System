"""
BLOCK: Application — small web application (Flask)
SLOT:  app            (every app needs exactly one app block)

The alternative to app_cli. Same features, in a browser.

    python app.py

    Flask is the only thing this block needs that is not built into Python.
    You do not have to install it yourself — the app checks on startup, tells
    you what is missing, and offers to install it. It will not install
    anything without asking.

THE PORT IS CHOSEN FOR YOU
    macOS runs AirPlay Receiver on port 5000, which is the port Flask tutorials
    always use, so the obvious choice fails on a Mac for reasons that have
    nothing to do with your code. This block works out a free port for your
    operating system and prints the address to open. See choose_port() near the
    bottom — it is worth reading, because "ask the system instead of assuming"
    is a habit worth having.

    To force a specific port:   PORT=9000 python app.py

CHOOSING THIS BLOCK ADDS WHOLE CATEGORIES OF RISK
    A command-line tool has one user, sitting at the machine. A web app is
    reachable, has sessions that can be stolen, renders attacker-supplied
    text back to other people, and accepts requests that may not have come
    from your own pages. If you pick this block, your report has more ground
    to cover, not less. That is a fair trade for a higher mark if you cover
    it well, and a trap if you do not.
"""

import os
import platform
import secrets
import socket
import sys

# Check Flask is present BEFORE trying to import it. The order matters: if the
# "from flask import ..." line ran first and Flask were missing, Python would
# stop with a traceback and this helpful code would never execute.


from flask import (Flask, redirect, render_template_string, request,
                   session, url_for)

import storage
import auth
import validate
import audit

BLOCK_NAME = "App: Flask web application"

app = Flask(__name__)

# *** WHY THIS IS NOT JUST app.secret_key = "something" ***
# Flask signs the session cookie with this key. Anyone who knows it can forge
# a cookie claiming to be any user. A key written into the source is in every
# copy of the code, in your git history, and in your submission.
#
# Here it is read from the environment, falling back to a random value that
# changes each restart (which signs everyone out on restart — annoying, but
# safe). In a real deployment you would set the environment variable.
app.secret_key = os.environ.get("APP_SECRET_KEY") or secrets.token_hex(32)

# Defence in depth on the session cookie itself.
# PRINCIPLE: Defence in depth — three independent cookie protections, none of
# which is relied on alone.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # JavaScript cannot read it, limiting XSS damage
    SESSION_COOKIE_SAMESITE="Lax",  # not sent on cross-site POSTs, blunts CSRF
    # SESSION_COOKIE_SECURE=True,   # switch on when you serve over HTTPS
)

PAGE = """
<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secure Notes</title>
<style>
  /* Colours are declared once as variables, then used by name below. Change a
     value here and it changes everywhere, which is why real stylesheets are
     written this way. */
  :root{
    --bg:#f4f6f8; --card:#ffffff; --ink:#161a21; --muted:#5d6675; --line:#dfe4ea;
    --navy:#1b335b; --teal:#0b6e6e; --good:#15803d; --bad:#b42318; --warn:#92400e;
    --warn-bg:#fdf6e7; --bad-bg:#fdecea; --good-bg:#e9f6ee;
  }
  /* If the visitor's system is set to dark mode, swap the palette. One media
     query, no JavaScript, no toggle to maintain. */
  @media (prefers-color-scheme: dark){
    :root{
      --bg:#101317; --card:#181c22; --ink:#e6e9ee; --muted:#98a2b3; --line:#2a313b;
      --navy:#c9d6ee; --teal:#4ecdc4; --good:#6ee7a0; --bad:#f97066; --warn:#e0a458;
      --warn-bg:#3a2a15; --bad-bg:#3d1a17; --good-bg:#0f2e1c;
    }
  }
  *{box-sizing:border-box}
  body{margin:0;padding:2.5rem 1rem 4rem;background:var(--bg);color:var(--ink);
       font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
       -webkit-font-smoothing:antialiased}
  .wrap{max-width:42rem;margin:0 auto}
  header{margin-bottom:1.5rem}
  h1{margin:0;font-size:1.7rem;letter-spacing:-.02em;color:var(--navy)}
  .tag{font-size:.74rem;text-transform:uppercase;letter-spacing:.13em;
       color:var(--muted);font-weight:700;margin-bottom:.3rem}
  .card{background:var(--card);border:1px solid var(--line);border-radius:12px;
        padding:1.1rem 1.25rem;margin-bottom:1rem}
  .who{display:flex;justify-content:space-between;align-items:center;gap:1rem;
       flex-wrap:wrap;margin-bottom:1rem}
  .who b{color:var(--teal)}
  a{color:var(--teal)}
  input,button{font:inherit;padding:.5rem .65rem;border-radius:8px;
               border:1px solid var(--line);background:var(--card);color:var(--ink)}
  input:focus-visible,button:focus-visible{outline:2px solid var(--teal);outline-offset:1px}
  button{cursor:pointer;font-weight:600}
  button.primary{background:var(--teal);border-color:var(--teal);color:#fff}
  button.link{border:0;background:none;color:var(--muted);padding:.2rem .3rem;
              font-weight:500;font-size:.85rem}
  button.link:hover{color:var(--bad);text-decoration:underline}
  .row{display:flex;gap:.5rem;flex-wrap:wrap}
  .row input{flex:1;min-width:11rem}
  .msg{padding:.6rem .8rem;border-radius:8px;margin-bottom:1rem;font-size:.92rem;
       border-left:4px solid}
  .msg.bad{background:var(--bad-bg);border-color:var(--bad);color:var(--bad)}
  .msg.good{background:var(--good-bg);border-color:var(--good);color:var(--good)}
  ul.notes{list-style:none;margin:0;padding:0}
  ul.notes li{display:flex;justify-content:space-between;align-items:flex-start;
              gap:1rem;padding:.6rem 0;border-bottom:1px solid var(--line)}
  ul.notes li:last-child{border-bottom:0}
  .id{font-variant-numeric:tabular-nums;color:var(--muted);font-size:.8rem;
      min-width:1.8rem}
  .empty{color:var(--muted);font-size:.92rem;padding:.4rem 0}
  h2{font-size:.95rem;margin:0 0 .7rem;color:var(--muted);text-transform:uppercase;
     letter-spacing:.09em}
  footer{margin-top:1.4rem;font-size:.8rem;color:var(--muted)}
  .badges{display:flex;flex-wrap:wrap;gap:.35rem;margin-top:.5rem}
  .badge{font-size:.72rem;padding:.16rem .5rem;border-radius:999px;
         border:1px solid var(--line);white-space:nowrap}
  .badge.weak{background:var(--warn-bg);color:var(--warn);border-color:var(--warn)}
  .weakbar{background:var(--warn-bg);color:var(--warn);border-left:4px solid var(--warn);
           padding:.6rem .8rem;border-radius:8px;margin-bottom:1rem;font-size:.88rem}
</style></head><body><div class="wrap">

<header>
  <div class="tag">CCT &middot; Programming Principles for Secure Systems</div>
  <h1>Secure Notes</h1>
</header>

{% if weak %}
  <div class="weakbar"><b>{{ weak|length }} deliberately weak block(s) in this build.</b>
    Good for seeing the problem; not what you submit.
    Rebuild with <code>python build.py --preset safe</code>.</div>
{% endif %}

{% if message %}<div class="msg {{ 'good' if good else 'bad' }}">{{ message }}</div>{% endif %}

{% if user %}
  <div class="card">
    <div class="who">
      <span>Signed in as <b>{{ user }}</b></span>
      <a href="{{ url_for('logout') }}">Sign out</a>
    </div>
    <form method="post" action="{{ url_for('add') }}" class="row">
      <input name="text" placeholder="Write a note&hellip;" autofocus>
      <button class="primary">Add note</button>
    </form>
  </div>

  <div class="card">
    <h2>Your notes {% if items %}({{ items|length }}){% endif %}</h2>
    {% if items %}
      <ul class="notes">
      {% for item in items %}
        <li>
          <span class="id">{{ item.id }}</span>
          <span style="flex:1">{{ item.text }}</span>
          <form method="post" action="{{ url_for('delete') }}">
            <input type="hidden" name="id" value="{{ item.id }}">
            <button class="link">delete</button>
          </form>
        </li>
      {% endfor %}
      </ul>
    {% else %}
      <p class="empty">Nothing saved yet. Add your first note above.</p>
    {% endif %}
  </div>
{% else %}
  <div class="card">
    <h2>Sign in</h2>
    <form method="post" action="{{ url_for('login') }}" class="row">
      <input name="username" placeholder="username" autofocus>
      <input name="password" type="password" placeholder="password">
      <button class="primary">Sign in</button>
    </form>
  </div>
  <div class="card">
    <h2>New here?</h2>
    <form method="post" action="{{ url_for('register') }}" class="row">
      <input name="username" placeholder="choose a username">
      <input name="password" type="password" placeholder="choose a password">
      <button>Register</button>
    </form>
  </div>
{% endif %}

<footer>
  This build is assembled from:
  <div class="badges">
    {% for name, is_weak in blocks %}
      <span class="badge {{ 'weak' if is_weak }}">{{ name }}</span>
    {% endfor %}
  </div>
</footer>
</div></body></html>
"""
# *** WHY {{ item.text }} AND NOT {{ item.text | safe }} ***
# Jinja2 escapes by default, so a note containing <script>alert(1)</script>
# displays as text instead of running. The |safe filter switches that off.
# Adding |safe to attacker-controlled content is how stored XSS happens. If
# you ever feel you need it, you almost certainly do not.
#
# Note that the page is styled with a stylesheet, not with style="" attributes
# built from user input. Letting user data reach a style attribute or a <script>
# block is another route to the same problem.

# Blocks whose names contain any of these are the deliberately weak ones. The
# page shows them, so a screenshot of your running app records which version
# you built — useful evidence for your report.
WEAK_MARKERS = ("PLAIN TEXT", "without salt", "none", "no rate limiting")


def assembled_blocks():
    """Return [(block name, is_weak), ...] for the footer badges."""
    import passwords
    out = []
    for module in (storage, passwords, validate, auth, audit):
        name = getattr(module, "BLOCK_NAME", module.__name__)
        out.append((name, any(m.lower() in name.lower() for m in WEAK_MARKERS)))
    return out


def render(message="", good=False):
    user = session.get("user")
    items = storage.list_items(user) if user else []
    blocks = assembled_blocks()
    return render_template_string(
        PAGE, user=user, items=items, message=message, good=good,
        blocks=blocks, weak=[b for b in blocks if b[1]])


@app.route("/")
def index():
    return render()


@app.route("/register", methods=["POST"])
def register():
    ok, msg = auth.register(request.form.get("username", "").strip(),
                            request.form.get("password", ""))
    return render(msg, good=ok)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    ok, msg = auth.login(username, request.form.get("password", ""))
    if ok:
        # Issue a fresh session only after the password has been checked.
        # Reusing a session id from before login enables session fixation,
        # where an attacker plants an id and waits for you to authenticate it.
        session.clear()
        session["user"] = username
    return render(msg, good=ok)


@app.route("/logout")
def logout():
    if session.get("user"):
        audit.record("logout", session["user"])
    session.clear()
    return redirect(url_for("index"))


@app.route("/add", methods=["POST"])
def add():
    user = session.get("user")
    if not user:
        # PRINCIPLE: Complete mediation — authorisation is checked on every
        # request to every protected route. Hiding a form is presentation,
        # not a control.
        # Check authorisation on EVERY route that needs it. Hiding the form
        # from signed-out visitors is not a control — anyone can POST here
        # directly with curl.
        return redirect(url_for("index"))
    text = request.form.get("text", "").strip()
    ok, msg = validate.item_text(text)
    if not ok:
        return render(msg)
    item_id = storage.add_item(user, text)
    audit.record("item_added", user, f"id={item_id}")
    return redirect(url_for("index"))


@app.route("/delete", methods=["POST"])
def delete():
    user = session.get("user")
    if not user:
        return redirect(url_for("index"))
    raw = request.form.get("id", "")
    if not raw.isdigit():
        return render("Invalid note id.")
    # PRINCIPLE: Defence in depth — two independent checks, each sufficient on
    # its own, so one mistake does not become a vulnerability.
    # storage.delete_item checks ownership too. Two checks, deliberately:
    # this one proves you are signed in, that one proves the note is yours.
    if storage.delete_item(user, int(raw)):
        audit.record("item_deleted", user, f"id={raw}")
    return redirect(url_for("index"))



# ---------------------------------------------------------------- choosing a port
# A web app has to listen on a port, and the usual choice for Flask is 5000.
# On a Mac that is a problem: macOS runs AirPlay Receiver on 5000, so your app
# either fails to start or, worse, appears to start while the browser shows a
# 403 that has nothing to do with your code. People lose an hour to this.
#
# Rather than tell you to remember that, the code works it out. It asks the
# operating system for a port that is genuinely free, starting from a sensible
# first choice for whichever system you are on.

# A detail worth knowing, because it is the sort of thing that wastes an
# afternoon: on macOS, probing port 5000 with bind() SUCCEEDS even when AirPlay
# Receiver is answering requests on it. The probe below is therefore not enough
# on its own, which is why the macOS list simply never offers 5000. Testing
# told us that; assuming would not have.
PREFERRED_PORTS = {
    # macOS: skip 5000 entirely — AirPlay Receiver is usually sitting on it,
    # and a bind test does not reliably detect that.
    "Darwin": [5055, 5056, 5057, 8000, 8080],
    # Windows and Linux: 5000 is normally free, so keep the Flask convention.
    "Windows": [5000, 5055, 8000, 8080],
    "Linux": [5000, 5055, 8000, 8080],
}


def port_is_free(port, host="127.0.0.1"):
    """Return True if nothing is already listening on this port.

    We find out by trying to claim it ourselves. socket.socket() opens a
    network connection object; bind() is the step that says "I want this
    port". If something else already holds it, bind raises OSError, and we
    report the port as taken.

    This is a useful check but not a perfect one — see the note above about
    macOS and port 5000. A test that can return the wrong answer is still
    worth having, as long as you know where it is blind.

    "with" closes the socket again immediately, so we release the port before
    Flask asks for it a moment later.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        # Without this, the port can linger in a closing state and appear busy.
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind((host, port))
            return True
        except OSError:
            return False


def choose_port():
    """Pick a port: an explicit choice if given, else the first free one.

    Order of preference:
      1. the PORT environment variable, if you set one  (PORT=9000 python app.py)
      2. the first free port in the list for this operating system
      3. port 0, which means "operating system, you pick" — always works
    """
    requested = os.environ.get("PORT")
    if requested and requested.isdigit():
        # You asked for a specific port, so you get it, free or not. If it is
        # busy Flask will tell you, and that error is more useful than us
        # quietly moving you somewhere you were not expecting.
        return int(requested)

    system = platform.system()                       # 'Darwin', 'Windows', 'Linux'
    candidates = PREFERRED_PORTS.get(system, [5000, 5055, 8000, 8080])
    for port in candidates:
        if port_is_free(port):
            return port
    return 0

if __name__ == "__main__":
    storage.init()
    print("\nBlocks:", storage.BLOCK_NAME, "|", auth.BLOCK_NAME, "|", audit.BLOCK_NAME)

    port = choose_port()
    system = platform.system()
    if system == "Darwin" and port != 5000:
        print("  (macOS: skipping port 5000, which AirPlay Receiver usually holds)")

    # host="127.0.0.1" keeps it on your own machine. Changing it to "0.0.0.0"
    # exposes it to your whole network, which you should not do with this app.
    # debug=True shows an interactive console on errors — never leave it on
    # anywhere other people can reach.
    if port:
        print(f"  Open this in your browser:  http://127.0.0.1:{port}\n")
        app.run(host="127.0.0.1", port=port, debug=False)
    else:
        # Port 0 means the operating system assigns one. We cannot print the
        # URL before starting, so Flask's own startup line is the one to read.
        print("  Every preferred port was busy — letting the OS choose one.")
        print("  Read the 'Running on http://...' line below for the address.\n")
        app.run(host="127.0.0.1", port=0, debug=False)
