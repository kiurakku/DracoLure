"""Deceptive responses that make the honeypot look like a real target.

Every payload here is fabricated. There are no real credentials, hosts, or
secrets — the values only exist to keep an attacker engaged long enough to be
fully profiled. Serving convincing bait is the whole point of a honeypot: an
attacker who believes they found a live ``/.env`` will keep interacting, and
every one of those interactions is captured and scored.
"""

from __future__ import annotations

from typing import Optional, Tuple

# A believable but entirely fake corporate landing page. Presenting this at
# "/" instead of "Honeypot Flask Server" is what makes the trap sticky — the
# surface must not announce itself as a honeypot.
LANDING_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Acme Internal Portal</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:system-ui,Arial,sans-serif;margin:0;background:#0f1116;
color:#e8eaed}header{padding:22px 32px;border-bottom:1px solid #23262d}
main{max-width:720px;margin:64px auto;padding:0 24px}a{color:#ffb703}
.card{background:#161922;border:1px solid #23262d;border-radius:10px;
padding:24px;margin-top:20px}code{color:#9ad}</style></head>
<body><header><strong>Acme Corp</strong> · Internal Portal</header>
<main><h1>Employee Services</h1>
<p>Welcome. Please sign in to access internal tooling.</p>
<div class="card"><p><a href="/admin">Admin console</a> ·
<a href="/wp-login.php">Legacy CMS</a> ·
<a href="/phpmyadmin/">Database</a></p>
<p><small>Server: Apache/2.4.29 (Ubuntu) · PHP/7.2.24</small></p></div>
</main></body></html>"""

_FAKE_LOGIN = """<!doctype html>
<html><head><title>{title}</title></head><body>
<h2>{title}</h2>
<form method="post" action="{action}">
<label>Username <input name="user"></label><br>
<label>Password <input type="password" name="pass"></label><br>
<button type="submit">Sign in</button></form>
<p><small>{footer}</small></p></body></html>"""

_FAKE_ENV = (
    "APP_ENV=production\n"
    "APP_DEBUG=false\n"
    "APP_KEY=base64:Zk9uZVRpbWVIb25leXBvdEtleU5vdFJlYWxfXw==\n"
    "DB_CONNECTION=mysql\n"
    "DB_HOST=127.0.0.1\n"
    "DB_DATABASE=acme_portal\n"
    "DB_USERNAME=acme_app\n"
    "DB_PASSWORD=Tr@p-N0t-Real-8f21\n"
    "REDIS_HOST=127.0.0.1\n"
    "MAIL_HOST=smtp.mailtrap.io\n"
)

_FAKE_GIT_CONFIG = (
    "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"
    "[remote \"origin\"]\n\turl = git@github.com:acme-corp/portal.git\n"
    "[user]\n\temail = ops@acme.example\n"
)


def decoy_for(path: str) -> Optional[Tuple[str, str, int]]:
    """Return ``(body, content_type, status)`` bait for ``path``.

    ``None`` means "no specific decoy" — the caller serves a generic 404 that
    still logs the probe.
    """
    p = path.lower().rstrip("/")

    if p in ("", "/index.html"):
        return LANDING_PAGE, "text/html; charset=utf-8", 200
    if p == "/.env":
        return _FAKE_ENV, "text/plain; charset=utf-8", 200
    if p == "/.git/config":
        return _FAKE_GIT_CONFIG, "text/plain; charset=utf-8", 200
    if p in ("/admin", "/admin/login"):
        return (
            _FAKE_LOGIN.format(
                title="Admin Console", action="/admin/login",
                footer="Acme Portal v3.1"),
            "text/html; charset=utf-8", 200)
    if p in ("/wp-login.php", "/wp-admin"):
        return (
            _FAKE_LOGIN.format(
                title="WordPress", action="/wp-login.php",
                footer="Powered by WordPress 5.4.2"),
            "text/html; charset=utf-8", 200)
    if p.startswith("/phpmyadmin"):
        return (
            _FAKE_LOGIN.format(
                title="phpMyAdmin", action="/phpmyadmin/index.php",
                footer="phpMyAdmin 4.8.1"),
            "text/html; charset=utf-8", 200)
    return None
