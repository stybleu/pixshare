import secrets
from flask import abort, request, session


def generate_csrf_token() -> str:
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def validate_csrf() -> None:
    form_token = (request.form.get("csrf_token") or "").strip()
    session_token = session.get("_csrf_token", "")
    if not form_token or not session_token or form_token != session_token:
        abort(400, "CSRF token invalide")


def inject_csrf_token():
    return {"csrf_token": generate_csrf_token()}
