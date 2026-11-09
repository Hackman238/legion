"""Request-level protections for the local web UI: cross-site writes, DNS rebinding, JSON error bodies."""
from __future__ import annotations

import hmac

from flask import Flask, jsonify, redirect, render_template, request


_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]", "0.0.0.0"}
_STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _request_host_name(host_header: str) -> str:
    value = str(host_header or "").strip().lower()
    if value.startswith("["):
        return value.split("]", 1)[0] + "]"
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


def origin_matches_request_host(origin: str, request_host: str) -> bool:
    """True when an Origin header names exactly this server (scheme-less host:port comparison).

    Both sides omit the port when it is the scheme default, so a plain string compare is right; stripping ports
    would let a page on another local port (http://127.0.0.1:8080) pass as same-origin.
    """
    value = str(origin or "").strip().lower()
    if not value or value == "null":
        return False
    origin_host = value.split("://", 1)[-1].split("/", 1)[0]
    return origin_host == str(request_host or "").strip().lower()


def request_is_cross_site(method: str, headers, request_host: str) -> bool:
    """True for a state-changing request that a browser sent from another origin.

    A hostile page can auto-submit a form (or a multipart fetch) at the local Legion port; browsers always add
    Origin and Sec-Fetch-Site to such requests, while same-origin page scripts and non-browser clients (curl,
    scripts) either send a matching Origin or none at all.
    """
    if str(method or "").upper() not in _STATE_CHANGING_METHODS:
        return False
    fetch_site = str(headers.get("Sec-Fetch-Site", "") or "").strip().lower()
    if fetch_site in {"cross-site", "same-site"}:
        return True
    origin = str(headers.get("Origin", "") or "").strip().lower()
    if not origin:
        return False  # non-browser clients (curl, scripts) send no Origin
    return not origin_matches_request_host(origin, request_host)  # "null" (sandboxed frame) never matches


def request_host_is_rebound(bind_host: str, request_host: str) -> bool:
    """DNS rebinding check: a loopback-only server must only be addressed as localhost."""
    if str(bind_host or "").strip() not in {"127.0.0.1", "localhost", "::1"}:
        return False
    return _request_host_name(request_host) not in _LOOPBACK_HOSTS


AUTH_COOKIE_NAME = "legion_token"
_AUTH_EXEMPT_PREFIXES = ("/static/",)
_AUTH_EXEMPT_PATHS = {"/health", "/login", "/logout", "/favicon.ico"}


def configured_web_token(app: Flask) -> str:
    return str(app.config.get("LEGION_WEB_TOKEN", "") or "").strip()


def request_presents_token(app: Flask) -> bool:
    """Bearer header, X-Legion-Token header or the session cookie, compared in constant time."""
    expected = configured_web_token(app)
    if not expected:
        return True
    candidates = []
    authorization = str(request.headers.get("Authorization", "") or "").strip()
    if authorization.lower().startswith("bearer "):
        candidates.append(authorization[7:].strip())
    candidates.append(str(request.headers.get("X-Legion-Token", "") or "").strip())
    candidates.append(str(request.cookies.get(AUTH_COOKIE_NAME, "") or "").strip())
    return any(candidate and hmac.compare_digest(candidate, expected) for candidate in candidates)


def install_request_guards(app: Flask) -> None:
    @app.before_request
    def _reject_cross_site_requests():
        bind_host = str(app.config.get("LEGION_WEB_BIND_HOST", "127.0.0.1") or "127.0.0.1")
        if request_host_is_rebound(bind_host, request.host):
            return jsonify({"status": "error", "error": "Host header does not match the local interface."}), 403
        if request_is_cross_site(request.method, request.headers, request.host):
            return jsonify({"status": "error", "error": "Cross-site requests are not accepted."}), 403
        if configured_web_token(app):
            path = str(request.path or "")
            if path in _AUTH_EXEMPT_PATHS or path.startswith(_AUTH_EXEMPT_PREFIXES):
                return None
            if not request_presents_token(app):
                # Browsers send "text/html,...,*/*;q=0.8": */* makes accept_json true too, so ask which wins.
                wants_page = request.method == "GET" and \
                    request.accept_mimetypes.best_match(["application/json", "text/html"]) == "text/html"
                if (path.startswith("/api/") or path.startswith("/ws/")) and not wants_page:
                    return jsonify({"status": "error", "error": "Authentication required: send the web token."}), 401
                return redirect("/login")
        return None

    @app.get("/login")
    def _login_form():
        if not configured_web_token(app):
            return redirect("/")
        if request_presents_token(app):
            return redirect("/")
        return render_template("login.html", error="")

    @app.post("/login")
    def _login_submit():
        if not configured_web_token(app):
            return redirect("/")
        supplied = str(request.form.get("token", "") or "").strip()
        if not supplied or not hmac.compare_digest(supplied, configured_web_token(app)):
            return render_template("login.html", error="That token was not accepted."), 401
        response = redirect("/")
        response.set_cookie(
            AUTH_COOKIE_NAME,
            supplied,
            httponly=True,
            samesite="Strict",
            secure=request.is_secure,
            max_age=12 * 60 * 60,
        )
        return response

    @app.post("/logout")
    def _logout():
        response = redirect("/login" if configured_web_token(app) else "/")
        response.delete_cookie(AUTH_COOKIE_NAME)
        return response

    def _json_http_error(error):
        if request.path.startswith("/api/") or request.path.startswith("/ws/"):
            code = int(getattr(error, "code", 500) or 500)
            message = str(getattr(error, "description", "") or getattr(error, "name", "") or "Request failed.")
            if code == 413:
                message = "Upload too large."
            return jsonify({"status": "error", "error": message}), code
        return error

    for status_code in (404, 405, 413, 500):
        app.register_error_handler(status_code, _json_http_error)
