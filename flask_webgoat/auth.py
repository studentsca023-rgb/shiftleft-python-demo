from urllib.parse import urlparse
from flask import Blueprint, request, jsonify, session, redirect
from . import query_db


def is_safe_url(url):
    """Check if URL is safe for redirect (relative URL only)."""
    parsed = urlparse(url)
    return not parsed.netloc and not parsed.scheme

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    if username is None or password is None:
        return (
            jsonify({"error": "username and password parameter have to be provided"}),
            400,
        )

    query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
    result = query_db(query, (username, password), True)
    if result is None:
        return jsonify({"bad_login": True}), 400
    session["user_info"] = (result[0], result[1], result[2])
    return jsonify({"success": True})


@bp.route("/login_and_redirect")
def login_and_redirect():
    username = request.args.get("username")
    password = request.args.get("password")
    url = request.args.get("url")
    if username is None or password is None or url is None:
        return (
            jsonify(
                {"error": "username, password, and url parameters have to be provided"}
            ),
            400,
        )

    parsed = urlparse(url)
    if parsed.netloc or parsed.scheme:
        return jsonify({"error": "Invalid redirect URL"}), 400
    safe_url = parsed.path
    if parsed.query:
        safe_url = f"{safe_url}?{parsed.query}"

    query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
    result = query_db(query, (username, password), True)
    if result is None:
        return redirect(safe_url)
    session["user_info"] = (result[0], result[1], result[2])
    return jsonify({"success": True})
