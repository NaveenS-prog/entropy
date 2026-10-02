"""Flask fixture demonstrating authenticated, unauthenticated, and inconsistent routes."""

from flask import Blueprint, Flask, jsonify, request
from functools import wraps

app = Flask(__name__)
bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated


# Clean authenticated endpoint
@app.route("/profile")
@login_required
def user_profile():
    return jsonify({"user": "bob"})


# ENT-AUTH-001: Standalone sensitive unprotected modifying route
@app.post("/admin/purge")
def purge_system():
    return jsonify({"purged": True})


# ENT-AUTH-002: Inconsistent authentication in blueprint
@bp.route("/overview")
@login_required
def dash_overview():
    return jsonify({"overview": True})


@bp.route("/settings")
@login_required
def dash_settings():
    return jsonify({"settings": True})


@bp.route("/raw_dump")
def dash_raw_dump():
    # Inconsistent: omitted login_required in dashboard blueprint
    return jsonify({"data": []})
