"""WatchTower SIEM - View Routes (serves the dashboard SPA and test tool)"""
from flask import Blueprint, render_template, redirect, url_for

views_bp = Blueprint("views", __name__)


@views_bp.get("/")
def index():
    return redirect(url_for("views.dashboard"))


@views_bp.get("/login")
def login_page():
    return render_template("dashboard/login.html")


@views_bp.get("/dashboard")
@views_bp.get("/dashboard/<path:subpath>")
def dashboard(subpath=None):
    return render_template("dashboard/app.html")


@views_bp.get("/test-tool")
def test_tool():
    """Attack simulator test tool — served at http://localhost:5000/test-tool"""
    return render_template("test_tool.html")
