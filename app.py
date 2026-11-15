"""Local demonstration web app for CyberPrior Objectives 1–3."""

from __future__ import annotations

import re
import hmac
import os
import secrets
import sqlite3
import smtplib
import ssl
from email.message import EmailMessage
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import Any
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from werkzeug.security import check_password_hash, generate_password_hash

import pandas as pd
from flask import Flask, abort, flash, redirect, render_template, request, send_from_directory, session, url_for


BASE_DIR = Path(__file__).resolve().parent
PROCESSED_DIR = BASE_DIR / "data" / "processed"
FIGURES_DIR = BASE_DIR / "docs" / "figures"
PRIORITIZED_FILE = PROCESSED_DIR / "CyberPrior_Prioritized_Dataset_v1.csv"
ENRICHED_FILE = PROCESSED_DIR / "CyberPrior_Enriched_Dataset_v1.csv"
RISK_FILE = PROCESSED_DIR / "CyberPrior_Risk_Assessed_Dataset_v1.csv"
EVALUATION_FILE = BASE_DIR / "docs" / "objective2_ml_evaluation_report.md"
VERIFICATION_FILE = BASE_DIR / "docs" / "objective1_verification_report.md"
RISK_LEVELS = ["Critical", "High", "Moderate", "Low"]
FIGURE_FILES = {
    "fig2_model_confusion_matrices.png",
    "fig3_feature_importance.png",
    "fig3_shap_summary.png",
    "fig4_threat_vs_impact_matrix.png",
}
CONTACT = {
    "name": "Sanchit Kumar", "role": "Team Lead",
    "email": "2023a1r118@mietjammu.in", "phone": "+91 95964 15537",
    "institute": "Model Institute of Engineering & Technology",
    "github": "https://github.com/sanchitk-dev/CyberPrior",
}


def _connect_db(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def _database(path: Path):
    connection = _connect_db(path)
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _initialize_local_store(app: Flask) -> None:
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    secret_file = Path(app.instance_path) / "secret_key"
    if not secret_file.exists():
        secret_file.write_text(secrets.token_hex(32), encoding="utf-8")
    app.secret_key = secret_file.read_text(encoding="utf-8").strip()
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", MAX_CONTENT_LENGTH=1024 * 1024)
    with _database(Path(app.instance_path) / "cyberprior.sqlite3") as db:
        db.executescript("""
          CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            recovery_hash TEXT,
            recovery_expires_at TEXT,
            email TEXT,
            created_at TEXT NOT NULL
          );
          CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            asset_name TEXT NOT NULL,
            cve_id TEXT NOT NULL,
            criticality TEXT NOT NULL,
            exposure TEXT NOT NULL,
            data_sensitivity TEXT NOT NULL,
            control_effectiveness TEXT NOT NULL,
            notes TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'Saved (not assessed)',
            created_at TEXT NOT NULL
          );
          CREATE TABLE IF NOT EXISTS monitoring_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            checked_at TEXT NOT NULL,
            source_snapshot TEXT NOT NULL,
            record_count INTEGER NOT NULL,
            critical_count INTEGER NOT NULL,
            high_count INTEGER NOT NULL,
            moderate_count INTEGER NOT NULL,
            low_count INTEGER NOT NULL
          );
          CREATE TABLE IF NOT EXISTS monitoring_records (
            check_id INTEGER NOT NULL REFERENCES monitoring_checks(id) ON DELETE CASCADE,
            asset_id TEXT NOT NULL,
            cve_id TEXT NOT NULL,
            asset TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            risk_score REAL NOT NULL,
            priority_score REAL NOT NULL,
            priority_rank INTEGER NOT NULL,
            kev INTEGER NOT NULL,
            recommended_action TEXT NOT NULL,
            PRIMARY KEY (check_id, asset_id)
          );
          CREATE TABLE IF NOT EXISTS monitoring_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            check_id INTEGER NOT NULL REFERENCES monitoring_checks(id) ON DELETE CASCADE,
            asset_id TEXT NOT NULL,
            cve_id TEXT NOT NULL,
            asset TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            summary TEXT NOT NULL,
            created_at TEXT NOT NULL
          );
          CREATE TABLE IF NOT EXISTS monitoring_alert_ack (
            alert_id INTEGER NOT NULL REFERENCES monitoring_alerts(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            acknowledged_at TEXT NOT NULL,
            PRIMARY KEY (alert_id, user_id)
          );
        """)
        user_columns = {row["name"] for row in db.execute("PRAGMA table_info(users)").fetchall()}
        if "recovery_hash" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN recovery_hash TEXT")
        if "recovery_expires_at" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN recovery_expires_at TEXT")
        if "email" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN email TEXT")
        db.execute("UPDATE submissions SET status = 'Saved (not assessed)' WHERE status = 'Pending assessment'")


def _send_recovery_email(email_address: str, recovery_code: str, expires_minutes: int | None = None) -> None:
    smtp_host = os.getenv("CYBERPRIOR_SMTP_HOST", "").strip()
    smtp_user = os.getenv("CYBERPRIOR_SMTP_USER", "").strip()
    smtp_password = os.getenv("CYBERPRIOR_SMTP_PASSWORD", "")
    from_address = os.getenv("CYBERPRIOR_SMTP_FROM", smtp_user).strip()
    if not smtp_host or not from_address:
        raise RuntimeError("Email delivery is not configured. Check the recovery email settings or contact the project owner.")
    try:
        smtp_port = int(os.getenv("CYBERPRIOR_SMTP_PORT", "587"))
    except ValueError as exc:
        raise RuntimeError("Email delivery settings are invalid. Check the recovery email settings or contact the project owner.") from exc

    message = EmailMessage()
    message["Subject"] = "CyberPrior account recovery code"
    message["From"] = from_address
    message["To"] = email_address
    expiry_note = f" This code expires in {expires_minutes} minutes." if expires_minutes else ""
    message.set_content(
        "Your CyberPrior account recovery code is:\n\n"
        f"{recovery_code}\n\n"
        f"Keep this code private. Anyone who has it can reset the password for your local CyberPrior account.{expiry_note} "
        "If you did not request this code, you can ignore this message."
    )
    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            server.ehlo()
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
            if smtp_user:
                server.login(smtp_user, smtp_password)
            server.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        raise RuntimeError("The recovery email could not be sent. Try again or contact the project owner.") from exc


def _is_safe_next(target: str | None) -> bool:
    if not target:
        return False
    parsed = urlparse(target)
    return not parsed.netloc and not parsed.scheme and target.startswith("/") and not target.startswith("//")


def _submission_values(form: Any) -> tuple[dict[str, str], list[str]]:
    values = {
        "asset_name": form.get("asset_name", "").strip(),
        "cve_id": form.get("cve_id", "").strip().upper(),
        "criticality": form.get("criticality", ""),
        "exposure": form.get("exposure", ""),
        "data_sensitivity": form.get("data_sensitivity", ""),
        "control_effectiveness": form.get("control_effectiveness", ""),
        "notes": form.get("notes", "").strip(),
    }
    valid_levels = {"Low", "Medium", "High", "Critical"}
    errors = []
    if not values["asset_name"] or len(values["asset_name"]) > 120:
        errors.append("Asset name is required and must be at most 120 characters.")
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", values["cve_id"]):
        errors.append("Enter a CVE identifier such as CVE-2024-3400.")
    if any(values[field] not in valid_levels for field in ("criticality", "data_sensitivity", "control_effectiveness")):
        errors.append("Choose a valid level for asset importance, data sensitivity, and safeguard strength.")
    if values["exposure"] not in {"Internal", "External"}:
        errors.append("Choose Internal or External network access.")
    if len(values["notes"]) > 1000:
        errors.append("Notes must be 1,000 characters or fewer.")
    return values, errors


def _as_bool(value: Any) -> bool:
    if pd.isna(value):
        return False
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "1", "yes"}


def _display(value: Any, fallback: str = "Not available") -> str:
    if value is None or pd.isna(value) or str(value).strip() in {"", "nan", "None"}:
        return fallback
    return str(value)


def _metric_rows(report: str, start_marker: str, end_marker: str | None) -> list[dict[str, str]]:
    start = report.find(start_marker)
    if start < 0:
        return []
    end = report.find(end_marker, start + len(start_marker)) if end_marker else -1
    section = report[start:end if end >= 0 else None]
    model_names = {"Logistic Regression", "Decision Tree", "Random Forest"}
    rows: list[dict[str, str]] = []
    for line in section.splitlines():
        if not line.strip().startswith("| **"):
            continue
        values = [part.strip() for part in line.strip().strip("|").split("|")]
        if len(values) < 6:
            continue
        name = values[0].strip("* ")
        if name in model_names:
            rows.append({
                "model": name,
                "accuracy": _metric_percent(values[1]),
                "macro_precision": _metric_percent(values[2]),
                "macro_recall": _metric_percent(values[3]),
                "macro_f1": _metric_percent(values[4]),
                "weighted_f1": _metric_percent(values[5]),
            })
    return rows


def _metric_percent(value: str) -> str:
    """Render report metrics consistently as percentages for the website."""
    cleaned = value.strip().replace(",", "")
    if cleaned.endswith("%"):
        return cleaned
    number = float(cleaned)
    return f"{number * 100:.2f}%" if abs(number) <= 1 else f"{number:.2f}%"


def _source_freshness() -> dict[str, str]:
    if not VERIFICATION_FILE.is_file():
        return {"snapshot": "Date unavailable", "nvd": "Not recorded", "epss": "Not recorded", "kev": "Not recorded"}
    report = VERIFICATION_FILE.read_text(encoding="utf-8")
    patterns = {
        "snapshot": r"\*\*Date Generated\*\*:\s*(\d{4}-\d{2}-\d{2})",
        "nvd": r"\*\*NVD cache files last updated\*\*:\s*(.+)",
        "epss": r"\*\*EPSS scoring date\(s\)\*\*:\s*(.+)",
        "kev": r"\*\*CISA KEV catalog\*\*:\s*(.+)",
    }
    values = {name: (re.search(pattern, report).group(1).strip() if re.search(pattern, report) else "Not recorded")
              for name, pattern in patterns.items()}
    try:
        values["snapshot"] = datetime.strptime(values["snapshot"], "%Y-%m-%d").strftime("%d %b %Y")
    except ValueError:
        values["snapshot"] = "Date unavailable"
    return values


def _load_data() -> tuple[pd.DataFrame, pd.DataFrame, str]:
    missing = [path.name for path in (PRIORITIZED_FILE, ENRICHED_FILE, RISK_FILE, EVALUATION_FILE) if not path.is_file()]
    if missing:
        raise FileNotFoundError("Required finalized CyberPrior outputs are missing: " + ", ".join(missing))
    prioritized = pd.read_csv(PRIORITIZED_FILE)
    enriched = pd.read_csv(ENRICHED_FILE)
    report = EVALUATION_FILE.read_text(encoding="utf-8")
    required = {"asset_id", "cve_id", "risk_level", "residual_risk_score", "priority_score", "priority_rank"}
    missing_columns = required - set(prioritized.columns)
    if missing_columns:
        # The project's finalized output names the risk label residual_risk_level.
        if "risk_level" in missing_columns:
            required.remove("risk_level")
            if "residual_risk_level" not in prioritized.columns:
                missing_columns.add("residual_risk_level")
            else:
                missing_columns.discard("risk_level")
        if missing_columns:
            raise ValueError("Prioritized dataset is missing columns: " + ", ".join(sorted(missing_columns)))
    return prioritized, enriched, report


def create_app() -> Flask:
    app = Flask(__name__)
    _initialize_local_store(app)
    app.jinja_env.filters["display"] = _display
    app.jinja_env.filters["is_true"] = _as_bool
    try:
        prioritized, enriched, evaluation_report = _load_data()
    except (FileNotFoundError, ValueError) as exc:
        # Keep the server usable so its error page can explain missing project artifacts.
        prioritized, enriched, evaluation_report = pd.DataFrame(), pd.DataFrame(), ""
        app.config["DATA_ERROR"] = str(exc)
    app.config["PRIORITIZED"] = prioritized
    app.config["ENRICHED"] = enriched
    app.config["EVALUATION_REPORT"] = evaluation_report
    app.config["SOURCE_FRESHNESS"] = _source_freshness()

    def require_data() -> tuple[pd.DataFrame, pd.DataFrame]:
        if app.config.get("DATA_ERROR"):
            abort(503, description=app.config["DATA_ERROR"])
        return app.config["PRIORITIZED"], app.config["ENRICHED"]

    @app.context_processor
    def shared_template_data() -> dict[str, Any]:
        return {
            "active_endpoint": request.endpoint,
            "current_username": session.get("username"),
            "csrf_token": lambda: session.setdefault("csrf_token", secrets.token_urlsafe(32)),
            "source_freshness": app.config["SOURCE_FRESHNESS"],
        }

    @app.before_request
    def require_login_for_workspace():
        if request.endpoint in {"setup", "login", "forgot_password", "send_password_recovery_code", "send_recovery_code", "logout", "contact", "about", "static", "not_found", "unavailable"}:
            return None
        if not session.get("user_id"):
            with _database(Path(app.instance_path) / "cyberprior.sqlite3") as db:
                has_users = db.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None
            return redirect(url_for("setup" if not has_users else "login", next=request.full_path.rstrip("?")))
        return None

    @app.before_request
    def validate_post_token():
        if request.method == "POST":
            expected = session.get("csrf_token", "")
            supplied = request.form.get("csrf_token", "")
            if not expected or not hmac.compare_digest(expected, supplied):
                abort(400, description="This form expired. Refresh the page and try again.")

    @app.route("/setup", methods=["GET", "POST"])
    def setup() -> str:
        db_path = Path(app.instance_path) / "cyberprior.sqlite3"
        with _database(db_path) as db:
            if request.method == "POST":
                username = request.form.get("username", "").strip()
                email_address = request.form.get("email", "").strip()
                password = request.form.get("password", "")
                if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
                    flash("Choose a username with 3–32 letters, numbers, dots, dashes, or underscores.", "error")
                elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email_address):
                    flash("Enter a valid email address for recovery-code delivery.", "error")
                elif len(password) < 12:
                    flash("Use a password with at least 12 characters.", "error")
                else:
                    recovery_code = secrets.token_urlsafe(24)
                    try:
                        db.execute(
                            "INSERT INTO users (username, password_hash, recovery_hash, email, created_at) VALUES (?, ?, ?, ?, ?)",
                            (username, generate_password_hash(password), generate_password_hash(recovery_code), email_address, datetime.now(timezone.utc).isoformat()),
                        )
                        return render_template("recovery_code.html", recovery_code=recovery_code, email=email_address, created_account=True, contact=CONTACT)
                    except sqlite3.IntegrityError:
                        flash("That username is already in use. Choose another one.", "error")
        return render_template("setup.html")

    @app.route("/login", methods=["GET", "POST"])
    def login() -> str:
        db_path = Path(app.instance_path) / "cyberprior.sqlite3"
        with _database(db_path) as db:
            has_users = db.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None
            if not has_users:
                return redirect(url_for("setup"))
            if request.method == "POST":
                username = request.form.get("username", "").strip()
                password = request.form.get("password", "")
                user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
                if user and check_password_hash(user["password_hash"], password):
                    session.clear()
                    session["user_id"] = user["id"]
                    session["username"] = user["username"]
                    destination = request.args.get("next")
                    return redirect(destination if _is_safe_next(destination) else url_for("dashboard"))
                flash("The username or password did not match.", "error")
        return render_template("login.html")

    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password() -> str:
        if request.method == "GET" and request.args.get("restart") == "1":
            session.pop("password_reset_email", None)
            return redirect(url_for("forgot_password"))
        email_address = session.get("password_reset_email", "")
        step = "verify" if email_address else "email"
        if request.method == "POST":
            email_address = request.form.get("email", "").strip()
            expected_email = session.get("password_reset_email", "")
            recovery_code = request.form.get("recovery_code", "").strip()
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")
            if not expected_email or not hmac.compare_digest(email_address.lower(), expected_email.lower()):
                flash("Start again with the email address for your account.", "error")
                session.pop("password_reset_email", None)
                return redirect(url_for("forgot_password"))
            if len(new_password) < 12:
                flash("Choose a new password with at least 12 characters.", "error")
            elif new_password != confirm_password:
                flash("The new passwords do not match.", "error")
            else:
                with _database(Path(app.instance_path) / "cyberprior.sqlite3") as db:
                    matches = db.execute(
                        "SELECT id, recovery_hash, recovery_expires_at FROM users WHERE lower(email) = lower(?) ORDER BY id LIMIT 2",
                        (email_address,),
                    ).fetchall()
                    user = matches[0] if len(matches) == 1 else None
                    code_is_valid = bool(user and user["recovery_hash"] and check_password_hash(user["recovery_hash"], recovery_code))
                    if code_is_valid and user["recovery_expires_at"]:
                        try:
                            expires_at = datetime.fromisoformat(user["recovery_expires_at"])
                            code_is_valid = expires_at > datetime.now(timezone.utc)
                        except ValueError:
                            code_is_valid = False
                    if code_is_valid:
                        db.execute(
                            "UPDATE users SET password_hash = ?, recovery_hash = NULL, recovery_expires_at = NULL WHERE id = ?",
                            (generate_password_hash(new_password), user["id"]),
                        )
                        session.clear()
                        flash("Your password has been changed. Sign in with your new password.", "success")
                        return redirect(url_for("login"))
                flash("That code could not be verified. Check it and try again, or request a new one.", "error")
            step = "verify"
        return render_template("forgot_password.html", contact=CONTACT, step=step, email=email_address)

    @app.route("/send-password-recovery-code", methods=["POST"])
    def send_password_recovery_code() -> str:
        email_address = request.form.get("email", "").strip()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email_address):
            flash("Enter a valid email address.", "error")
            return redirect(url_for("forgot_password"))
        email_address = email_address.lower()
        with _database(Path(app.instance_path) / "cyberprior.sqlite3") as db:
            matches = db.execute(
                "SELECT id FROM users WHERE lower(email) = lower(?) ORDER BY id LIMIT 2", (email_address,),
            ).fetchall()
        if len(matches) == 1:
            recovery_code = secrets.token_urlsafe(24)
            try:
                _send_recovery_email(email_address, recovery_code, expires_minutes=15)
            except RuntimeError as exc:
                flash(str(exc), "error")
                return redirect(url_for("forgot_password"))
            else:
                expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
                with _database(Path(app.instance_path) / "cyberprior.sqlite3") as db:
                    db.execute(
                        "UPDATE users SET recovery_hash = ?, recovery_expires_at = ? WHERE id = ?",
                        (generate_password_hash(recovery_code), expires_at, matches[0]["id"]),
                    )
        session["password_reset_email"] = email_address
        flash("If this email belongs to an account, a recovery code has been sent. Check your inbox and spam folder.", "success")
        return redirect(url_for("forgot_password"))

    @app.route("/account/recovery-code", methods=["GET", "POST"])
    def account_recovery_code() -> str:
        recovery_code = None
        email_address = ""
        with _database(Path(app.instance_path) / "cyberprior.sqlite3") as db:
            user = db.execute("SELECT email FROM users WHERE id = ?", (session["user_id"],)).fetchone()
            email_address = user["email"] or ""
        if request.method == "POST":
            email_address = request.form.get("email", "").strip()
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email_address):
                flash("Enter a valid email address so you can receive your recovery code.", "error")
                return render_template("account_recovery_code.html", recovery_code=None, email=email_address)
            recovery_code = secrets.token_urlsafe(24)
            with _database(Path(app.instance_path) / "cyberprior.sqlite3") as db:
                db.execute(
                    "UPDATE users SET recovery_hash = ?, recovery_expires_at = NULL, email = ? WHERE id = ?",
                    (generate_password_hash(recovery_code), email_address, session["user_id"]),
                )
            return render_template("recovery_code.html", recovery_code=recovery_code, email=email_address, created_account=False, contact=CONTACT)
        return render_template("account_recovery_code.html", recovery_code=recovery_code, email=email_address)

    @app.route("/send-recovery-code", methods=["POST"])
    def send_recovery_code() -> str:
        recovery_code = request.form.get("recovery_code", "").strip()
        email_address = request.form.get("email", "").strip()
        created_account = request.form.get("created_account") == "true"
        if not recovery_code or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email_address):
            mail_status = "Enter a valid email address to send this recovery code."
        else:
            try:
                _send_recovery_email(email_address, recovery_code)
                mail_status = f"Recovery code sent to {email_address}."
            except RuntimeError as exc:
                mail_status = str(exc)
        return render_template(
            "recovery_code.html", recovery_code=recovery_code, email=email_address,
            created_account=created_account, contact=CONTACT, mail_status=mail_status,
        )

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        flash("You have been signed out.", "success")
        return redirect(url_for("login"))

    @app.route("/contact")
    def contact() -> str:
        return render_template("contact.html", contact=CONTACT)

    @app.route("/records")
    def records() -> str:
        with _database(Path(app.instance_path) / "cyberprior.sqlite3") as db:
            rows = db.execute(
                "SELECT * FROM submissions WHERE user_id = ? ORDER BY id DESC", (session["user_id"],)
            ).fetchall()
        return render_template("records.html", records=rows)

    @app.route("/records/new", methods=["GET", "POST"])
    def new_record() -> str:
        if request.method == "POST":
            values, errors = _submission_values(request.form)
            if errors:
                for error in errors:
                    flash(error, "error")
                return render_template("record_form.html", form=request.form)
            with _database(Path(app.instance_path) / "cyberprior.sqlite3") as db:
                db.execute("""INSERT INTO submissions
                    (user_id, asset_name, cve_id, criticality, exposure, data_sensitivity,
                     control_effectiveness, notes, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (session["user_id"], *values.values(), "Saved (not assessed)", datetime.now(timezone.utc).isoformat(timespec="seconds")))
            flash("Your scenario has been saved. It has not been assessed or scored.", "success")
            return redirect(url_for("records"))
        return render_template("record_form.html", form={}, editing=False)

    @app.route("/records/<int:record_id>/edit", methods=["GET", "POST"])
    def edit_record(record_id: int) -> str:
        db_path = Path(app.instance_path) / "cyberprior.sqlite3"
        with _database(db_path) as db:
            row = db.execute("SELECT * FROM submissions WHERE id = ? AND user_id = ?", (record_id, session["user_id"])).fetchone()
            if row is None:
                abort(404)
            if request.method == "POST":
                values, errors = _submission_values(request.form)
                if errors:
                    for error in errors:
                        flash(error, "error")
                    return render_template("record_form.html", form=request.form, editing=True)
                db.execute("""UPDATE submissions SET asset_name = ?, cve_id = ?, criticality = ?, exposure = ?,
                    data_sensitivity = ?, control_effectiveness = ?, notes = ?
                    WHERE id = ? AND user_id = ?""",
                    (*values.values(), record_id, session["user_id"]))
                flash("Scenario updated. It remains saved but unassessed.", "success")
                return redirect(url_for("records"))
        return render_template("record_form.html", form=dict(row), editing=True)

    @app.route("/records/<int:record_id>/delete", methods=["POST"])
    def delete_record(record_id: int):
        with _database(Path(app.instance_path) / "cyberprior.sqlite3") as db:
            cursor = db.execute("DELETE FROM submissions WHERE id = ? AND user_id = ?", (record_id, session["user_id"]))
            if cursor.rowcount == 0:
                abort(404)
        flash("Scenario deleted.", "success")
        return redirect(url_for("records"))

    @app.route("/monitoring", methods=["GET", "POST"])
    def monitoring() -> str:
        df, _ = require_data()
        db_path = Path(app.instance_path) / "cyberprior.sqlite3"
        if request.method == "POST":
            checked_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            levels = {"Critical": 0, "High": 1, "Moderate": 2, "Low": 3}
            current_by_asset: dict[str, dict[str, Any]] = {}
            for record in df.to_dict("records"):
                current_by_asset[str(record["asset_id"])] = record
            with _database(db_path) as db:
                previous_check = db.execute("SELECT id FROM monitoring_checks ORDER BY id DESC LIMIT 1").fetchone()
                previous_by_asset: dict[str, sqlite3.Row] = {}
                if previous_check:
                    previous_by_asset = {
                        row["asset_id"]: row for row in db.execute(
                            "SELECT * FROM monitoring_records WHERE check_id = ?", (previous_check["id"],)
                        ).fetchall()
                    }
                counts = df["residual_risk_level"].value_counts().to_dict()
                source_snapshot = app.config["SOURCE_FRESHNESS"].get("snapshot", "Date unavailable")
                cursor = db.execute(
                    """INSERT INTO monitoring_checks
                       (checked_at, source_snapshot, record_count, critical_count, high_count, moderate_count, low_count)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (checked_at, source_snapshot, len(df), int(counts.get("Critical", 0)), int(counts.get("High", 0)),
                     int(counts.get("Moderate", 0)), int(counts.get("Low", 0))),
                )
                check_id = cursor.lastrowid
                inserts = []
                alerts = []
                for asset_id, record in current_by_asset.items():
                    level = str(record.get("residual_risk_level", "Low"))
                    risk_score = float(record.get("residual_risk_score", 0) or 0)
                    priority_score = float(record.get("priority_score", 0) or 0)
                    priority_rank = int(float(record.get("priority_rank", 0) or 0))
                    kev = int(_as_bool(record.get("cisa_kev")))
                    inserts.append((check_id, asset_id, str(record.get("cve_id", "")), str(record.get("asset", "")),
                                    level, risk_score, priority_score, priority_rank, kev,
                                    str(record.get("recommended_action", ""))))
                    old = previous_by_asset.get(asset_id)
                    if not old:
                        continue
                    old_level = str(old["risk_level"])
                    old_kev = int(old["kev"])
                    delta = risk_score - float(old["risk_score"])
                    if kev and not old_kev:
                        alerts.append((check_id, asset_id, str(record.get("cve_id", "")), str(record.get("asset", "")),
                                       "kev", "Newly listed in the known-exploited catalog", checked_at))
                    elif levels.get(level, 3) < levels.get(old_level, 3):
                        alerts.append((check_id, asset_id, str(record.get("cve_id", "")), str(record.get("asset", "")),
                                       "escalation", f"Risk level increased from {old_level} to {level}", checked_at))
                    elif delta >= 10:
                        alerts.append((check_id, asset_id, str(record.get("cve_id", "")), str(record.get("asset", "")),
                                       "risk_increase", f"Residual risk increased by {delta:.1f} points", checked_at))
                    elif priority_rank and old["priority_rank"] and int(old["priority_rank"]) - priority_rank >= 25:
                        alerts.append((check_id, asset_id, str(record.get("cve_id", "")), str(record.get("asset", "")),
                                       "priority_change", f"Resolve rank moved up from #{old['priority_rank']} to #{priority_rank}", checked_at))
                db.executemany(
                    """INSERT INTO monitoring_records
                       (check_id, asset_id, cve_id, asset, risk_level, risk_score, priority_score, priority_rank, kev, recommended_action)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", inserts,
                )
                db.executemany(
                    """INSERT INTO monitoring_alerts
                       (check_id, asset_id, cve_id, asset, alert_type, summary, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""", alerts,
                )
            flash(
                "Baseline snapshot recorded." if not previous_check else
                f"Snapshot check complete · {len(alerts)} change alert{'s' if len(alerts) != 1 else ''} found.",
                "success",
            )
            return redirect(url_for("monitoring"))

        ranked = df.sort_values("priority_rank", kind="stable")
        attention = ranked[ranked["residual_risk_level"].isin(["Critical", "High"])].head(10).to_dict("records")
        risk_counts = df["residual_risk_level"].value_counts().to_dict()
        with _database(db_path) as db:
            checks = db.execute("SELECT * FROM monitoring_checks ORDER BY id DESC LIMIT 8").fetchall()
            latest_check = checks[0] if checks else None
            recent_alerts = []
            alert_count = 0
            if latest_check:
                alert_count = db.execute(
                    "SELECT COUNT(*) FROM monitoring_alerts WHERE check_id = ?", (latest_check["id"],)
                ).fetchone()[0]
                recent_alerts = db.execute(
                    """SELECT a.*, ack.acknowledged_at FROM monitoring_alerts a
                       LEFT JOIN monitoring_alert_ack ack ON ack.alert_id = a.id AND ack.user_id = ?
                       ORDER BY a.id DESC LIMIT 12""",
                    (session["user_id"],),
                ).fetchall()
            trends = list(reversed(checks))
        return render_template(
            "monitoring.html", checks=checks, trends=trends, latest_check=latest_check,
            recent_alerts=recent_alerts, alert_count=alert_count, attention=attention,
            risk_counts={level: int(risk_counts.get(level, 0)) for level in RISK_LEVELS}, total=len(df),
        )

    @app.route("/monitoring/alerts/<int:alert_id>/acknowledge", methods=["POST"])
    def acknowledge_monitoring_alert(alert_id: int):
        with _database(Path(app.instance_path) / "cyberprior.sqlite3") as db:
            exists = db.execute("SELECT 1 FROM monitoring_alerts WHERE id = ?", (alert_id,)).fetchone()
            if exists is None:
                abort(404)
            db.execute(
                "INSERT OR IGNORE INTO monitoring_alert_ack (alert_id, user_id, acknowledged_at) VALUES (?, ?, ?)",
                (alert_id, session["user_id"], datetime.now(timezone.utc).isoformat(timespec="seconds")),
            )
        flash("Alert acknowledged.", "success")
        return redirect(url_for("monitoring"))

    @app.route("/")
    def dashboard() -> str:
        df, _ = require_data()
        risk_counts = df["residual_risk_level"].value_counts().to_dict()
        total = len(df)
        risk_rows = [{
            "level": level,
            "count": int(risk_counts.get(level, 0)),
            "percent": (risk_counts.get(level, 0) / total * 100) if total else 0,
        } for level in RISK_LEVELS]
        risk_colors = {"Critical": "#ff6174", "High": "#ff9b54", "Moderate": "#f4c95d", "Low": "#45d3a2"}
        gradient_stops = []
        cumulative = 0.0
        for item in risk_rows:
            next_stop = cumulative + item["percent"]
            gradient_stops.append(f"{risk_colors[item['level']]} {cumulative:.4f}% {next_stop:.4f}%")
            cumulative = next_stop
        risk_gradient = ", ".join(gradient_stops)
        exposure_counts = df["exposure"].fillna("Unknown").value_counts().to_dict()
        criticality_counts = df["criticality"].fillna("Unknown").value_counts().to_dict()
        for label in ("External", "Internal"):
            exposure_counts.setdefault(label, 0)
        for label in ("Critical", "High", "Medium", "Low"):
            criticality_counts.setdefault(label, 0)
        kev_count = int(df["cisa_kev"].map(_as_bool).sum())
        critical_count = int(risk_counts.get("Critical", 0))
        stats = {
            "records": total,
            "cves": int(df["cve_id"].nunique()),
            "asset_types": int(df["asset"].nunique()),
            "critical": critical_count,
            "high": int(risk_counts.get("High", 0)),
            "moderate": int(risk_counts.get("Moderate", 0)),
            "low": int(risk_counts.get("Low", 0)),
            "kev": kev_count,
        }
        stats["high_critical"] = stats["critical"] + stats["high"]
        ranked_rows = df.sort_values("priority_rank", kind="stable")
        representative_rows = []
        for level in RISK_LEVELS:
            level_rows = ranked_rows[ranked_rows["residual_risk_level"] == level]
            if not level_rows.empty:
                representative_rows.append(level_rows.iloc[0])
        top_rows = sorted(representative_rows, key=lambda row: row["priority_rank"])
        comparison = None
        if total and df["cve_id"].nunique() > 0:
            cve_spread = df.groupby("cve_id")["residual_risk_score"].agg(["min", "max", "count"])
            cve_spread["spread"] = cve_spread["max"] - cve_spread["min"]
            cve_spread = cve_spread[cve_spread["count"] > 1]
            if not cve_spread.empty:
                selected_cve = cve_spread.sort_values(["spread", "count"], ascending=[False, False]).index[0]
                scenarios = df[df["cve_id"].astype(str) == str(selected_cve)].sort_values(
                    ["residual_risk_score", "priority_rank"], ascending=[False, True], kind="stable"
                )
                high_context = scenarios.iloc[0].to_dict()
                low_context = scenarios.iloc[-1].to_dict()
                comparison = {
                    "cve_id": str(selected_cve),
                    "high": high_context,
                    "low": low_context,
                    "spread": float(cve_spread.loc[selected_cve, "spread"]),
                    "scenarios": int(len(scenarios)),
                    "asset_types": int(scenarios["asset"].nunique()),
                }
        return render_template(
            "dashboard.html", stats=stats, risk_rows=risk_rows,
            exposure_counts=exposure_counts, criticality_counts=criticality_counts,
            top_rows=top_rows, total=total, risk_gradient=risk_gradient,
            comparison=comparison,
        )

    @app.route("/prioritizer")
    def prioritizer() -> str:
        df, _ = require_data()
        filtered = df.copy()
        search = request.args.get("search", "").strip()
        risk = request.args.get("risk", "")
        exposure = request.args.get("exposure", "")
        criticality = request.args.get("criticality", "")
        kev = request.args.get("kev", "")
        sort = request.args.get("sort", "priority_rank")

        if search:
            mask = (
                filtered["cve_id"].astype(str).str.contains(search, case=False, na=False, regex=False)
                | filtered["asset"].astype(str).str.contains(search, case=False, na=False, regex=False)
                | filtered["asset_id"].astype(str).str.contains(search, case=False, na=False, regex=False)
            )
            filtered = filtered[mask]
        if risk in RISK_LEVELS:
            filtered = filtered[filtered["residual_risk_level"] == risk]
        if exposure in {"Internal", "External"}:
            filtered = filtered[filtered["exposure"] == exposure]
        if criticality in {"Low", "Medium", "High", "Critical"}:
            filtered = filtered[filtered["criticality"] == criticality]
        if kev in {"yes", "no"}:
            filtered = filtered[filtered["cisa_kev"].map(_as_bool) == (kev == "yes")]

        sort_fields = {
            "priority_rank": ("priority_rank", True),
            "priority_score": ("priority_score", False),
            "residual_risk_score": ("residual_risk_score", False),
            "nvd_cvss_score": ("nvd_cvss_score", False),
            "epss_score": ("epss_score", False),
        }
        sort_field, ascending = sort_fields.get(sort, sort_fields["priority_rank"])
        filtered = filtered.sort_values(sort_field, ascending=ascending, kind="stable")
        page_size = 40
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        pages = max(1, (len(filtered) + page_size - 1) // page_size)
        page = min(page, pages)
        rows = filtered.iloc[(page - 1) * page_size:page * page_size].to_dict("records")
        return render_template(
            "prioritizer.html", rows=rows, total_matches=len(filtered), page=page,
            pages=pages, page_size=page_size, search=search, risk=risk,
            exposure=exposure, criticality=criticality, kev=kev, sort=sort,
        )

    @app.route("/vulnerability/<asset_id>")
    def vulnerability_detail(asset_id: str) -> str:
        df, _ = require_data()
        matches = df[df["asset_id"].astype(str).str.casefold() == asset_id.casefold()]
        if matches.empty:
            abort(404)
        record = matches.iloc[0].to_dict()
        explanations = [part.strip() for part in str(record.get("risk_explanation", "")).split(";") if part.strip()]
        shap_values = {
            "cvss_score": _display(record.get("nvd_cvss_score")),
            "epss_score": f"{float(record['epss_score']) * 100:.2f}%",
            "cisa_kev": "Listed" if _as_bool(record.get("cisa_kev")) else "Not listed",
            "criticality": _display(record.get("criticality")),
            "exposure": _display(record.get("exposure")),
            "data_sensitivity": _display(record.get("data_sensitivity")),
            "control_effectiveness": _display(record.get("control_effectiveness")),
        }
        shap_result = None
        shap_error = None
        try:
            shap_result = _get_explainer().explain_asset(asset_id)
        except Exception as exc:  # Keep the risk-engine explanation available if SHAP is unavailable.
            app.logger.exception("SHAP explanation failed for %s", asset_id)
            shap_error = f"Model attribution is unavailable for this view ({type(exc).__name__})."
        return render_template(
            "vulnerability.html", record=record, explanations=explanations,
            shap_result=shap_result, shap_error=shap_error, shap_values=shap_values,
        )

    @app.route("/threat-intelligence")
    def threat_intelligence() -> str:
        _, df = require_data()
        cves = sorted(df["cve_id"].dropna().astype(str).unique().tolist())
        selected = request.args.get("cve", "").strip().upper()
        record = None
        if selected in cves:
            record = df[df["cve_id"].astype(str) == selected].iloc[0].to_dict()
        return render_template("threat_intelligence.html", cves=cves, selected=selected, record=record)

    @app.route("/ml-insights")
    def ml_insights() -> str:
        df, _ = require_data()
        report = app.config["EVALUATION_REPORT"]
        random_metrics = _metric_rows(report, "## 1. Comparative Model Performance", "### Evaluation 2: Performance on CVEs excluded from training")
        grouped_metrics = _metric_rows(report, "### Evaluation 2: Performance on CVEs excluded from training", "The first split is the standard baseline")
        random_split_match = re.search(
            r"\*\*Split Protocol\*\*: Stratified (\d+)% Train \((\d+) records\) / (\d+)% Test \((\d+) records\), `random_state=(\d+)`",
            report,
        )
        random_split = random_split_match.groups() if random_split_match else None
        split_match = re.search(
            r"It produced (\d+) training rows across (\d+) CVEs and (\d+) test rows across (\d+) CVEs, with zero CVE overlap",
            report,
        )
        grouped_split = split_match.groups() if split_match else None
        if not random_metrics or not grouped_metrics:
            abort(503, description="Could not read model metrics from docs/objective2_ml_evaluation_report.md")
        return render_template(
            "ml_insights.html", random_metrics=random_metrics,
            grouped_metrics=grouped_metrics, grouped_split=grouped_split,
            random_split=random_split, cve_count=int(df["cve_id"].nunique()),
            figure_files=sorted(FIGURE_FILES),
        )

    @app.route("/about")
    def about() -> str:
        df, _ = require_data()
        return render_template(
            "about.html", records=len(df), cves=df["cve_id"].nunique(),
            asset_types=df["asset"].nunique(),
            kev_records=int(df["cisa_kev"].map(_as_bool).sum()),
        )

    @app.route("/figures/<path:filename>")
    def project_figure(filename: str):
        if filename not in FIGURE_FILES:
            abort(404)
        return send_from_directory(FIGURES_DIR, filename)

    @app.errorhandler(404)
    def not_found(_error: Any) -> tuple[str, int]:
        return render_template("error.html", code=404, message="That project record or page was not found."), 404

    @app.errorhandler(503)
    def unavailable(error: Any) -> tuple[str, int]:
        return render_template("error.html", code=503, message=getattr(error, "description", "Required project data is unavailable.")), 503

    return app


@lru_cache(maxsize=1)
def _get_explainer():
    """Load the existing model and SHAP explainer once, only when detail is requested."""
    import sys

    sys.path.insert(0, str(BASE_DIR / "src"))
    from explainability import CyberPriorExplainer

    return CyberPriorExplainer()


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
