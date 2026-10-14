"""Local demonstration web app for CyberPrior Objectives 1 and 2."""

from __future__ import annotations

import re
import hmac
import secrets
import sqlite3
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import Any
from datetime import datetime, timezone
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
        """)
        db.execute("UPDATE submissions SET status = 'Saved (not assessed)' WHERE status = 'Pending assessment'")


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
        if request.endpoint in {"setup", "login", "logout", "contact", "about", "static", "not_found", "unavailable"}:
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
            has_users = db.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None
            if has_users:
                return redirect(url_for("login"))
            if request.method == "POST":
                username = request.form.get("username", "").strip()
                password = request.form.get("password", "")
                if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
                    flash("Choose a username with 3–32 letters, numbers, dots, dashes, or underscores.", "error")
                elif len(password) < 12:
                    flash("Use a password with at least 12 characters.", "error")
                else:
                    db.execute(
                        "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                        (username, generate_password_hash(password), datetime.now(timezone.utc).isoformat()),
                    )
                    flash("Your local account is ready. Sign in to continue.", "success")
                    return redirect(url_for("login"))
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
        selected_ids = {str(row["asset_id"]) for row in representative_rows}
        for _, row in ranked_rows.iterrows():
            if len(representative_rows) >= 5:
                break
            if str(row["asset_id"]) not in selected_ids:
                representative_rows.append(row)
                selected_ids.add(str(row["asset_id"]))
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
