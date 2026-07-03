"""
Packet Sentinel
----------------
A simple Flask dashboard for analyzing packet captures exported from
Wireshark as CSV (File -> Export Packet Dissections -> As CSV).

Expected CSV columns (Wireshark default export):
    No., Time, Source, Destination, Protocol, Length, Info

Run:
    python app.py
Then open:
    http://127.0.0.1:5000/
"""

import os
import stat
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
import pandas as pd
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "packet-sentinel-dev-key"  # needed for flash messages

CSV_PATH = os.path.join(os.path.dirname(__file__), "network_data.csv")
ALLOWED_EXTENSIONS = {"csv"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def load_data():
    """Load and lightly clean the Wireshark CSV export."""
    if not os.path.exists(CSV_PATH):
        return pd.DataFrame(
            columns=["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"]
        )

    df = pd.read_csv(CSV_PATH)

    # Normalize column names in case of extra whitespace
    df.columns = [c.strip() for c in df.columns]

    # Make sure key columns exist even if the export was customized
    for col in ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"]:
        if col not in df.columns:
            df[col] = ""

    # Length should be numeric for stats/charts
    df["Length"] = pd.to_numeric(df["Length"], errors="coerce").fillna(0)

    return df


def build_summary(df: pd.DataFrame):
    """Compute dashboard summary statistics from the packet dataframe."""
    if df.empty:
        return {
            "total_packets": 0,
            "total_bytes": 0,
            "protocol_counts": {},
            "top_sources": {},
            "top_destinations": {},
        }

    def clean_counts(series):
        # Force plain str keys and plain int values so the dict is
        # always JSON-serializable (pandas/NumPy types are not).
        counts = series.astype(str).value_counts().head(10)
        return {str(k): int(v) for k, v in counts.items()}

    protocol_counts = clean_counts(df["Protocol"])
    top_sources = clean_counts(df["Source"])
    top_destinations = clean_counts(df["Destination"])

    return {
        "total_packets": int(len(df)),
        "total_bytes": int(df["Length"].sum()),
        "protocol_counts": protocol_counts,
        "top_sources": top_sources,
        "top_destinations": top_destinations,
    }


@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("file")

    if file is None or file.filename == "":
        flash("No file selected.")
        return redirect(url_for("index"))

    if not allowed_file(file.filename):
        flash("Please upload a .csv file exported from Wireshark.")
        return redirect(url_for("index"))

    try:
        # Validate it actually parses as a CSV before committing to it
        preview = pd.read_csv(file)
        if preview.empty:
            flash("That CSV has no rows.")
            return redirect(url_for("index"))
    except Exception as exc:
        flash(f"Could not read that file as CSV: {exc}")
        return redirect(url_for("index"))

    filename = secure_filename(file.filename)
    file.stream.seek(0)

    tmp_path = CSV_PATH + ".tmp"
    try:
        file.save(tmp_path)
    except PermissionError as exc:
        flash(
            f"Permission denied writing temp file at {tmp_path}. "
            f"OS error: {exc}. This is almost always a folder-permission or "
            f"Windows 'Controlled Folder Access' block on {os.path.dirname(CSV_PATH)}."
        )
        return redirect(url_for("index"))

    try:
        if os.path.exists(CSV_PATH):
            # Wireshark exports (and some editors) leave files marked
            # read-only on Windows, which blocks os.replace().
            os.chmod(CSV_PATH, stat.S_IWRITE)
        os.replace(tmp_path, CSV_PATH)
    except PermissionError as exc:
        flash(
            f"Saved temp file OK, but permission denied replacing {CSV_PATH}. "
            f"OS error: {exc}. Close any program that has network_data.csv open "
            f"(Excel, Wireshark, editor) and make sure it isn't read-only."
        )
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        return redirect(url_for("index"))
    except Exception as exc:
        flash(f"Could not finalize uploaded file: {exc}")
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        return redirect(url_for("index"))

    flash(f"Loaded {filename} — {len(preview)} packets.")
    return redirect(url_for("index"))


@app.route("/")
def index():
    df = load_data()
    summary = build_summary(df)
    return render_template(
        "index.html",
        summary=summary,
        has_data=not df.empty,
        csv_name=os.path.basename(CSV_PATH),
    )


@app.route("/api/packets")
def api_packets():
    """Return packet rows as JSON, with optional search + pagination."""
    df = load_data()

    search = request.args.get("search", "").strip().lower()
    protocol = request.args.get("protocol", "").strip()
    page = max(int(request.args.get("page", 1)), 1)
    per_page = min(max(int(request.args.get("per_page", 25)), 1), 200)

    if protocol:
        df = df[df["Protocol"] == protocol]

    if search:
        mask = (
            df["Source"].astype(str).str.lower().str.contains(search)
            | df["Destination"].astype(str).str.lower().str.contains(search)
            | df["Info"].astype(str).str.lower().str.contains(search)
            | df["Protocol"].astype(str).str.lower().str.contains(search)
        )
        df = df[mask]

    total = len(df)
    start = (page - 1) * per_page
    end = start + per_page
    page_df = df.iloc[start:end]

    return jsonify(
        {
            "total": total,
            "page": page,
            "per_page": per_page,
            "rows": page_df.to_dict(orient="records"),
        }
    )


@app.route("/api/summary")
def api_summary():
    """Return dashboard summary stats as JSON (used for chart refresh)."""
    df = load_data()
    return jsonify(build_summary(df))


if __name__ == "__main__":
    app.run(debug=True)