# VULNSCAN - Automated Web Security Scanner
# Passive reconnaissance only - no active exploitation

from flask import Flask, request, jsonify, render_template, Response
from scanner import run_scan
from report import generate_report, generate_html_report
import threading
import uuid
import json

app = Flask(__name__)

# In-memory scan results storage
scan_results = {}
scan_status = {}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def start_scan():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' field"}), 400

    url = data["url"].strip()
    if not url:
        return jsonify({"error": "URL cannot be empty"}), 400

    scan_id = str(uuid.uuid4())
    scan_status[scan_id] = "running"

    def do_scan():
        try:
            result = run_scan(url)
            result["scan_id"] = scan_id
            scan_results[scan_id] = result
            scan_status[scan_id] = "complete"
        except Exception as e:
            scan_results[scan_id] = {"error": str(e), "scan_id": scan_id}
            scan_status[scan_id] = "error"

    thread = threading.Thread(target=do_scan)
    thread.start()
    thread.join(timeout=90)

    if scan_status[scan_id] == "running":
        return jsonify({"scan_id": scan_id, "status": "running"}), 202

    if scan_status[scan_id] == "error":
        return jsonify(scan_results.get(scan_id, {"error": "Unknown error"})), 500

    return jsonify(scan_results[scan_id])


@app.route("/scan/<scan_id>/status")
def scan_progress(scan_id):
    status = scan_status.get(scan_id, "not_found")
    if status == "not_found":
        return jsonify({"error": "Scan not found"}), 404
    if status == "complete":
        return jsonify({"status": "complete", "result": scan_results[scan_id]})
    return jsonify({"status": status})


@app.route("/scan/<scan_id>/details")
def scan_details(scan_id):
    if scan_id not in scan_results:
        return jsonify({"error": "Scan not found"}), 404
    result = scan_results[scan_id]
    if "error" in result and "findings" not in result:
        return jsonify({"error": result["error"]}), 500
    return jsonify(result)


@app.route("/report/<scan_id>")
def get_report(scan_id):
    """Generate and serve the professional 6-page HTML/PDF security report."""
    if scan_id not in scan_results:
        return "<h1>Report not found</h1>", 404
    result = scan_results[scan_id]
    if "error" in result and "findings" not in result:
        return f"<h1>Scan Error</h1><p>{result['error']}</p>", 500
    html = generate_report(result, target_url=result.get("target"))
    return Response(html, mimetype="text/html", headers={
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-cache"
    })


@app.route("/report/<scan_id>/json")
def get_report_json(scan_id):
    if scan_id not in scan_results:
        return jsonify({"error": "Report not found"}), 404
    return jsonify(scan_results[scan_id])


if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")
    print("\n" + "=" * 50)
    print("  VULNSCAN - Automated Web Security Scanner")
    print("  Comprehensive Edition - 15 Check Modules")
    print("  http://localhost:5000")
    print("=" * 50 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
