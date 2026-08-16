# VULNSCAN v4.0 - Automated Web Security Scanner
# Passive reconnaissance only - no active exploitation

from flask import Flask, request, jsonify, render_template, Response, send_file
from scanner import run_scan
from report import generate_report, generate_html_report
from history import save_scan, load_history, clear_history, HISTORY_FILE
import threading
import uuid
import json
import os

app = Flask(__name__)

# In-memory scan results storage
scan_results = {}
scan_status = {}

# Scheduled scans storage
SCHEDULED_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scheduled.json')


def run_scan_sync(scan_id, url):
    """Run a scan synchronously (for use in threads)"""
    try:
        result = run_scan(url)
        result["scan_id"] = scan_id
        scan_results[scan_id] = result
        scan_status[scan_id] = "complete"
        # Save to history
        stats = result.get("stats", {})
        from report import calculate_risk_score
        risk_score = calculate_risk_score(result.get("findings", []))
        save_scan(
            scan_id=scan_id,
            target_url=url,
            findings_count=result.get("total_findings", 0),
            risk_score=risk_score,
            critical=stats.get("critical", 0),
            high=stats.get("high", 0)
        )
    except Exception as e:
        scan_results[scan_id] = {"error": str(e), "scan_id": scan_id}
        scan_status[scan_id] = "error"


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

    thread = threading.Thread(target=run_scan_sync, args=(scan_id, url))
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


@app.route("/report/<scan_id>/pdf")
def download_pdf(scan_id):
    """Generate PDF using weasyprint and send as download"""
    if scan_id not in scan_results:
        return "Scan not found", 404
    result = scan_results[scan_id]
    if "error" in result and "findings" not in result:
        return f"<h1>Scan Error</h1><p>{result['error']}</p>", 500
    html = generate_report(result, target_url=result.get("target"))
    try:
        from weasyprint import HTML
        import io
        pdf_bytes = HTML(string=html).write_pdf()
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'vulnscan_report_{scan_id[:8]}.pdf'
        )
    except ImportError:
        return Response(html, mimetype='text/html')


# ===================== SCAN HISTORY =====================

@app.route('/history')
def scan_history():
    return jsonify(load_history())


@app.route('/history/clear', methods=['POST'])
def clear_scan_history():
    clear_history()
    return jsonify({'ok': True, 'message': 'History cleared'})


# ===================== BULK SCAN =====================

@app.route('/scan/bulk', methods=['POST'])
def bulk_scan():
    """Scan multiple URLs (max 10)"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON body'}), 400

    urls = data.get('urls', [])[:10]
    if not urls:
        return jsonify({'error': 'No URLs provided'}), 400

    scan_ids = []
    for url in urls:
        url = url.strip()
        if not url:
            continue
        scan_id = str(uuid.uuid4())
        scan_status[scan_id] = "queued"
        scan_results[scan_id] = {'status': 'queued', 'target_url': url}
        scan_ids.append({'url': url, 'scan_id': scan_id})

        scan_status[scan_id] = "running"
        thread = threading.Thread(target=run_scan_sync, args=(scan_id, url))
        thread.daemon = True
        thread.start()

    return jsonify({'ok': True, 'total': len(scan_ids), 'scans': scan_ids})


# ===================== API DOCUMENTATION =====================

@app.route('/api')
def api_docs():
    return jsonify({
        'name': 'VULNSCAN',
        'version': '4.0',
        'description': 'Automated Web Security Scanner - Passive Recon',
        'modules': 28,
        'endpoints': {
            'POST /scan': 'Start single scan - body: {"url": "https://example.com"}',
            'GET /scan/<id>/status': 'Get scan status (running/complete/error)',
            'GET /scan/<id>/details': 'Get full scan results',
            'GET /report/<id>': 'Get HTML security report',
            'GET /report/<id>/json': 'Get JSON report data',
            'GET /report/<id>/pdf': 'Download PDF report',
            'POST /scan/bulk': 'Scan multiple URLs - body: {"urls": ["url1", "url2", ...]}',
            'GET /history': 'Get scan history (last 50)',
            'POST /history/clear': 'Clear scan history',
            'POST /schedule': 'Add scheduled scan - body: {"url": "...", "interval_hours": 24}',
            'GET /schedule': 'List scheduled scans',
            'DELETE /schedule/<id>': 'Delete a scheduled scan',
            'GET /api': 'This documentation'
        },
        'example_curl': 'curl -X POST http://host/scan -H "Content-Type: application/json" -d \'{"url":"https://example.com"}\'',
        'features': [
            'Security Headers Analysis',
            'SSL/TLS Certificate Check',
            'Technology Stack Detection',
            'CVE Database Cross-reference',
            'Exposed Files/Paths (166 paths)',
            'DNS Records',
            'Port Scanning (21 ports)',
            'Email Harvesting',
            'Subdomain Enumeration',
            'Certificate Transparency Logs',
            'Domain Reputation Check',
            'WHOIS Intelligence',
            'IP Geolocation',
            'Content Analysis',
            'Performance Metrics',
            'Email Security (SPF/DMARC)',
            'HTTP Methods Testing',
            'Social Presence Check',
            'Wayback Machine Archive',
            'CORS Policy Analysis',
            'Cookie Security',
            'JavaScript Analysis',
            'Form Security Analysis',
            'Robots.txt Analysis',
            'Server Version Disclosure',
            'Social Media Links',
            'External Resources'
            'Secret Scanning (24 patterns)',
        ]
    })


# ===================== SCHEDULED SCANS =====================

def load_schedules():
    try:
        with open(SCHEDULED_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_schedules(schedules):
    with open(SCHEDULED_FILE, 'w') as f:
        json.dump(schedules, f, indent=2)


@app.route('/schedule', methods=['GET', 'POST'])
def handle_schedule():
    if request.method == 'GET':
        return jsonify(load_schedules())

    data = request.get_json()
    if not data or not data.get('url'):
        return jsonify({'error': 'Missing url'}), 400

    url = data['url'].strip()
    interval_hours = data.get('interval_hours', 24)

    schedules = load_schedules()
    schedule_id = str(uuid.uuid4())[:8]
    schedules.append({
        'id': schedule_id,
        'url': url,
        'interval_hours': interval_hours,
        'active': True,
        'created': __import__('datetime').datetime.now().isoformat(),
        'last_run': None,
        'run_count': 0
    })
    save_schedules(schedules)

    return jsonify({
        'ok': True,
        'id': schedule_id,
        'message': f'Scheduled scan of {url} every {interval_hours}h'
    })


@app.route('/schedule/<schedule_id>', methods=['DELETE'])
def delete_schedule(schedule_id):
    schedules = load_schedules()
    schedules = [s for s in schedules if s.get('id') != schedule_id]
    save_schedules(schedules)
    return jsonify({'ok': True, 'message': f'Schedule {schedule_id} deleted'})


if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")
    print("\n" + "=" * 50)
    print("  VULNSCAN v4.0 - Automated Web Security Scanner")
    print("  27 Check Modules | CVE DB | CT Logs | Bulk Scan")
    print("  http://localhost:5000")
    print("=" * 50 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
