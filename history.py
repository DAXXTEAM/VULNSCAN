# VULNSCAN - Scan History Management
import json
import os
from datetime import datetime

HISTORY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scan_history.json')


def save_scan(scan_id, target_url, findings_count, risk_score, critical=0, high=0):
    history = load_history()
    history.append({
        'scan_id': scan_id,
        'url': target_url,
        'date': datetime.now().isoformat(),
        'findings': findings_count,
        'risk_score': risk_score,
        'critical': critical,
        'high': high
    })
    # Keep last 50
    history = history[-50:]
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)


def load_history():
    try:
        with open(HISTORY_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def clear_history():
    try:
        os.remove(HISTORY_FILE)
    except OSError:
        pass
