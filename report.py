# VULNSCAN - Report Generator
# Generates professional HTML security reports

from datetime import datetime


def get_severity_color(severity):
    colors = {
        "critical": "#ff0040",
        "high": "#ff4444",
        "medium": "#ffaa00",
        "low": "#00ccff",
        "info": "#888888"
    }
    return colors.get(severity, "#888888")


def generate_html_report(scan_result):
    target = scan_result["target"]
    scan_date = scan_result["scan_date"]
    risk_level = scan_result["risk_level"]
    max_cvss = scan_result["max_cvss"]
    stats = scan_result["stats"]
    findings = scan_result["findings"]
    duration = scan_result["duration_seconds"]

    findings_html = ""
    for i, f in enumerate(findings, 1):
        color = get_severity_color(f["severity"])
        findings_html += f"""
        <div class="finding-card">
            <div class="finding-header">
                <span class="finding-num">#{i}</span>
                <span class="severity-badge" style="background:{color}">{f['severity'].upper()}</span>
                <span class="cvss-badge">CVSS: {f['cvss_score']}</span>
            </div>
            <h3 class="finding-title">{f['title']}</h3>
            <div class="finding-meta">
                <span class="category-tag">{f.get('category', 'General')}</span>
                <span class="affected-url">{f['affected_url']}</span>
            </div>
            <p class="finding-desc">{f['description']}</p>
            <div class="recommendation">
                <strong>&#9888; Recommendation:</strong> {f['recommendation']}
            </div>
        </div>
        """

    risk_color = get_severity_color(risk_level.lower())

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VULNSCAN Report - {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0a0a1a;
            color: #e0e0e0;
            line-height: 1.6;
        }}
        .report-container {{
            max-width: 1000px;
            margin: 0 auto;
            padding: 40px 20px;
        }}
        .cover {{
            text-align: center;
            padding: 60px 20px;
            border: 1px solid #1a1a3a;
            border-radius: 12px;
            margin-bottom: 40px;
            background: linear-gradient(135deg, #0a0a1a 0%, #1a1a3a 100%);
        }}
        .cover h1 {{
            font-size: 42px;
            color: #00ff88;
            margin-bottom: 10px;
            letter-spacing: 4px;
        }}
        .cover .subtitle {{
            font-size: 18px;
            color: #888;
            margin-bottom: 30px;
        }}
        .cover .target-url {{
            font-size: 22px;
            color: #fff;
            background: #111;
            padding: 12px 24px;
            border-radius: 8px;
            display: inline-block;
            font-family: monospace;
            margin: 20px 0;
        }}
        .cover-meta {{
            margin-top: 30px;
            color: #666;
            font-size: 14px;
        }}
        .cover-meta span {{
            margin: 0 15px;
        }}
        .exec-summary {{
            background: #111;
            border: 1px solid #1a1a3a;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 40px;
        }}
        .exec-summary h2 {{
            color: #00ff88;
            margin-bottom: 20px;
            font-size: 24px;
        }}
        .risk-score {{
            text-align: center;
            padding: 20px;
            margin: 20px 0;
        }}
        .risk-score .score {{
            font-size: 64px;
            font-weight: bold;
            color: {risk_color};
        }}
        .risk-score .label {{
            font-size: 18px;
            color: #888;
            margin-top: 5px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 10px;
            margin: 20px 0;
        }}
        .stat-box {{
            text-align: center;
            padding: 15px 10px;
            border-radius: 8px;
            background: #0a0a1a;
        }}
        .stat-box .num {{
            font-size: 28px;
            font-weight: bold;
        }}
        .stat-box .lbl {{
            font-size: 12px;
            text-transform: uppercase;
            margin-top: 5px;
            color: #888;
        }}
        .findings-section {{
            margin-top: 40px;
        }}
        .findings-section h2 {{
            color: #00ff88;
            margin-bottom: 20px;
            font-size: 24px;
        }}
        .finding-card {{
            background: #111;
            border: 1px solid #1a1a3a;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 15px;
        }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 10px;
        }}
        .finding-num {{
            color: #555;
            font-size: 14px;
        }}
        .severity-badge {{
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            color: #fff;
            text-transform: uppercase;
        }}
        .cvss-badge {{
            background: #222;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            color: #aaa;
        }}
        .finding-title {{
            color: #fff;
            font-size: 16px;
            margin-bottom: 8px;
        }}
        .finding-meta {{
            margin-bottom: 10px;
            font-size: 12px;
        }}
        .category-tag {{
            background: #1a1a3a;
            padding: 2px 8px;
            border-radius: 3px;
            color: #00ff88;
            margin-right: 10px;
        }}
        .affected-url {{
            color: #666;
            font-family: monospace;
            font-size: 11px;
        }}
        .finding-desc {{
            color: #bbb;
            margin-bottom: 12px;
            font-size: 14px;
        }}
        .recommendation {{
            background: #0a0a1a;
            padding: 12px;
            border-radius: 6px;
            border-left: 3px solid #ffaa00;
            font-size: 13px;
            color: #ddd;
        }}
        .footer {{
            text-align: center;
            margin-top: 60px;
            padding: 20px;
            border-top: 1px solid #1a1a3a;
            color: #444;
            font-size: 12px;
        }}
        @media print {{
            body {{ background: #fff; color: #000; }}
            .report-container {{ max-width: 100%; }}
            .cover {{ border-color: #ccc; background: #f9f9f9; }}
            .cover h1 {{ color: #006644; }}
            .finding-card {{ border-color: #ddd; background: #f5f5f5; }}
            .exec-summary {{ background: #f5f5f5; border-color: #ddd; }}
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <div class="cover">
            <h1>VULNSCAN</h1>
            <p class="subtitle">Automated Web Security Assessment Report</p>
            <div class="target-url">{target}</div>
            <div class="cover-meta">
                <span>Date: {scan_date[:10]}</span>
                <span>Duration: {duration}s</span>
                <span>Auditor: VULNSCAN Automated Scanner</span>
            </div>
        </div>

        <div class="exec-summary">
            <h2>Executive Summary</h2>
            <div class="risk-score">
                <div class="score">{max_cvss}</div>
                <div class="label">Maximum CVSS Score &mdash; Risk Level: {risk_level}</div>
            </div>
            <div class="stats-grid">
                <div class="stat-box">
                    <div class="num" style="color:#ff0040">{stats['critical']}</div>
                    <div class="lbl">Critical</div>
                </div>
                <div class="stat-box">
                    <div class="num" style="color:#ff4444">{stats['high']}</div>
                    <div class="lbl">High</div>
                </div>
                <div class="stat-box">
                    <div class="num" style="color:#ffaa00">{stats['medium']}</div>
                    <div class="lbl">Medium</div>
                </div>
                <div class="stat-box">
                    <div class="num" style="color:#00ccff">{stats['low']}</div>
                    <div class="lbl">Low</div>
                </div>
                <div class="stat-box">
                    <div class="num" style="color:#888">{stats['info']}</div>
                    <div class="lbl">Info</div>
                </div>
            </div>
            <p style="text-align:center;color:#888;margin-top:15px;">
                Total findings: {scan_result['total_findings']} | Scan completed in {duration} seconds
            </p>
        </div>

        <div class="findings-section">
            <h2>Detailed Findings</h2>
            {findings_html}
        </div>

        <div class="footer">
            <p>Generated by VULNSCAN - Automated Web Security Scanner</p>
            <p>Report generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            <p style="margin-top:10px;">DISCLAIMER: This scan performs passive reconnaissance only. No active exploitation was performed.</p>
        </div>
    </div>
</body>
</html>"""

    return html
