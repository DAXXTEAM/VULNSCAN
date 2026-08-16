# VULNSCAN - Professional Security Report Generator
# Generates 6-page HTML/PDF security audit reports

from datetime import datetime
import hashlib
import html as html_module


def get_severity_color(severity):
    colors = {
        "critical": "#ff0040",
        "high": "#ff6b35",
        "medium": "#ffaa00",
        "low": "#00ccff",
        "info": "#888888"
    }
    return colors.get(severity.lower(), "#888888")


def get_severity_bg(severity):
    colors = {
        "critical": "rgba(255,0,64,0.15)",
        "high": "rgba(255,107,53,0.15)",
        "medium": "rgba(255,170,0,0.15)",
        "low": "rgba(0,204,255,0.15)",
        "info": "rgba(136,136,136,0.1)"
    }
    return colors.get(severity.lower(), "rgba(136,136,136,0.1)")


def calculate_risk_score(findings):
    scored = [f for f in findings if f.get("cvss_score", 0) > 0]
    if not scored:
        return 0.0
    weights = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    total_weight = 0
    weighted_sum = 0
    for f in scored:
        w = weights.get(f["severity"], 1)
        weighted_sum += f["cvss_score"] * w
        total_weight += w
    if total_weight == 0:
        return 0.0
    raw = weighted_sum / total_weight
    return round(min(raw, 10.0), 1)


def generate_summary(stats, risk_level, target, risk_score):
    total_issues = stats["critical"] + stats["high"] + stats["medium"] + stats["low"]
    if stats["critical"] > 0:
        urgency = "immediate attention is required"
    elif stats["high"] > 0:
        urgency = "prompt remediation is recommended"
    elif stats["medium"] > 0:
        urgency = "moderate improvements are suggested"
    else:
        urgency = "the target demonstrates reasonable security posture"

    summary = (
        f"A comprehensive passive security assessment was conducted against {target}. "
        f"The assessment identified a total of {total_issues} actionable finding(s) across "
        f"{stats['critical']} critical, {stats['high']} high, {stats['medium']} medium, and "
        f"{stats['low']} low severity categories. With an overall risk score of {risk_score}/10.0 "
        f"({risk_level}), {urgency}. This report provides detailed remediation guidance for each "
        f"identified vulnerability to support the organization's security improvement efforts."
    )
    return summary


def get_effort(cvss):
    if cvss >= 8.0:
        return "Immediate"
    elif cvss >= 6.0:
        return "Low"
    elif cvss >= 4.0:
        return "Medium"
    else:
        return "Low"


def get_priority(severity):
    mapping = {"critical": "P1 - Critical", "high": "P2 - High", "medium": "P3 - Medium", "low": "P4 - Low"}
    return mapping.get(severity, "P5 - Info")


def escape(text):
    return html_module.escape(str(text))


def generate_report(scan_results, target_url=None):
    """Generate a professional 6-page HTML security audit report.
    
    Args:
        scan_results: Dict from run_scan() with findings, stats, etc.
        target_url: Optional override for target URL (uses scan_results['target'] if not provided)
    
    Returns:
        Complete HTML string suitable for browser rendering and PDF printing.
    """
    target = target_url or scan_results.get("target", "Unknown")
    scan_date = scan_results.get("scan_date", datetime.utcnow().isoformat() + "Z")
    stats = scan_results.get("stats", {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
    findings = scan_results.get("findings", [])
    duration = scan_results.get("duration_seconds", 0)

    # Filter out info-only findings for the report body
    actionable_findings = [f for f in findings if f["severity"] != "info"]
    actionable_findings.sort(key=lambda x: -x.get("cvss_score", 0))

    risk_score = calculate_risk_score(findings)

    # Determine risk level
    if risk_score >= 9.0:
        risk_level = "CRITICAL"
        risk_color = "#ff0040"
    elif risk_score >= 7.0:
        risk_level = "HIGH"
        risk_color = "#ff6b35"
    elif risk_score >= 4.0:
        risk_level = "MEDIUM"
        risk_color = "#ffaa00"
    elif risk_score > 0:
        risk_level = "LOW"
        risk_color = "#00ccff"
    else:
        risk_level = "INFORMATIONAL"
        risk_color = "#888888"

    summary_text = generate_summary(stats, risk_level, target, risk_score)

    # Generate report ID
    report_id = "VS-" + hashlib.md5(f"{target}{scan_date}".encode()).hexdigest()[:12].upper()
    date_str = scan_date[:10] if len(scan_date) >= 10 else datetime.utcnow().strftime("%Y-%m-%d")

    # === PAGE 3-4: DETAILED FINDINGS ===
    findings_html = ""
    for i, f in enumerate(actionable_findings, 1):
        sev = f["severity"]
        color = get_severity_color(sev)
        bg = get_severity_bg(sev)
        cvss = f.get("cvss_score", 0)

        evidence = f.get("description", "N/A")
        business_impact = ""
        if cvss >= 8.0:
            business_impact = "Critical business risk. May lead to data breach, service disruption, or unauthorized system access."
        elif cvss >= 6.0:
            business_impact = "High business risk. Could enable targeted attacks against users or expose sensitive configuration."
        elif cvss >= 4.0:
            business_impact = "Moderate business risk. May provide attack vectors for information disclosure or session attacks."
        else:
            business_impact = "Low business risk. Provides information that could assist reconnaissance efforts."

        # Secret scanning section for PDF
        secret_section = ""
        if f.get('category') == 'Secret Scanning' and f.get('value_masked'):
            secret_section = f"""
            <div class="finding-section" style="background:rgba(255,0,64,0.05);border:1px solid rgba(255,0,64,0.2);border-radius:6px;padding:12px;margin-top:8px;">
                <div class="finding-label" style="color:#ff0040;">🔑 EXPOSED CREDENTIAL (MASKED)</div>
                <div class="finding-value mono" style="color:#ff0040;font-size:14px;">{escape(f.get('value_masked', 'N/A'))}</div>
                <div class="finding-value" style="font-size:11px;color:#888;margin-top:6px;">⚠️ Full value available in web dashboard. Rotate this key immediately.</div>
            </div>"""

        findings_html += f"""
        <div class="finding-card" style="border-left: 4px solid {color}; background: {bg};">
            <div class="finding-header">
                <span class="finding-num" style="background:{color}; color:#fff;">{i}</span>
                <h3 class="finding-title">{escape(f.get('title', 'Untitled'))}</h3>
                <span class="cvss-badge" style="background:{color}; color:#fff;">CVSS {cvss}</span>
            </div>
            <div class="finding-section">
                <div class="finding-label">Affected URL</div>
                <div class="finding-value mono">{escape(f.get('affected_url', target))}</div>
            </div>
            <div class="finding-section">
                <div class="finding-label">Description</div>
                <div class="finding-value">{escape(f.get('description', 'N/A'))}</div>
            </div>
            <div class="finding-section">
                <div class="finding-label">Evidence</div>
                <div class="finding-value evidence-box">{escape(evidence)}</div>
            </div>{secret_section}
            <div class="finding-section">
                <div class="finding-label">Business Impact</div>
                <div class="finding-value">{business_impact}</div>
            </div>
            <div class="remediation-box">
                <span class="remediation-icon">&#10003;</span>
                <div>
                    <strong>Remediation</strong><br>
                    {escape(f.get('recommendation', 'N/A'))}
                </div>
            </div>
        </div>
        """

    # === PAGE 5: REMEDIATION ROADMAP TABLE ===
    roadmap_rows = ""
    for i, f in enumerate(actionable_findings, 1):
        sev = f["severity"]
        color = get_severity_color(sev)
        cvss = f.get("cvss_score", 0)
        effort = get_effort(cvss)
        priority = get_priority(sev)
        roadmap_rows += f"""
        <tr>
            <td style="text-align:center; font-weight:bold;">{i}</td>
            <td>{escape(f.get('title', 'Untitled')[:60])}</td>
            <td><span style="color:{color}; font-weight:bold;">{priority}</span></td>
            <td style="text-align:center;"><span class="table-cvss" style="background:{color};">{cvss}</span></td>
            <td style="text-align:center;">{effort}</td>
            <td>{escape(f.get('recommendation', 'N/A')[:80])}</td>
        </tr>
        """

    # Critical/High/Medium/Low counts for timeline
    critical_items = [f for f in actionable_findings if f["severity"] == "critical"]
    high_items = [f for f in actionable_findings if f["severity"] == "high"]
    medium_items = [f for f in actionable_findings if f["severity"] == "medium"]
    low_items = [f for f in actionable_findings if f["severity"] == "low"]

    # Build HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report - {escape(target)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            color: #333;
            line-height: 1.6;
            font-size: 14px;
        }}

        /* Page break controls for PDF */
        @media print {{
            .page {{ page-break-after: always; }}
            .page:last-child {{ page-break-after: avoid; }}
            .no-break {{ page-break-inside: avoid; }}
            body {{ font-size: 12px; }}
            .page-number {{ position: fixed; bottom: 20px; right: 40px; font-size: 10px; color: #666; }}
        }}

        .page {{
            min-height: 100vh;
            padding: 40px 50px;
            position: relative;
        }}

        .page-footer {{
            position: absolute;
            bottom: 20px;
            right: 50px;
            font-size: 11px;
            color: #666;
        }}

        /* === PAGE 1: COVER === */
        .cover-page {{
            background: #0a0a1a;
            color: #fff;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
        }}

        .confidential-badge {{
            background: #ff0040;
            color: #fff;
            padding: 8px 24px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 13px;
            letter-spacing: 2px;
            margin-bottom: 50px;
        }}

        .cover-title {{
            font-size: 42px;
            font-weight: 800;
            letter-spacing: 3px;
            margin-bottom: 12px;
            color: #fff;
        }}

        .cover-subtitle {{
            font-size: 18px;
            color: #aaa;
            margin-bottom: 40px;
            font-weight: 300;
        }}

        .cover-target-box {{
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.2);
            border-radius: 8px;
            padding: 16px 40px;
            margin-bottom: 40px;
        }}

        .cover-target-label {{
            font-size: 11px;
            color: #888;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-bottom: 6px;
        }}

        .cover-target-url {{
            font-size: 22px;
            font-family: 'Courier New', monospace;
            color: #00ff88;
        }}

        .cover-meta {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 12px 40px;
            text-align: left;
            margin-top: 30px;
            margin-bottom: 40px;
            font-size: 13px;
        }}

        .cover-meta-item {{
            display: flex;
            justify-content: space-between;
            gap: 20px;
        }}

        .cover-meta-label {{
            color: #888;
        }}

        .cover-meta-value {{
            color: #fff;
            font-weight: 600;
        }}

        .cover-severity-badges {{
            display: flex;
            gap: 15px;
            margin-top: 30px;
        }}

        .cover-sev-badge {{
            padding: 10px 18px;
            border-radius: 6px;
            font-weight: bold;
            font-size: 14px;
            text-align: center;
            min-width: 70px;
        }}

        .cover-sev-badge .count {{
            font-size: 24px;
            display: block;
        }}

        .cover-sev-badge .label {{
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
            opacity: 0.9;
        }}

        /* === PAGE 2: EXECUTIVE SUMMARY === */
        .summary-page {{
            background: #fafbfc;
        }}

        .page-title {{
            font-size: 28px;
            font-weight: 700;
            color: #1a1a2e;
            margin-bottom: 30px;
            padding-bottom: 12px;
            border-bottom: 3px solid #1a1a2e;
        }}

        .risk-score-circle {{
            width: 140px;
            height: 140px;
            border-radius: 50%;
            border: 6px solid {risk_color};
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
        }}

        .risk-score-value {{
            font-size: 48px;
            font-weight: 800;
            color: {risk_color};
        }}

        .risk-score-label {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 2px;
            color: #666;
        }}

        .risk-level-text {{
            text-align: center;
            font-size: 16px;
            margin-bottom: 25px;
        }}

        .risk-level-text strong {{
            color: {risk_color};
        }}

        .summary-paragraph {{
            background: #fff;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 25px;
            line-height: 1.8;
            color: #444;
        }}

        .count-boxes {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            margin-bottom: 30px;
        }}

        .count-box {{
            text-align: center;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #e0e0e0;
            background: #fff;
        }}

        .count-box .num {{
            font-size: 32px;
            font-weight: 800;
        }}

        .count-box .lbl {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #666;
            margin-top: 4px;
        }}

        .scope-section {{
            background: #fff;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 20px;
        }}

        .scope-section h3 {{
            font-size: 16px;
            color: #1a1a2e;
            margin-bottom: 15px;
        }}

        .scope-grid {{
            display: grid;
            grid-template-columns: 160px 1fr;
            gap: 8px 16px;
            font-size: 13px;
        }}

        .scope-label {{
            font-weight: 600;
            color: #555;
        }}

        .scope-value {{
            color: #333;
        }}

        /* === PAGE 3-4: FINDINGS === */
        .findings-page {{
            background: #fafbfc;
        }}

        .finding-card {{
            background: #fff;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 16px;
        }}

        .finding-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 14px;
        }}

        .finding-num {{
            width: 28px;
            height: 28px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
            font-weight: bold;
            flex-shrink: 0;
        }}

        .finding-title {{
            flex: 1;
            font-size: 15px;
            font-weight: 600;
            color: #1a1a2e;
        }}

        .cvss-badge {{
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            flex-shrink: 0;
        }}

        .finding-section {{
            margin-bottom: 12px;
        }}

        .finding-label {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #888;
            font-weight: 600;
            margin-bottom: 4px;
        }}

        .finding-value {{
            font-size: 13px;
            color: #444;
            line-height: 1.6;
        }}

        .finding-value.mono {{
            font-family: 'Courier New', monospace;
            background: #f5f5f5;
            padding: 6px 10px;
            border-radius: 4px;
            font-size: 12px;
        }}

        .evidence-box {{
            background: #f8f8f8;
            border: 1px solid #eee;
            border-radius: 4px;
            padding: 8px 12px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            white-space: pre-wrap;
            word-break: break-all;
        }}

        .remediation-box {{
            background: #f0fdf4;
            border: 1px solid #86efac;
            border-radius: 6px;
            padding: 12px 16px;
            display: flex;
            gap: 10px;
            align-items: flex-start;
            margin-top: 12px;
        }}

        .remediation-icon {{
            color: #16a34a;
            font-size: 18px;
            font-weight: bold;
            flex-shrink: 0;
            margin-top: 2px;
        }}

        .remediation-box div {{
            font-size: 13px;
            color: #333;
        }}

        /* === PAGE 5: ROADMAP === */
        .roadmap-page {{
            background: #fafbfc;
        }}

        .roadmap-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
            margin-bottom: 30px;
        }}

        .roadmap-table th {{
            background: #1a1a2e;
            color: #fff;
            padding: 10px 12px;
            text-align: left;
            font-weight: 600;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .roadmap-table td {{
            padding: 10px 12px;
            border-bottom: 1px solid #e0e0e0;
            vertical-align: top;
        }}

        .roadmap-table tr:nth-child(even) {{
            background: #f8f9fa;
        }}

        .table-cvss {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            color: #fff;
            font-weight: bold;
            font-size: 11px;
        }}

        .timeline-section {{
            background: #fff;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 20px;
        }}

        .timeline-section h3 {{
            font-size: 16px;
            color: #1a1a2e;
            margin-bottom: 15px;
        }}

        .timeline-item {{
            display: flex;
            gap: 15px;
            align-items: flex-start;
            padding: 12px 0;
            border-bottom: 1px solid #f0f0f0;
        }}

        .timeline-item:last-child {{
            border-bottom: none;
        }}

        .timeline-badge {{
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            white-space: nowrap;
            color: #fff;
            min-width: 100px;
            text-align: center;
        }}

        .timeline-text {{
            font-size: 13px;
            color: #444;
        }}

        /* === PAGE 6: DISCLAIMER === */
        .disclaimer-page {{
            background: #fafbfc;
        }}

        .disclaimer-box {{
            background: #fff8f0;
            border: 1px solid #fed7aa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 25px;
        }}

        .disclaimer-box h3 {{
            color: #c2410c;
            margin-bottom: 10px;
            font-size: 16px;
        }}

        .disclaimer-box p {{
            font-size: 13px;
            color: #555;
            line-height: 1.7;
        }}

        .standards-section {{
            background: #fff;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 25px;
        }}

        .standards-section h3 {{
            font-size: 16px;
            color: #1a1a2e;
            margin-bottom: 12px;
        }}

        .standards-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 8px;
        }}

        .standard-item {{
            font-size: 13px;
            padding: 6px 10px;
            background: #f8f9fa;
            border-radius: 4px;
            color: #444;
        }}

        .auditor-box {{
            background: #f0f9ff;
            border: 1px solid #bae6fd;
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 25px;
        }}

        .auditor-box h3 {{
            color: #0369a1;
            margin-bottom: 15px;
            font-size: 16px;
        }}

        .auditor-grid {{
            display: grid;
            grid-template-columns: 120px 1fr;
            gap: 8px 16px;
            font-size: 13px;
        }}

        .auditor-label {{
            font-weight: 600;
            color: #555;
        }}

        .auditor-value {{
            color: #333;
        }}

        .report-footer {{
            text-align: center;
            padding-top: 20px;
            border-top: 1px solid #e0e0e0;
            margin-top: 20px;
        }}

        .report-footer p {{
            font-size: 12px;
            color: #888;
            margin-bottom: 4px;
        }}

        /* Overflow & word-wrap fixes */
        * {{ box-sizing: border-box; }}
        body {{ overflow-x: hidden; }}
        .finding-card {{ page-break-inside: avoid; overflow: hidden; word-wrap: break-word; }}
        pre, code {{ white-space: pre-wrap; word-break: break-all; overflow-wrap: break-word; }}
        table {{ width: 100%; table-layout: fixed; }}
        td, th {{ word-wrap: break-word; overflow-wrap: break-word; }}
        .url {{ word-break: break-all; font-size: 12px; }}
        p, li, div {{ overflow-wrap: break-word; word-break: break-word; }}
    </style>
</head>
<body>

    <!-- PAGE 1: COVER -->
    <div class="page cover-page">
        <div class="confidential-badge">&#9888; CONFIDENTIAL</div>
        <h1 class="cover-title">SECURITY AUDIT REPORT</h1>
        <p class="cover-subtitle">Passive Reconnaissance Assessment</p>

        <div class="cover-target-box">
            <div class="cover-target-label">Target Domain</div>
            <div class="cover-target-url">{escape(target)}</div>
        </div>

        <div class="cover-meta">
            <div class="cover-meta-item">
                <span class="cover-meta-label">Assessment Date:</span>
                <span class="cover-meta-value">{date_str}</span>
            </div>
            <div class="cover-meta-item">
                <span class="cover-meta-label">Report Version:</span>
                <span class="cover-meta-value">1.0</span>
            </div>
            <div class="cover-meta-item">
                <span class="cover-meta-label">Classification:</span>
                <span class="cover-meta-value">Confidential</span>
            </div>
            <div class="cover-meta-item">
                <span class="cover-meta-label">Prepared by:</span>
                <span class="cover-meta-value">Arpit Singh</span>
            </div>
        </div>

        <div class="cover-severity-badges">
            <div class="cover-sev-badge" style="background:rgba(255,0,64,0.2); color:#ff0040;">
                <span class="count">{stats['critical']}</span>
                <span class="label">Critical</span>
            </div>
            <div class="cover-sev-badge" style="background:rgba(255,107,53,0.2); color:#ff6b35;">
                <span class="count">{stats['high']}</span>
                <span class="label">High</span>
            </div>
            <div class="cover-sev-badge" style="background:rgba(255,170,0,0.2); color:#ffaa00;">
                <span class="count">{stats['medium']}</span>
                <span class="label">Medium</span>
            </div>
            <div class="cover-sev-badge" style="background:rgba(0,204,255,0.2); color:#00ccff;">
                <span class="count">{stats['low']}</span>
                <span class="label">Low</span>
            </div>
        </div>

        <div class="page-footer" style="color:#555;">Page 1 of 6</div>
    </div>

    <!-- PAGE 2: EXECUTIVE SUMMARY -->
    <div class="page summary-page">
        <h2 class="page-title">Executive Summary</h2>

        <div class="risk-score-circle">
            <span class="risk-score-value">{risk_score}</span>
            <span class="risk-score-label">Risk Score</span>
        </div>

        <div class="risk-level-text">
            Overall Risk Level: <strong>{risk_level}</strong>
        </div>

        <div class="summary-paragraph">{summary_text}</div>

        <div class="count-boxes">
            <div class="count-box">
                <div class="num" style="color:#ff0040;">{stats['critical']}</div>
                <div class="lbl">Critical</div>
            </div>
            <div class="count-box">
                <div class="num" style="color:#ff6b35;">{stats['high']}</div>
                <div class="lbl">High</div>
            </div>
            <div class="count-box">
                <div class="num" style="color:#ffaa00;">{stats['medium']}</div>
                <div class="lbl">Medium</div>
            </div>
            <div class="count-box">
                <div class="num" style="color:#00ccff;">{stats['low']}</div>
                <div class="lbl">Low</div>
            </div>
        </div>

        <div class="scope-section">
            <h3>Scope &amp; Methodology</h3>
            <div class="scope-grid">
                <span class="scope-label">Target URL:</span>
                <span class="scope-value">{escape(target)}</span>
                <span class="scope-label">Methodology:</span>
                <span class="scope-value">OWASP Testing Guide v4.2, PTES</span>
                <span class="scope-label">Techniques Used:</span>
                <span class="scope-value">HTTP Header Analysis, Directory Enumeration, DNS Reconnaissance, Technology Fingerprinting, SSL/TLS Analysis</span>
                <span class="scope-label">Tools:</span>
                <span class="scope-value">cURL, DNS lookup utilities, SSL analyzers, browser developer tools</span>
                <span class="scope-label">Limitations:</span>
                <span class="scope-value">Passive reconnaissance only &mdash; no active exploitation or intrusive testing was performed</span>
            </div>
        </div>

        <div class="page-footer">Page 2 of 6</div>
    </div>

    <!-- PAGE 3-4: DETAILED FINDINGS -->
    <div class="page findings-page">
        <h2 class="page-title">Detailed Findings</h2>
        {findings_html if findings_html else '<p style="color:#888; text-align:center; margin-top:40px;">No actionable findings identified.</p>'}
        <div class="page-footer">Page 3 of 6</div>
    </div>

    <!-- PAGE 5: REMEDIATION ROADMAP -->
    <div class="page roadmap-page">
        <h2 class="page-title">Remediation Roadmap</h2>

        {f'''<table class="roadmap-table">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Vulnerability</th>
                    <th>Priority</th>
                    <th>CVSS</th>
                    <th>Effort</th>
                    <th>Action Required</th>
                </tr>
            </thead>
            <tbody>
                {roadmap_rows}
            </tbody>
        </table>''' if roadmap_rows else '<p style="color:#888;">No remediation items.</p>'}

        <div class="timeline-section">
            <h3>Risk Reduction Timeline</h3>
            <div class="timeline-item">
                <span class="timeline-badge" style="background:#ff0040;">Within 24 Hours</span>
                <span class="timeline-text">
                    {f"Fix {len(critical_items)} critical finding(s): " + ", ".join(escape(f.get("title","")[:40]) for f in critical_items[:3]) if critical_items else "No critical items requiring immediate action."}
                </span>
            </div>
            <div class="timeline-item">
                <span class="timeline-badge" style="background:#ff6b35;">Within 1 Week</span>
                <span class="timeline-text">
                    {f"Fix {len(high_items)} high severity finding(s): " + ", ".join(escape(f.get("title","")[:40]) for f in high_items[:3]) if high_items else "No high severity items requiring urgent remediation."}
                </span>
            </div>
            <div class="timeline-item">
                <span class="timeline-badge" style="background:#ffaa00;">Within 1 Month</span>
                <span class="timeline-text">
                    {f"Fix {len(medium_items)} medium and {len(low_items)} low severity finding(s)" if (medium_items or low_items) else "No medium/low items in the remediation queue."}
                </span>
            </div>
        </div>

        <div class="page-footer">Page 5 of 6</div>
    </div>

    <!-- PAGE 6: DISCLAIMER & AUDITOR -->
    <div class="page disclaimer-page">
        <h2 class="page-title">Disclaimer &amp; Auditor Information</h2>

        <div class="disclaimer-box">
            <h3>&#9888; Legal Disclaimer</h3>
            <p>
                This security assessment report is provided for informational purposes only. The assessment
                was conducted using passive reconnaissance techniques only. No active exploitation, intrusive
                testing, or unauthorized access attempts were made. The findings represent the security posture
                observed at the time of assessment and may not reflect all vulnerabilities present. The assessor
                assumes no liability for any damage resulting from the use or misuse of information contained
                in this report. This report is confidential and intended solely for the authorized recipient(s).
                Unauthorized distribution is prohibited.
            </p>
        </div>

        <div class="standards-section">
            <h3>Assessment Standards</h3>
            <div class="standards-grid">
                <div class="standard-item"><strong>OWASP</strong> &mdash; Open Web Application Security Project Testing Guide v4.2</div>
                <div class="standard-item"><strong>PTES</strong> &mdash; Penetration Testing Execution Standard</div>
                <div class="standard-item"><strong>NIST</strong> &mdash; National Institute of Standards and Technology SP 800-115</div>
                <div class="standard-item"><strong>CVSS</strong> &mdash; Common Vulnerability Scoring System v3.1</div>
            </div>
        </div>

        <div class="auditor-box">
            <h3>&#128274; Auditor Information</h3>
            <div class="auditor-grid">
                <span class="auditor-label">Name:</span>
                <span class="auditor-value">Arpit Singh</span>
                <span class="auditor-label">Role:</span>
                <span class="auditor-value">Independent Security Researcher</span>
                <span class="auditor-label">Email:</span>
                <span class="auditor-value">mrdaxxteam@gmail.com</span>
                <span class="auditor-label">GitHub:</span>
                <span class="auditor-value">github.com/DAXXTEAM</span>
                <span class="auditor-label">Date:</span>
                <span class="auditor-value">{date_str}</span>
            </div>
        </div>

        <div class="report-footer">
            <p><strong>Report ID:</strong> {report_id}</p>
            <p>&copy; 2026 Arpit Singh. All rights reserved.</p>
        </div>

        <div class="page-footer">Page 6 of 6</div>
    </div>

</body>
</html>"""

    return html


# Backward compatibility: keep old function name working
def generate_html_report(scan_result):
    """Backward-compatible wrapper that calls the new generate_report function."""
    return generate_report(scan_result, target_url=scan_result.get("target"))
