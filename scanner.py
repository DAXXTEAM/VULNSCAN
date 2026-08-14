# VULNSCAN - Automated Web Security Scanner
# Passive reconnaissance only - no active exploitation

import requests
import ssl
import socket
import dns.resolver
import uuid
import time
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT = 8

EXPOSED_PATHS = [
    "/.env", "/phpinfo.php", "/admin", "/backup.sql",
    "/.git/config", "/wp-login.php", "/server-status",
    "/.htaccess", "/config.php", "/database.sql",
    "/wp-config.php.bak", "/.DS_Store", "/debug.log",
    "/api/docs", "/swagger.json", "/.well-known/security.txt"
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "high",
        "cvss": 6.1,
        "desc": "HTTP Strict Transport Security (HSTS) header is missing. This allows downgrade attacks and cookie hijacking.",
        "fix": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header."
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "cvss": 5.3,
        "desc": "Content Security Policy (CSP) header is missing. This increases the risk of XSS attacks.",
        "fix": "Implement a strict Content-Security-Policy header to prevent XSS and data injection attacks."
    },
    "X-Frame-Options": {
        "severity": "medium",
        "cvss": 4.3,
        "desc": "X-Frame-Options header is missing. The site may be vulnerable to clickjacking attacks.",
        "fix": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' header."
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "cvss": 3.1,
        "desc": "X-Content-Type-Options header is missing. Browsers may MIME-sniff responses.",
        "fix": "Add 'X-Content-Type-Options: nosniff' header."
    },
    "Referrer-Policy": {
        "severity": "low",
        "cvss": 3.1,
        "desc": "Referrer-Policy header is missing. Sensitive information may leak via Referer header.",
        "fix": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header."
    },
    "Permissions-Policy": {
        "severity": "low",
        "cvss": 2.6,
        "desc": "Permissions-Policy header is missing. Browser features are not restricted.",
        "fix": "Add Permissions-Policy header to restrict browser features like camera, microphone, geolocation."
    },
    "X-XSS-Protection": {
        "severity": "info",
        "cvss": 0.0,
        "desc": "X-XSS-Protection header is not set (deprecated but still recommended for older browsers).",
        "fix": "Add 'X-XSS-Protection: 1; mode=block' for legacy browser support."
    }
}


def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def get_domain(url):
    return urlparse(url).hostname


def check_security_headers(url):
    findings = []
    try:
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True, verify=False)
        headers = resp.headers

        for header_name, info in SECURITY_HEADERS.items():
            if header_name.lower() not in {k.lower(): k for k in headers}:
                findings.append({
                    "severity": info["severity"],
                    "cvss_score": info["cvss"],
                    "title": f"Missing Security Header: {header_name}",
                    "description": info["desc"],
                    "affected_url": url,
                    "recommendation": info["fix"],
                    "category": "Security Headers"
                })
            else:
                findings.append({
                    "severity": "info",
                    "cvss_score": 0.0,
                    "title": f"Security Header Present: {header_name}",
                    "description": f"{header_name} header is properly configured.",
                    "affected_url": url,
                    "recommendation": "No action needed.",
                    "category": "Security Headers"
                })
    except requests.exceptions.RequestException as e:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "HTTP Headers Check Failed",
            "description": f"Could not retrieve headers: {str(e)[:100]}",
            "affected_url": url,
            "recommendation": "Verify the target URL is accessible.",
            "category": "Security Headers"
        })
    return findings


def check_ssl_tls(url):
    findings = []
    domain = get_domain(url)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()

                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (not_after - datetime.utcnow()).days

                issuer = dict(x[0] for x in cert.get('issuer', []))
                subject = dict(x[0] for x in cert.get('subject', []))

                if days_left < 0:
                    findings.append({
                        "severity": "critical",
                        "cvss_score": 9.1,
                        "title": "SSL Certificate Expired",
                        "description": f"Certificate expired {abs(days_left)} days ago. Issued by: {issuer.get('organizationName', 'Unknown')}",
                        "affected_url": url,
                        "recommendation": "Renew the SSL certificate immediately.",
                        "category": "SSL/TLS"
                    })
                elif days_left < 30:
                    findings.append({
                        "severity": "high",
                        "cvss_score": 6.5,
                        "title": "SSL Certificate Expiring Soon",
                        "description": f"Certificate expires in {days_left} days (on {not_after.strftime('%Y-%m-%d')}). Issuer: {issuer.get('organizationName', 'Unknown')}",
                        "affected_url": url,
                        "recommendation": "Renew the SSL certificate before expiration.",
                        "category": "SSL/TLS"
                    })
                else:
                    findings.append({
                        "severity": "info",
                        "cvss_score": 0.0,
                        "title": "SSL Certificate Valid",
                        "description": f"Certificate valid for {days_left} days. Expires: {not_after.strftime('%Y-%m-%d')}. Protocol: {protocol}. Issuer: {issuer.get('organizationName', 'Unknown')}",
                        "affected_url": url,
                        "recommendation": "No action needed. Monitor expiration date.",
                        "category": "SSL/TLS"
                    })

                if protocol in ('TLSv1', 'TLSv1.1'):
                    findings.append({
                        "severity": "high",
                        "cvss_score": 7.4,
                        "title": "Deprecated TLS Version",
                        "description": f"Server supports deprecated protocol: {protocol}",
                        "affected_url": url,
                        "recommendation": "Disable TLS 1.0 and TLS 1.1. Use TLS 1.2 or higher.",
                        "category": "SSL/TLS"
                    })

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "severity": "critical",
            "cvss_score": 9.1,
            "title": "SSL Certificate Verification Failed",
            "description": f"Certificate verification error: {str(e)[:150]}",
            "affected_url": url,
            "recommendation": "Fix the SSL certificate chain. Ensure valid CA-signed certificate.",
            "category": "SSL/TLS"
        })
    except Exception as e:
        findings.append({
            "severity": "medium",
            "cvss_score": 4.0,
            "title": "SSL/TLS Check Error",
            "description": f"Could not complete SSL check: {str(e)[:100]}",
            "affected_url": url,
            "recommendation": "Verify SSL/TLS is properly configured on port 443.",
            "category": "SSL/TLS"
        })
    return findings


def check_technology_stack(url):
    findings = []
    try:
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True, verify=False)
        headers = resp.headers
        techs = []

        server = headers.get("Server", "")
        if server:
            techs.append(f"Server: {server}")

        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            techs.append(f"X-Powered-By: {powered_by}")

        asp_ver = headers.get("X-AspNet-Version", "")
        if asp_ver:
            techs.append(f"ASP.NET: {asp_ver}")

        via = headers.get("Via", "")
        if via:
            techs.append(f"Via: {via}")

        body = resp.text[:5000].lower()
        if "wp-content" in body or "wordpress" in body:
            techs.append("CMS: WordPress")
        if "drupal" in body:
            techs.append("CMS: Drupal")
        if "joomla" in body:
            techs.append("CMS: Joomla")
        if "react" in body or "reactdom" in body:
            techs.append("Frontend: React")
        if "angular" in body:
            techs.append("Frontend: Angular")
        if "vue" in body or "vuejs" in body:
            techs.append("Frontend: Vue.js")
        if "next" in body and "/_next/" in body:
            techs.append("Framework: Next.js")
        if "laravel" in body:
            techs.append("Framework: Laravel")

        if techs:
            findings.append({
                "severity": "info",
                "cvss_score": 0.0,
                "title": "Technology Stack Detected",
                "description": "Detected technologies: " + ", ".join(techs),
                "affected_url": url,
                "recommendation": "Consider hiding version information in production.",
                "category": "Technology Detection"
            })
        else:
            findings.append({
                "severity": "info",
                "cvss_score": 0.0,
                "title": "Technology Stack - Minimal Disclosure",
                "description": "No significant technology fingerprints detected in headers or HTML.",
                "affected_url": url,
                "recommendation": "Good practice - minimal technology disclosure.",
                "category": "Technology Detection"
            })
    except Exception as e:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "Technology Detection Failed",
            "description": f"Could not detect technologies: {str(e)[:100]}",
            "affected_url": url,
            "recommendation": "Verify the URL is accessible.",
            "category": "Technology Detection"
        })
    return findings


def check_exposed_files(url):
    findings = []

    def check_path(path):
        try:
            check_url = url + path
            resp = requests.get(check_url, timeout=TIMEOUT, allow_redirects=False, verify=False)
            if resp.status_code == 200:
                return {
                    "severity": "high" if path in ["/.env", "/backup.sql", "/database.sql", "/.git/config", "/wp-config.php.bak"] else "medium",
                    "cvss_score": 7.5 if path in ["/.env", "/backup.sql", "/database.sql", "/.git/config", "/wp-config.php.bak"] else 5.3,
                    "title": f"Exposed File/Path: {path}",
                    "description": f"The path {path} returned HTTP 200. This file/endpoint may expose sensitive information.",
                    "affected_url": check_url,
                    "recommendation": f"Restrict access to {path}. Add authentication or remove from production.",
                    "category": "Exposed Files"
                }
            elif resp.status_code == 403:
                return {
                    "severity": "info",
                    "cvss_score": 0.0,
                    "title": f"Path Forbidden: {path}",
                    "description": f"The path {path} returned HTTP 403 (Forbidden). File exists but access is restricted.",
                    "affected_url": check_url,
                    "recommendation": "Access is restricted. Verify this is intentional.",
                    "category": "Exposed Files"
                }
        except:
            pass
        return None

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(check_path, p): p for p in EXPOSED_PATHS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)

    if not findings:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "No Exposed Files Detected",
            "description": "Common sensitive file paths returned 404 or connection errors.",
            "affected_url": url,
            "recommendation": "Continue monitoring for accidental exposure.",
            "category": "Exposed Files"
        })
    return findings


def check_dns_info(url):
    findings = []
    domain = get_domain(url)
    try:
        records = {}
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass
            except Exception:
                pass

        desc_parts = []
        for rtype, values in records.items():
            desc_parts.append(f"{rtype}: {', '.join(values[:3])}")

        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "DNS Records",
            "description": "; ".join(desc_parts) if desc_parts else "No DNS records found.",
            "affected_url": url,
            "recommendation": "Review DNS records for any unnecessary exposure.",
            "category": "DNS"
        })

        if 'TXT' in records:
            for txt in records['TXT']:
                if 'v=spf1' in txt:
                    findings.append({
                        "severity": "info",
                        "cvss_score": 0.0,
                        "title": "SPF Record Found",
                        "description": f"SPF record: {txt[:200]}",
                        "affected_url": url,
                        "recommendation": "Verify SPF record is correctly configured.",
                        "category": "DNS"
                    })

    except Exception as e:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "DNS Lookup Error",
            "description": f"Could not resolve DNS: {str(e)[:100]}",
            "affected_url": url,
            "recommendation": "Verify the domain name is correct.",
            "category": "DNS"
        })
    return findings


def check_robots_txt(url):
    findings = []
    try:
        resp = requests.get(url + "/robots.txt", timeout=TIMEOUT, verify=False)
        if resp.status_code == 200 and len(resp.text.strip()) > 0:
            content = resp.text[:1000]
            disallowed = [line.split(":", 1)[1].strip() for line in content.split("\n")
                         if line.strip().lower().startswith("disallow:") and line.split(":", 1)[1].strip()]

            findings.append({
                "severity": "info",
                "cvss_score": 0.0,
                "title": "Robots.txt Found",
                "description": f"robots.txt exists with {len(disallowed)} disallowed paths. " +
                              (f"Paths: {', '.join(disallowed[:5])}" if disallowed else "No paths disallowed."),
                "affected_url": url + "/robots.txt",
                "recommendation": "Review robots.txt for unintentional disclosure of sensitive paths.",
                "category": "Robots.txt"
            })

            sensitive_keywords = ["/admin", "/backup", "/config", "/secret", "/private", "/internal", "/api"]
            exposed = [p for p in disallowed if any(k in p.lower() for k in sensitive_keywords)]
            if exposed:
                findings.append({
                    "severity": "low",
                    "cvss_score": 3.7,
                    "title": "Sensitive Paths in Robots.txt",
                    "description": f"robots.txt discloses potentially sensitive paths: {', '.join(exposed[:5])}",
                    "affected_url": url + "/robots.txt",
                    "recommendation": "Robots.txt should not be relied upon for security. Use proper access controls.",
                    "category": "Robots.txt"
                })
        else:
            findings.append({
                "severity": "info",
                "cvss_score": 0.0,
                "title": "No Robots.txt",
                "description": "robots.txt file not found or empty.",
                "affected_url": url + "/robots.txt",
                "recommendation": "Consider adding a robots.txt for crawler guidance.",
                "category": "Robots.txt"
            })
    except Exception as e:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "Robots.txt Check Failed",
            "description": f"Error: {str(e)[:100]}",
            "affected_url": url + "/robots.txt",
            "recommendation": "Verify URL accessibility.",
            "category": "Robots.txt"
        })
    return findings


def check_cookies(url):
    findings = []
    try:
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True, verify=False)
        cookies = resp.cookies

        if not cookies:
            set_cookie_headers = [v for k, v in resp.headers.items() if k.lower() == 'set-cookie']
            if not set_cookie_headers:
                findings.append({
                    "severity": "info",
                    "cvss_score": 0.0,
                    "title": "No Cookies Set",
                    "description": "No cookies were set in the response.",
                    "affected_url": url,
                    "recommendation": "No action needed.",
                    "category": "Cookies"
                })
                return findings

        for cookie in cookies:
            issues = []
            if not cookie.secure:
                issues.append("Secure flag missing")
            if not cookie.has_nonstandard_attr('HttpOnly') and 'httponly' not in str(cookie).lower():
                issues.append("HttpOnly flag missing")
            if not cookie.has_nonstandard_attr('SameSite') and 'samesite' not in str(cookie).lower():
                issues.append("SameSite flag missing")

            if issues:
                findings.append({
                    "severity": "medium",
                    "cvss_score": 4.7,
                    "title": f"Cookie Security Issues: {cookie.name}",
                    "description": f"Cookie '{cookie.name}' has security issues: {', '.join(issues)}",
                    "affected_url": url,
                    "recommendation": "Set Secure, HttpOnly, and SameSite=Strict flags on all cookies.",
                    "category": "Cookies"
                })
            else:
                findings.append({
                    "severity": "info",
                    "cvss_score": 0.0,
                    "title": f"Cookie Secure: {cookie.name}",
                    "description": f"Cookie '{cookie.name}' has proper security flags.",
                    "affected_url": url,
                    "recommendation": "No action needed.",
                    "category": "Cookies"
                })

    except Exception as e:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "Cookie Check Failed",
            "description": f"Error: {str(e)[:100]}",
            "affected_url": url,
            "recommendation": "Verify URL accessibility.",
            "category": "Cookies"
        })
    return findings


def check_cors(url):
    findings = []
    try:
        headers = {"Origin": "https://evil-attacker.com"}
        resp = requests.get(url, headers=headers, timeout=TIMEOUT, verify=False)

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*":
            findings.append({
                "severity": "medium",
                "cvss_score": 5.3,
                "title": "Wildcard CORS Policy",
                "description": "Access-Control-Allow-Origin is set to '*', allowing any domain to make requests.",
                "affected_url": url,
                "recommendation": "Restrict CORS to specific trusted origins instead of using wildcard.",
                "category": "CORS"
            })
        elif "evil-attacker.com" in acao:
            sev = "high" if acac.lower() == "true" else "medium"
            score = 8.1 if acac.lower() == "true" else 5.3
            findings.append({
                "severity": sev,
                "cvss_score": score,
                "title": "CORS Reflects Arbitrary Origin",
                "description": f"Server reflects arbitrary Origin header in ACAO. Credentials allowed: {acac or 'No'}",
                "affected_url": url,
                "recommendation": "Implement a strict whitelist for allowed CORS origins.",
                "category": "CORS"
            })
        elif acao:
            findings.append({
                "severity": "info",
                "cvss_score": 0.0,
                "title": "CORS Policy Configured",
                "description": f"CORS is restricted to: {acao}",
                "affected_url": url,
                "recommendation": "Verify the allowed origin is trusted.",
                "category": "CORS"
            })
        else:
            findings.append({
                "severity": "info",
                "cvss_score": 0.0,
                "title": "No CORS Headers",
                "description": "No Access-Control-Allow-Origin header detected.",
                "affected_url": url,
                "recommendation": "No action needed if cross-origin access is not required.",
                "category": "CORS"
            })
    except Exception as e:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "CORS Check Failed",
            "description": f"Error: {str(e)[:100]}",
            "affected_url": url,
            "recommendation": "Verify URL accessibility.",
            "category": "CORS"
        })
    return findings


def check_server_disclosure(url):
    findings = []
    try:
        resp = requests.get(url, timeout=TIMEOUT, verify=False)
        headers = resp.headers

        server = headers.get("Server", "")
        powered = headers.get("X-Powered-By", "")
        asp = headers.get("X-AspNet-Version", "")

        disclosures = []
        if server:
            disclosures.append(f"Server: {server}")
        if powered:
            disclosures.append(f"X-Powered-By: {powered}")
        if asp:
            disclosures.append(f"X-AspNet-Version: {asp}")

        import re
        version_pattern = re.compile(r'\d+\.\d+')

        if disclosures:
            has_version = any(version_pattern.search(d) for d in disclosures)
            findings.append({
                "severity": "medium" if has_version else "low",
                "cvss_score": 5.3 if has_version else 2.6,
                "title": "Server Version Disclosure",
                "description": f"Server discloses: {'; '.join(disclosures)}",
                "affected_url": url,
                "recommendation": "Remove or hide server version information. Configure web server to suppress version headers.",
                "category": "Server Disclosure"
            })
        else:
            findings.append({
                "severity": "info",
                "cvss_score": 0.0,
                "title": "No Server Version Disclosure",
                "description": "Server does not disclose version information in response headers.",
                "affected_url": url,
                "recommendation": "Good practice - no version disclosure.",
                "category": "Server Disclosure"
            })
    except Exception as e:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "Server Disclosure Check Failed",
            "description": f"Error: {str(e)[:100]}",
            "affected_url": url,
            "recommendation": "Verify URL accessibility.",
            "category": "Server Disclosure"
        })
    return findings


def run_scan(url):
    url = normalize_url(url)
    scan_id = str(uuid.uuid4())
    start_time = time.time()

    all_findings = []
    checks = [
        ("Security Headers", check_security_headers),
        ("SSL/TLS", check_ssl_tls),
        ("Technology Detection", check_technology_stack),
        ("Exposed Files", check_exposed_files),
        ("DNS", check_dns_info),
        ("Robots.txt", check_robots_txt),
        ("Cookies", check_cookies),
        ("CORS", check_cors),
        ("Server Disclosure", check_server_disclosure),
    ]

    progress = []

    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {}
        for name, func in checks:
            futures[executor.submit(func, url)] = name

        for future in as_completed(futures):
            check_name = futures[future]
            try:
                results = future.result(timeout=15)
                all_findings.extend(results)
                progress.append({"check": check_name, "status": "done", "findings": len(results)})
            except Exception as e:
                progress.append({"check": check_name, "status": "error", "error": str(e)[:100]})

    elapsed = round(time.time() - start_time, 2)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_findings.sort(key=lambda x: severity_order.get(x["severity"], 5))

    stats = {
        "critical": sum(1 for f in all_findings if f["severity"] == "critical"),
        "high": sum(1 for f in all_findings if f["severity"] == "high"),
        "medium": sum(1 for f in all_findings if f["severity"] == "medium"),
        "low": sum(1 for f in all_findings if f["severity"] == "low"),
        "info": sum(1 for f in all_findings if f["severity"] == "info"),
    }

    max_cvss = max((f["cvss_score"] for f in all_findings), default=0.0)
    if max_cvss >= 9.0:
        risk_level = "CRITICAL"
    elif max_cvss >= 7.0:
        risk_level = "HIGH"
    elif max_cvss >= 4.0:
        risk_level = "MEDIUM"
    elif max_cvss > 0:
        risk_level = "LOW"
    else:
        risk_level = "INFORMATIONAL"

    report = {
        "scan_id": scan_id,
        "target": url,
        "scan_date": datetime.utcnow().isoformat() + "Z",
        "duration_seconds": elapsed,
        "risk_level": risk_level,
        "max_cvss": max_cvss,
        "stats": stats,
        "total_findings": len(all_findings),
        "findings": all_findings,
        "progress": progress
    }

    return report
