# VULNSCAN - Automated Web Security Scanner
# Passive reconnaissance only - no active exploitation

import requests
import ssl
import socket
import dns.resolver
import uuid
import time
import re
import whois
from datetime import datetime
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

TIMEOUT = 8

EXPOSED_FILES = [
    # PHP Info
    '/phpinfo.php', '/info.php', '/php.php', '/test.php', '/admin/phpinfo.php',
    # Config files
    '/.env', '/.env.local', '/.env.production', '/.env.backup',
    '/config.php', '/config.json', '/config.yml', '/configuration.php',
    '/wp-config.php', '/wp-config.php.bak', '/database.php', '/db.php',
    '/settings.php', '/settings.json', '/app.config', '/web.config',
    # Backup files
    '/backup.zip', '/backup.tar.gz', '/backup.sql', '/dump.sql',
    '/database.sql', '/site.sql', '/db.sql', '/backup.tar',
    '/www.zip', '/public_html.zip', '/.backup',
    # Git/Version control
    '/.git/config', '/.git/HEAD', '/.gitignore', '/.svn/entries',
    # Admin panels
    '/admin', '/admin/', '/admin/login', '/admin/index.php',
    '/wp-admin', '/wp-admin/', '/wp-login.php',
    '/administrator', '/phpmyadmin', '/pma', '/phpMyAdmin',
    '/adminer.php', '/db', '/database', '/mysql', '/sql',
    # Log files
    '/error.log', '/access.log', '/debug.log', '/app.log',
    '/logs/error.log', '/log/error.log',
    # API endpoints
    '/api', '/api/v1', '/api/v2', '/graphql', '/swagger',
    '/swagger.json', '/swagger-ui.html', '/api-docs', '/openapi.json',
    '/rest', '/rest/api',
    # Common sensitive
    '/robots.txt', '/sitemap.xml', '/.htaccess', '/crossdomain.xml',
    '/clientaccesspolicy.xml', '/security.txt', '/.well-known/security.txt',
    # Server status
    '/server-status', '/server-info', '/_status', '/status',
    '/health', '/healthcheck', '/ping',
    # CMS specific
    '/xmlrpc.php', '/feed', '/wp-json/wp/v2/users',
    '/joomla', '/drupal', '/magento',
    # Additional sensitive paths
    '/.env.dev', '/.env.staging', '/.env.example',
    '/composer.json', '/composer.lock', '/package.json', '/package-lock.json',
    '/yarn.lock', '/Gemfile', '/Gemfile.lock',
    '/Dockerfile', '/docker-compose.yml', '/.dockerenv',
    '/Makefile', '/Rakefile', '/Gruntfile.js', '/Gulpfile.js',
    '/webpack.config.js', '/tsconfig.json', '/.babelrc',
    # More backups
    '/backup/', '/backups/', '/old/', '/temp/', '/tmp/',
    '/copy/', '/archive/', '/_backup/',
    # Credentials / secrets
    '/credentials.json', '/secrets.json', '/id_rsa', '/.ssh/id_rsa',
    '/htpasswd', '/.htpasswd', '/passwd', '/shadow',
    # CPanel / hosting
    '/cpanel', '/plesk', '/webmail',
    # CI/CD
    '/.github/', '/.gitlab-ci.yml', '/Jenkinsfile', '/.circleci/config.yml',
    # Node / Python
    '/node_modules/', '/__pycache__/', '/venv/', '/.venv/',
    # Database dumps
    '/mysql.sql', '/postgres.sql', '/mongodb.json',
    '/data.json', '/users.json', '/export.csv',
    # Apache/Nginx configs
    '/nginx.conf', '/apache.conf', '/httpd.conf',
    '/.nginx.conf', '/sites-enabled/', '/conf/',
    # Tomcat
    '/manager/html', '/manager/status', '/WEB-INF/web.xml',
    # Debug/Test
    '/test/', '/debug/', '/trace/', '/console/',
    '/phpunit.xml', '/.phpunit.result.cache',
    # Source code
    '/source/', '/src/', '/app/', '/includes/',
    # Logs extended
    '/logs/', '/log/', '/var/log/',
    '/wp-content/debug.log', '/storage/logs/laravel.log',
]

HIGH_SEVERITY_PATHS = [
    '/.env', '/.env.local', '/.env.production', '/.env.backup', '/.env.dev', '/.env.staging',
    '/backup.sql', '/database.sql', '/dump.sql', '/site.sql', '/db.sql', '/mysql.sql',
    '/.git/config', '/.git/HEAD', '/wp-config.php', '/wp-config.php.bak',
    '/config.php', '/database.php', '/db.php', '/credentials.json', '/secrets.json',
    '/id_rsa', '/.ssh/id_rsa', '/htpasswd', '/.htpasswd',
    '/backup.zip', '/backup.tar.gz', '/www.zip', '/public_html.zip',
    '/users.json', '/export.csv', '/storage/logs/laravel.log',
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "high",
        "cvss": 6.1,
        "desc": "HTTP Strict Transport Security (HSTS) header is missing. This allows downgrade attacks and cookie hijacking.",
        "fix": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "expected": "max-age=31536000; includeSubDomains"
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "cvss": 5.3,
        "desc": "Content Security Policy (CSP) header is missing. This increases the risk of XSS attacks.",
        "fix": "Add header: Content-Security-Policy: default-src 'self'",
        "expected": "default-src 'self'"
    },
    "X-Frame-Options": {
        "severity": "medium",
        "cvss": 4.3,
        "desc": "X-Frame-Options header is missing. The site may be vulnerable to clickjacking attacks.",
        "fix": "Add header: X-Frame-Options: DENY",
        "expected": "DENY"
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "cvss": 3.1,
        "desc": "X-Content-Type-Options header is missing. Browsers may MIME-sniff responses.",
        "fix": "Add header: X-Content-Type-Options: nosniff",
        "expected": "nosniff"
    },
    "Referrer-Policy": {
        "severity": "low",
        "cvss": 3.1,
        "desc": "Referrer-Policy header is missing. Sensitive information may leak via Referer header.",
        "fix": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
        "expected": "strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "severity": "low",
        "cvss": 2.6,
        "desc": "Permissions-Policy header is missing. Browser features are not restricted.",
        "fix": "Add header: Permissions-Policy: geolocation=(), microphone=()",
        "expected": "geolocation=(), microphone=()"
    },
    "X-XSS-Protection": {
        "severity": "info",
        "cvss": 0.0,
        "desc": "X-XSS-Protection header is not set (deprecated but still recommended for older browsers).",
        "fix": "Add header: X-XSS-Protection: 1; mode=block",
        "expected": "1; mode=block"
    }
}

COMMON_PORTS = [80, 443, 8080, 8443, 3000, 4000, 5000, 8000, 8888, 9000]

EXTENDED_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
    6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 8888: 'Jupyter',
    9200: 'Elasticsearch', 27017: 'MongoDB', 11211: 'Memcached'
}

COMMON_SUBDOMAINS = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 'test',
    'shop', 'blog', 'portal', 'app', 'mobile', 'cdn', 'static', 'media',
    'vpn', 'remote', 'cpanel', 'whm', 'webmail', 'ns1', 'ns2', 'smtp',
    'pop', 'imap', 'mx', 'support', 'help', 'docs', 'wiki', 'git', 'gitlab',
    'jenkins', 'jira', 'confluence', 'grafana', 'kibana', 'monitor']

CMS_SIGNATURES = {
    'WordPress': ['/wp-content/', '/wp-includes/', 'wp-json'],
    'Joomla': ['/administrator/', 'Joomla!', '/components/'],
    'Drupal': ['/sites/default/', 'Drupal.settings', 'drupal.js'],
    'Magento': ['/skin/frontend/', 'Mage.Cookies', '/magento/'],
    'Shopify': ['cdn.shopify.com', 'Shopify.theme'],
    'Wix': ['wix.com', 'wixstatic.com'],
    'Squarespace': ['squarespace.com', 'static.squarespace.com'],
    'Next.js': ['__NEXT_DATA__', '_next/static'],
    'React': ['__react', 'react-root'],
    'Vue.js': ['__vue__', 'vue-app'],
    'Angular': ['ng-version', 'angular.js'],
    'Laravel': ['laravel_session', 'X-Laravel'],
    'Django': ['csrfmiddlewaretoken', 'django'],
    'Flask': ['werkzeug', 'Flask'],
}

DANGEROUS_METHODS = ['TRACE', 'TRACK', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']

SOCIAL_MEDIA_PATTERNS = {
    'facebook': r'https?://(?:www\.)?facebook\.com/[^\s"\'<>]+',
    'twitter': r'https?://(?:www\.)?(?:twitter|x)\.com/[^\s"\'<>]+',
    'instagram': r'https?://(?:www\.)?instagram\.com/[^\s"\'<>]+',
    'linkedin': r'https?://(?:www\.)?linkedin\.com/[^\s"\'<>]+',
    'youtube': r'https?://(?:www\.)?youtube\.com/[^\s"\'<>]+',
    'github': r'https?://(?:www\.)?github\.com/[^\s"\'<>]+',
    'tiktok': r'https?://(?:www\.)?tiktok\.com/[^\s"\'<>]+',
    'pinterest': r'https?://(?:www\.)?pinterest\.com/[^\s"\'<>]+',
    'reddit': r'https?://(?:www\.)?reddit\.com/[^\s"\'<>]+',
    'telegram': r'https?://(?:t\.me|telegram\.me)/[^\s"\'<>]+',
}


def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def get_domain(url):
    return urlparse(url).hostname


def check_security_headers(url):
    findings = []
    headers_detail = {}
    try:
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True, verify=False)
        headers = resp.headers
        headers_lower_map = {k.lower(): v for k, v in headers.items()}

        for header_name, info in SECURITY_HEADERS.items():
            present = header_name.lower() in headers_lower_map
            if not present:
                findings.append({
                    "severity": info["severity"],
                    "cvss_score": info["cvss"],
                    "title": f"Missing Security Header: {header_name}",
                    "description": info["desc"],
                    "affected_url": url,
                    "recommendation": info["fix"],
                    "category": "Security Headers"
                })
                headers_detail[header_name] = {
                    "present": False,
                    "expected": info["expected"],
                    "actual": None
                }
            else:
                actual_value = headers_lower_map[header_name.lower()]
                findings.append({
                    "severity": "info",
                    "cvss_score": 0.0,
                    "title": f"Security Header Present: {header_name}",
                    "description": f"{header_name} header is configured: {actual_value}",
                    "affected_url": url,
                    "recommendation": "No action needed.",
                    "category": "Security Headers"
                })
                headers_detail[header_name] = {
                    "present": True,
                    "expected": info["expected"],
                    "actual": actual_value
                }
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
    return findings, headers_detail


def check_ssl_tls(url):
    findings = []
    ssl_detail = {}
    domain = get_domain(url)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()

                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                days_left = (not_after - datetime.utcnow()).days

                issuer = dict(x[0] for x in cert.get('issuer', []))
                subject = dict(x[0] for x in cert.get('subject', []))

                sans = []
                for san_type, san_value in cert.get('subjectAltName', []):
                    sans.append(san_value)

                ssl_detail = {
                    "valid": days_left > 0,
                    "days_remaining": days_left,
                    "expires": not_after.strftime('%Y-%m-%d %H:%M:%S'),
                    "issued": not_before.strftime('%Y-%m-%d %H:%M:%S'),
                    "issuer": issuer.get('organizationName', issuer.get('commonName', 'Unknown')),
                    "subject": subject.get('commonName', 'Unknown'),
                    "protocol": protocol,
                    "sans": sans[:20],
                    "serial_number": cert.get('serialNumber', 'Unknown'),
                }

                if days_left < 0:
                    findings.append({
                        "severity": "critical",
                        "cvss_score": 9.1,
                        "title": "SSL Certificate Expired",
                        "description": f"Certificate expired {abs(days_left)} days ago. Issued by: {ssl_detail['issuer']}",
                        "affected_url": url,
                        "recommendation": "Renew the SSL certificate immediately.",
                        "category": "SSL/TLS"
                    })
                elif days_left < 30:
                    findings.append({
                        "severity": "high",
                        "cvss_score": 6.5,
                        "title": "SSL Certificate Expiring Soon",
                        "description": f"Certificate expires in {days_left} days (on {not_after.strftime('%Y-%m-%d')}). Issuer: {ssl_detail['issuer']}",
                        "affected_url": url,
                        "recommendation": "Renew the SSL certificate before expiration.",
                        "category": "SSL/TLS"
                    })
                else:
                    findings.append({
                        "severity": "info",
                        "cvss_score": 0.0,
                        "title": "SSL Certificate Valid",
                        "description": f"Certificate valid for {days_left} days. Expires: {not_after.strftime('%Y-%m-%d')}. Protocol: {protocol}. Issuer: {ssl_detail['issuer']}. SANs: {', '.join(sans[:5])}",
                        "affected_url": url,
                        "recommendation": "No action needed. Monitor expiration date.",
                        "category": "SSL/TLS"
                    })

                if protocol in ('TLSv1', 'TLSv1.1'):
                    findings.append({
                        "severity": "high",
                        "cvss_score": 7.4,
                        "title": "Deprecated TLS Version in Use",
                        "description": f"Server negotiated deprecated protocol: {protocol}",
                        "affected_url": url,
                        "recommendation": "Disable TLS 1.0 and TLS 1.1. Use TLS 1.2 or higher.",
                        "category": "SSL/TLS"
                    })
                    ssl_detail["deprecated_tls"] = True
                else:
                    ssl_detail["deprecated_tls"] = False

        for old_proto_name, old_proto in [("TLSv1", ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None),
                                           ("TLSv1.1", ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None)]:
            if old_proto is None:
                continue
            try:
                old_ctx = ssl.SSLContext(old_proto)
                old_ctx.check_hostname = False
                old_ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((domain, 443), timeout=5) as s2:
                    with old_ctx.wrap_socket(s2, server_hostname=domain) as ss2:
                        findings.append({
                            "severity": "high",
                            "cvss_score": 7.4,
                            "title": f"Server Supports Deprecated {old_proto_name}",
                            "description": f"Server accepts connections using deprecated {old_proto_name} protocol.",
                            "affected_url": url,
                            "recommendation": f"Disable {old_proto_name} on the server. Use TLS 1.2+ only.",
                            "category": "SSL/TLS"
                        })
                        ssl_detail["deprecated_tls"] = True
            except:
                pass

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
        ssl_detail = {"valid": False, "error": str(e)[:150]}
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
        ssl_detail = {"valid": False, "error": str(e)[:100]}
    return findings, ssl_detail


def check_technology_stack(url):
    findings = []
    techs = []
    tech_detail = {}
    try:
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True, verify=False)
        headers = resp.headers
        body = resp.text[:50000]
        body_lower = body.lower()

        server = headers.get("Server", "")
        if server:
            techs.append(f"Server: {server}")
            tech_detail["server"] = server

        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            techs.append(f"X-Powered-By: {powered_by}")
            tech_detail["powered_by"] = powered_by
            php_match = re.search(r'PHP[/ ]?([\d.]+)', powered_by)
            if php_match:
                tech_detail["php_version"] = php_match.group(1)

        asp_ver = headers.get("X-AspNet-Version", "")
        if asp_ver:
            techs.append(f"ASP.NET: {asp_ver}")
            tech_detail["aspnet_version"] = asp_ver

        via = headers.get("Via", "")
        if via:
            techs.append(f"Via: {via}")

        set_cookies = resp.headers.get('Set-Cookie', '')
        if 'laravel_session' in set_cookies.lower():
            techs.append("Framework: Laravel")
            tech_detail["framework"] = "Laravel"

        # Deep CMS detection using CMS_SIGNATURES
        detected_cms = []
        for cms_name, signatures in CMS_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in body_lower or sig.lower() in set_cookies.lower():
                    if cms_name not in detected_cms:
                        detected_cms.append(cms_name)
                    break

        for cms in detected_cms:
            if cms not in str(techs):
                techs.append(f"CMS/Framework: {cms}")
                if "cms" not in tech_detail:
                    tech_detail["cms"] = cms
                else:
                    tech_detail["cms"] = tech_detail["cms"] + ", " + cms

        # Legacy CMS detection (kept for version extraction)
        if "wp-content" in body_lower or "wp-includes" in body_lower:
            if "WordPress" not in detected_cms:
                techs.append("CMS: WordPress")
                tech_detail["cms"] = tech_detail.get("cms", "WordPress")
            wp_ver = re.search(r'content="WordPress ([\d.]+)"', body)
            if wp_ver:
                tech_detail["cms_version"] = wp_ver.group(1)

        # Frontend frameworks
        if "__react" in body_lower or "react-root" in body_lower or "data-reactroot" in body_lower or "_reactRootContainer" in body:
            if "React" not in str(techs):
                techs.append("Frontend: React")
                tech_detail["frontend_framework"] = "React"
        if "__vue" in body_lower or "data-v-" in body or 'id="app"' in body_lower:
            vue_check = re.search(r'vue[/@]([\d.]+)', body_lower)
            if "Vue" not in str(techs):
                techs.append("Frontend: Vue.js")
                tech_detail["frontend_framework"] = "Vue.js"
            if vue_check:
                tech_detail["vue_version"] = vue_check.group(1)
        if "ng-version" in body or "ng-app" in body_lower or "angular" in body_lower:
            ng_ver = re.search(r'ng-version="([\d.]+)"', body)
            if "Angular" not in str(techs):
                techs.append("Frontend: Angular")
                tech_detail["frontend_framework"] = "Angular"
            if ng_ver:
                tech_detail["angular_version"] = ng_ver.group(1)

        if "/_next/" in body and "Next.js" not in str(techs):
            techs.append("Framework: Next.js")
            tech_detail["framework"] = tech_detail.get("framework", "") + " Next.js"

        jquery_match = re.search(r'jquery[.-]?([\d.]+)(?:\.min)?\.js', body_lower)
        if jquery_match:
            techs.append(f"jQuery: {jquery_match.group(1)}")
            tech_detail["jquery_version"] = jquery_match.group(1)

        bootstrap_match = re.search(r'bootstrap[.-]?([\d.]+)(?:\.min)?\.(?:js|css)', body_lower)
        if bootstrap_match:
            techs.append(f"Bootstrap: {bootstrap_match.group(1)}")
            tech_detail["bootstrap_version"] = bootstrap_match.group(1)

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
    return findings, techs, tech_detail


def check_exposed_files(url):
    findings = []
    exposed_detail = []

    def check_path(path):
        try:
            check_url = url + path
            resp = requests.get(check_url, timeout=TIMEOUT, allow_redirects=False, verify=False)
            if resp.status_code == 200:
                is_high = path in HIGH_SEVERITY_PATHS
                result = {
                    "severity": "high" if is_high else "medium",
                    "cvss_score": 7.5 if is_high else 5.3,
                    "title": f"Exposed File/Path: {path}",
                    "description": f"The path {path} returned HTTP 200 (accessible). This file/endpoint may expose sensitive information.",
                    "affected_url": check_url,
                    "recommendation": f"Restrict access to {path}. Add authentication or remove from production.",
                    "category": "Exposed Files"
                }
                detail = {"path": path, "status": 200, "severity": "high" if is_high else "medium", "url": check_url}
                return result, detail
            elif resp.status_code == 403:
                result = {
                    "severity": "low",
                    "cvss_score": 2.0,
                    "title": f"Path Exists (Forbidden): {path}",
                    "description": f"The path {path} returned HTTP 403 (Forbidden). File exists but access is restricted.",
                    "affected_url": check_url,
                    "recommendation": "Access is restricted. Verify this is intentional.",
                    "category": "Exposed Files"
                }
                detail = {"path": path, "status": 403, "severity": "low", "url": check_url}
                return result, detail
        except:
            pass
        return None, None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_path, p): p for p in EXPOSED_FILES}
        for future in as_completed(futures):
            result, detail = future.result()
            if result:
                findings.append(result)
            if detail:
                exposed_detail.append(detail)

    if not findings:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "No Exposed Files Detected",
            "description": f"Checked {len(EXPOSED_FILES)} common sensitive file paths. None returned 200 or 403.",
            "affected_url": url,
            "recommendation": "Continue monitoring for accidental exposure.",
            "category": "Exposed Files"
        })
    return findings, exposed_detail


def check_dns_info(url):
    findings = []
    domain = get_domain(url)
    dns_detail = {}
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

        dns_detail = records

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
    return findings, dns_detail


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


def check_ports(url):
    findings = []
    open_ports = []
    domain = get_domain(url)

    def check_port(port_info):
        port, service = port_info
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((domain, port))
            sock.close()
            if result == 0:
                return {'port': port, 'service': service, 'status': 'open'}
        except:
            pass
        return None

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(check_port, (p, s)): p for p, s in EXTENDED_PORTS.items()}
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x['port'])

    if open_ports:
        dangerous_ports = [p for p in open_ports if p['port'] in [21, 23, 445, 3306, 3389, 5432, 5900, 6379, 9200, 27017, 11211]]
        non_standard = [p for p in open_ports if p['port'] not in (80, 443)]

        if dangerous_ports:
            findings.append({
                "severity": "high",
                "cvss_score": 7.5,
                "title": "Dangerous Ports Open",
                "description": "High-risk ports detected: " + ", ".join(str(p['port']) + "/" + p['service'] for p in dangerous_ports) + ". These services should not be publicly accessible.",
                "affected_url": url,
                "recommendation": "Restrict access to database/admin ports using firewall rules. Only allow from trusted IPs.",
                "category": "Port Scan"
            })
        elif non_standard:
            findings.append({
                "severity": "medium",
                "cvss_score": 4.3,
                "title": "Non-Standard Ports Open",
                "description": "Non-standard ports detected: " + ", ".join(str(p['port']) + "/" + p['service'] for p in non_standard),
                "affected_url": url,
                "recommendation": "Review if non-standard ports should be publicly accessible. Use firewall rules to restrict.",
                "category": "Port Scan"
            })

        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": f"Open Ports Detected ({len(open_ports)})",
            "description": "Open ports: " + ", ".join(str(p['port']) + "/" + p['service'] for p in open_ports),
            "affected_url": url,
            "recommendation": "Ensure only necessary ports are exposed.",
            "category": "Port Scan"
        })
    else:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "Port Scan Complete",
            "description": "No common ports responded (checked: " + ', '.join(f"{p}/{s}" for p, s in EXTENDED_PORTS.items()) + ")",
            "affected_url": url,
            "recommendation": "Standard ports may be filtered by firewall.",
            "category": "Port Scan"
        })

    return findings, open_ports


def check_emails(url):
    findings = []
    emails_found = []
    try:
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True, verify=False)
        body = resp.text

        email_pattern = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
        raw_emails = email_pattern.findall(body)

        filtered = set()
        ignore_extensions = ['.png', '.jpg', '.gif', '.css', '.js', '.svg', '.woff']
        for email in raw_emails:
            email_lower = email.lower()
            if not any(email_lower.endswith(ext) for ext in ignore_extensions):
                if not email_lower.startswith('//') and '@' in email:
                    filtered.add(email_lower)

        emails_found = sorted(list(filtered))[:50]

        if emails_found:
            findings.append({
                "severity": "low",
                "cvss_score": 3.1,
                "title": f"Email Addresses Found ({len(emails_found)})",
                "description": f"Found {len(emails_found)} email(s) in page source: {', '.join(emails_found[:10])}",
                "affected_url": url,
                "recommendation": "Consider obfuscating email addresses to prevent spam harvesting.",
                "category": "Email Harvesting"
            })
        else:
            findings.append({
                "severity": "info",
                "cvss_score": 0.0,
                "title": "No Email Addresses Found",
                "description": "No email addresses detected in page source.",
                "affected_url": url,
                "recommendation": "No action needed.",
                "category": "Email Harvesting"
            })
    except Exception as e:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "Email Harvesting Failed",
            "description": f"Error: {str(e)[:100]}",
            "affected_url": url,
            "recommendation": "Verify URL accessibility.",
            "category": "Email Harvesting"
        })
    return findings, emails_found


def check_social_media(url):
    findings = []
    social_links = {}
    try:
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True, verify=False)
        body = resp.text

        for platform, pattern in SOCIAL_MEDIA_PATTERNS.items():
            matches = re.findall(pattern, body)
            if matches:
                unique = list(set(matches))[:5]
                social_links[platform] = unique

        if social_links:
            findings.append({
                "severity": "info",
                "cvss_score": 0.0,
                "title": f"Social Media Links Found ({len(social_links)} platforms)",
                "description": f"Found links to: {', '.join(social_links.keys())}",
                "affected_url": url,
                "recommendation": "Verify all social media links are official and active.",
                "category": "Social Media"
            })
        else:
            findings.append({
                "severity": "info",
                "cvss_score": 0.0,
                "title": "No Social Media Links Found",
                "description": "No social media links detected in page source.",
                "affected_url": url,
                "recommendation": "No action needed.",
                "category": "Social Media"
            })
    except Exception as e:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "Social Media Check Failed",
            "description": f"Error: {str(e)[:100]}",
            "affected_url": url,
            "recommendation": "Verify URL accessibility.",
            "category": "Social Media"
        })
    return findings, social_links


def check_external_links(url):
    findings = []
    external_domains = []
    try:
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True, verify=False)
        body = resp.text
        target_domain = get_domain(url)

        url_pattern = re.compile(r'(?:src|href|action)=["\']?(https?://[^\s"\'<>]+)', re.IGNORECASE)
        all_urls = url_pattern.findall(body)

        ext_domains = set()
        for found_url in all_urls:
            try:
                found_domain = urlparse(found_url).hostname
                if found_domain and found_domain != target_domain and not found_domain.endswith('.' + target_domain):
                    ext_domains.add(found_domain)
            except:
                pass

        external_domains = sorted(list(ext_domains))[:50]

        if external_domains:
            findings.append({
                "severity": "info",
                "cvss_score": 0.0,
                "title": f"External Domains Loaded ({len(external_domains)})",
                "description": f"Page loads resources from {len(external_domains)} external domains: {', '.join(external_domains[:15])}",
                "affected_url": url,
                "recommendation": "Review external domains for trust. Use SRI (Subresource Integrity) for external scripts.",
                "category": "External Links"
            })
        else:
            findings.append({
                "severity": "info",
                "cvss_score": 0.0,
                "title": "No External Resources",
                "description": "No external domains detected in page resources.",
                "affected_url": url,
                "recommendation": "Good practice - self-hosted resources.",
                "category": "External Links"
            })
    except Exception as e:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "External Links Check Failed",
            "description": f"Error: {str(e)[:100]}",
            "affected_url": url,
            "recommendation": "Verify URL accessibility.",
            "category": "External Links"
        })
    return findings, external_domains


def check_forms(url):
    findings = []
    forms_detail = []
    try:
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True, verify=False)
        body = resp.text

        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        form_tag_pattern = re.compile(r'<form([^>]*)>', re.IGNORECASE)
        forms = form_pattern.findall(body)
        form_tags = form_tag_pattern.findall(body)

        for i, (form_attrs, form_content) in enumerate(zip(form_tags, forms)):
            form_info = {"index": i + 1, "issues": []}

            action_match = re.search(r'action=["\']([^"\']*)["\']', form_attrs, re.IGNORECASE)
            action = action_match.group(1) if action_match else ""
            form_info["action"] = action

            method_match = re.search(r'method=["\']([^"\']*)["\']', form_attrs, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else "GET"
            form_info["method"] = method

            has_csrf = bool(re.search(r'(csrf|_token|csrfmiddlewaretoken|authenticity_token|__RequestVerificationToken)', form_content, re.IGNORECASE))
            if not has_csrf and method == "POST":
                form_info["issues"].append("No CSRF token detected")

            if action and action.startswith("http://"):
                form_info["issues"].append("Form submits over HTTP (not HTTPS)")

            password_fields = re.findall(r'<input[^>]*type=["\']password["\'][^>]*>', form_content, re.IGNORECASE)
            for pf in password_fields:
                if 'autocomplete="off"' not in pf.lower() and "autocomplete='off'" not in pf.lower():
                    form_info["issues"].append("Password field with autocomplete enabled")
                    break

            input_count = len(re.findall(r'<input', form_content, re.IGNORECASE))
            form_info["input_count"] = input_count
            form_info["has_password"] = bool(password_fields)

            forms_detail.append(form_info)

            if form_info["issues"]:
                findings.append({
                    "severity": "medium",
                    "cvss_score": 5.3,
                    "title": f"Form #{i+1} Security Issues",
                    "description": f"Form (action='{action}', method={method}) has issues: {'; '.join(form_info['issues'])}",
                    "affected_url": url,
                    "recommendation": "Add CSRF tokens to forms, use HTTPS for submissions, disable autocomplete on password fields.",
                    "category": "Form Analysis"
                })

        if forms_detail and not any(f["issues"] for f in forms_detail):
            findings.append({
                "severity": "info",
                "cvss_score": 0.0,
                "title": f"Forms Found ({len(forms_detail)}) - No Issues",
                "description": f"Found {len(forms_detail)} form(s) with no detected security issues.",
                "affected_url": url,
                "recommendation": "No action needed.",
                "category": "Form Analysis"
            })
        elif not forms_detail:
            findings.append({
                "severity": "info",
                "cvss_score": 0.0,
                "title": "No Forms Found",
                "description": "No HTML forms detected on the page.",
                "affected_url": url,
                "recommendation": "No action needed.",
                "category": "Form Analysis"
            })

    except Exception as e:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "Form Analysis Failed",
            "description": f"Error: {str(e)[:100]}",
            "affected_url": url,
            "recommendation": "Verify URL accessibility.",
            "category": "Form Analysis"
        })
    return findings, forms_detail


def check_javascript(url):
    findings = []
    js_detail = []
    try:
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True, verify=False)
        body = resp.text
        target_domain = get_domain(url)

        script_pattern = re.compile(r'<script[^>]*src=["\']([^"\']+)["\']', re.IGNORECASE)
        scripts = script_pattern.findall(body)

        for script_src in scripts:
            js_info = {"src": script_src, "issues": []}

            if script_src.startswith('//'):
                full_url = 'https:' + script_src
            elif script_src.startswith('/'):
                full_url = url + script_src
            elif not script_src.startswith('http'):
                full_url = url + '/' + script_src
            else:
                full_url = script_src

            if full_url.startswith('http://'):
                js_info["issues"].append("Loaded over HTTP (insecure)")

            try:
                script_domain = urlparse(full_url).hostname
                if script_domain and script_domain != target_domain:
                    known_cdns = ['cdnjs.cloudflare.com', 'cdn.jsdelivr.net', 'unpkg.com',
                                  'ajax.googleapis.com', 'code.jquery.com', 'stackpath.bootstrapcdn.com',
                                  'maxcdn.bootstrapcdn.com', 'cdn.bootcdn.net', 'cdn.staticfile.org',
                                  'fonts.googleapis.com', 'www.google-analytics.com',
                                  'www.googletagmanager.com', 'connect.facebook.net']
                    if script_domain not in known_cdns:
                        js_info["issues"].append(f"External script from unknown domain: {script_domain}")
                    js_info["external"] = True
                    js_info["domain"] = script_domain
                else:
                    js_info["external"] = False
            except:
                pass

            if '.min.js' in script_src:
                js_info["minified"] = True
            else:
                js_info["minified"] = False

            js_detail.append(js_info)

        sourcemap_pattern = re.compile(r'//[#@]\s*sourceMappingURL=([^\s]+)', re.IGNORECASE)
        sourcemaps = sourcemap_pattern.findall(body)
        if sourcemaps:
            findings.append({
                "severity": "low",
                "cvss_score": 3.1,
                "title": "Source Maps Exposed",
                "description": f"Found {len(sourcemaps)} source map reference(s). Source maps can expose original source code.",
                "affected_url": url,
                "recommendation": "Remove source maps from production builds.",
                "category": "JavaScript Analysis"
            })

        http_scripts = [j for j in js_detail if "Loaded over HTTP (insecure)" in j.get("issues", [])]
        unknown_scripts = [j for j in js_detail if any("unknown domain" in issue for issue in j.get("issues", []))]

        if http_scripts:
            findings.append({
                "severity": "medium",
                "cvss_score": 5.3,
                "title": f"JavaScript Loaded Over HTTP ({len(http_scripts)})",
                "description": f"Scripts loaded insecurely: {', '.join(s['src'][:80] for s in http_scripts[:5])}",
                "affected_url": url,
                "recommendation": "Load all scripts over HTTPS to prevent MITM attacks.",
                "category": "JavaScript Analysis"
            })

        if unknown_scripts:
            findings.append({
                "severity": "low",
                "cvss_score": 3.1,
                "title": f"Scripts from Unknown CDNs ({len(unknown_scripts)})",
                "description": f"Scripts loaded from non-standard sources: {', '.join(s.get('domain', '?') for s in unknown_scripts[:5])}",
                "affected_url": url,
                "recommendation": "Use Subresource Integrity (SRI) for external scripts. Verify script sources.",
                "category": "JavaScript Analysis"
            })

        if js_detail and not http_scripts and not unknown_scripts and not sourcemaps:
            findings.append({
                "severity": "info",
                "cvss_score": 0.0,
                "title": f"JavaScript Files ({len(js_detail)}) - No Issues",
                "description": f"Found {len(js_detail)} script(s). All load securely from trusted sources.",
                "affected_url": url,
                "recommendation": "No action needed.",
                "category": "JavaScript Analysis"
            })
        elif not js_detail:
            findings.append({
                "severity": "info",
                "cvss_score": 0.0,
                "title": "No External JavaScript",
                "description": "No external script tags detected.",
                "affected_url": url,
                "recommendation": "No action needed.",
                "category": "JavaScript Analysis"
            })

    except Exception as e:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "JavaScript Analysis Failed",
            "description": f"Error: {str(e)[:100]}",
            "affected_url": url,
            "recommendation": "Verify URL accessibility.",
            "category": "JavaScript Analysis"
        })
    return findings, js_detail


# ===================== NEW MODULES =====================

def check_whois_info(url):
    findings = []
    whois_detail = {}
    domain = get_domain(url)
    base_domain = domain.replace('www.', '')
    try:
        w = whois.whois(base_domain)
        whois_detail = {
            'registrar': str(w.registrar) if w.registrar else 'N/A',
            'created': str(w.creation_date) if w.creation_date else 'N/A',
            'expires': str(w.expiration_date) if w.expiration_date else 'N/A',
            'updated': str(w.updated_date) if w.updated_date else 'N/A',
            'name_servers': w.name_servers if w.name_servers else [],
            'status': w.status if w.status else [],
            'country': str(w.country) if w.country else 'N/A',
            'org': str(w.org) if w.org else 'N/A',
        }

        # Calculate domain age
        domain_age_str = ''
        if w.creation_date:
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            age_days = (datetime.utcnow() - created).days
            domain_age_str = f"{age_days // 365} years, {(age_days % 365) // 30} months"
            whois_detail['domain_age_days'] = age_days
            whois_detail['domain_age'] = domain_age_str

        # Calculate expiry countdown
        if w.expiration_date:
            expires = w.expiration_date
            if isinstance(expires, list):
                expires = expires[0]
            days_to_expire = (expires - datetime.utcnow()).days
            whois_detail['days_to_expire'] = days_to_expire

            if days_to_expire < 30:
                findings.append({
                    "severity": "high",
                    "cvss_score": 6.0,
                    "title": "Domain Expiring Soon",
                    "description": f"Domain expires in {days_to_expire} days ({expires.strftime('%Y-%m-%d')}). Registrar: {w.registrar}",
                    "affected_url": url,
                    "recommendation": "Renew the domain immediately to prevent expiration and potential hijacking.",
                    "category": "Domain Intelligence"
                })
            elif days_to_expire < 90:
                findings.append({
                    "severity": "medium",
                    "cvss_score": 4.0,
                    "title": "Domain Expiring Within 90 Days",
                    "description": f"Domain expires in {days_to_expire} days ({expires.strftime('%Y-%m-%d')}). Registrar: {w.registrar}",
                    "affected_url": url,
                    "recommendation": "Renew the domain before expiration.",
                    "category": "Domain Intelligence"
                })

        desc = f"Registrar: {whois_detail['registrar']}. Created: {whois_detail['created']}. Expires: {whois_detail['expires']}."
        if domain_age_str:
            desc += f" Age: {domain_age_str}."
        if whois_detail['org'] != 'N/A':
            desc += f" Org: {whois_detail['org']}."

        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "WHOIS Information",
            "description": desc,
            "affected_url": url,
            "recommendation": "Verify domain registration details are correct.",
            "category": "Domain Intelligence"
        })

    except Exception as e:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "WHOIS Lookup Failed",
            "description": f"Could not retrieve WHOIS data: {str(e)[:100]}",
            "affected_url": url,
            "recommendation": "WHOIS may be restricted for this domain.",
            "category": "Domain Intelligence"
        })
    return findings, whois_detail


def check_ip_geolocation(url):
    findings = []
    geo_detail = {}
    domain = get_domain(url)
    try:
        ip = socket.gethostbyname(domain)
        r = requests.get(f'http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,lat,lon', timeout=5)
        data = r.json()
        if data.get('status') == 'success':
            geo_detail = {
                'ip': ip,
                'country': data.get('country', 'N/A'),
                'region': data.get('regionName', 'N/A'),
                'city': data.get('city', 'N/A'),
                'isp': data.get('isp', 'N/A'),
                'org': data.get('org', 'N/A'),
                'as': data.get('as', 'N/A'),
                'lat': data.get('lat', 0),
                'lon': data.get('lon', 0),
            }
            findings.append({
                "severity": "info",
                "cvss_score": 0.0,
                "title": "IP Geolocation",
                "description": f"IP: {ip} | Location: {geo_detail['city']}, {geo_detail['region']}, {geo_detail['country']} | ISP: {geo_detail['isp']} | Org: {geo_detail['org']}",
                "affected_url": url,
                "recommendation": "Verify server location matches expected hosting region.",
                "category": "IP & Location"
            })
        else:
            geo_detail = {'ip': ip, 'error': 'Lookup failed'}
            findings.append({
                "severity": "info",
                "cvss_score": 0.0,
                "title": "IP Geolocation",
                "description": f"IP: {ip} - Geolocation lookup returned no data.",
                "affected_url": url,
                "recommendation": "IP may be private or lookup service unavailable.",
                "category": "IP & Location"
            })
    except Exception as e:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "IP Geolocation Failed",
            "description": f"Could not resolve IP or geolocate: {str(e)[:100]}",
            "affected_url": url,
            "recommendation": "Verify domain resolves correctly.",
            "category": "IP & Location"
        })
    return findings, geo_detail


def check_subdomains(url):
    findings = []
    found_subdomains = []
    domain = get_domain(url)
    base_domain = domain.replace('www.', '')

    def resolve_sub(sub):
        subdomain = f"{sub}.{base_domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            return {'subdomain': subdomain, 'ip': ip}
        except:
            return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(resolve_sub, sub): sub for sub in COMMON_SUBDOMAINS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found_subdomains.append(result)

    found_subdomains.sort(key=lambda x: x['subdomain'])

    if found_subdomains:
        sub_list = ', '.join(s['subdomain'] for s in found_subdomains[:15])
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": f"Subdomains Found ({len(found_subdomains)})",
            "description": f"Discovered {len(found_subdomains)} subdomains: {sub_list}",
            "affected_url": url,
            "recommendation": "Review all subdomains for security. Ensure unused subdomains are decommissioned.",
            "category": "Subdomain Enumeration"
        })

        # Check for potentially dangerous subdomains
        risky_subs = [s for s in found_subdomains if any(
            k in s['subdomain'] for k in ['admin', 'staging', 'dev', 'test', 'jenkins', 'git', 'jira']
        )]
        if risky_subs:
            findings.append({
                "severity": "medium",
                "cvss_score": 4.3,
                "title": "Sensitive Subdomains Exposed",
                "description": f"Potentially sensitive subdomains: {', '.join(s['subdomain'] for s in risky_subs)}",
                "affected_url": url,
                "recommendation": "Restrict access to admin/dev/staging subdomains. Use VPN or IP whitelisting.",
                "category": "Subdomain Enumeration"
            })
    else:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "No Subdomains Found",
            "description": f"Checked {len(COMMON_SUBDOMAINS)} common subdomain prefixes. None resolved.",
            "affected_url": url,
            "recommendation": "No action needed.",
            "category": "Subdomain Enumeration"
        })

    return findings, found_subdomains


def check_content_analysis(url):
    findings = []
    content_detail = {}
    try:
        r = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}, verify=False)
        soup = BeautifulSoup(r.text, 'html.parser')
        domain = get_domain(url)

        # Extract meta info
        title = soup.title.string.strip() if soup.title and soup.title.string else ''
        meta_desc = ''
        meta_kw = ''
        desc_tag = soup.find('meta', attrs={'name': re.compile(r'description', re.I)})
        if desc_tag and desc_tag.get('content'):
            meta_desc = desc_tag['content']
        kw_tag = soup.find('meta', attrs={'name': re.compile(r'keywords', re.I)})
        if kw_tag and kw_tag.get('content'):
            meta_kw = kw_tag['content']

        h1_tags = [h.get_text(strip=True) for h in soup.find_all('h1')][:5]
        h2_tags = [h.get_text(strip=True) for h in soup.find_all('h2')][:10]

        all_links = soup.find_all('a', href=True)
        internal_links = []
        external_links = []
        for link in all_links:
            href = link.get('href', '')
            if href.startswith(('http://', 'https://')):
                link_domain = urlparse(href).hostname
                if link_domain and link_domain != domain and not link_domain.endswith('.' + domain):
                    external_links.append(href)
                else:
                    internal_links.append(href)
            elif href.startswith('/') or href.startswith('#'):
                internal_links.append(href)

        contact_emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', r.text)
        phone_numbers = re.findall(r'[\+\(]?[1-9][0-9 .\-\(\)]{8,}[0-9]', r.text)[:10]

        content_detail = {
            'title': title,
            'meta_description': meta_desc[:200],
            'meta_keywords': meta_kw[:200],
            'h1_tags': h1_tags,
            'h2_tags': h2_tags,
            'total_links': len(all_links),
            'internal_links': len(internal_links),
            'external_links': len(external_links),
            'images': len(soup.find_all('img')),
            'scripts': len(soup.find_all('script')),
            'word_count': len(r.text.split()),
            'page_size_kb': round(len(r.content) / 1024, 1),
            'contact_emails': list(set(contact_emails))[:10],
            'phone_numbers': list(set(phone_numbers))[:10],
        }

        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "Content Analysis",
            "description": f"Title: '{title}' | {content_detail['word_count']} words | {content_detail['total_links']} links ({content_detail['internal_links']} internal, {content_detail['external_links']} external) | {content_detail['images']} images | {content_detail['page_size_kb']}KB",
            "affected_url": url,
            "recommendation": "Review page content for sensitive information exposure.",
            "category": "Content Analysis"
        })

        if not title:
            findings.append({
                "severity": "low",
                "cvss_score": 1.0,
                "title": "Missing Page Title",
                "description": "The page has no <title> tag set.",
                "affected_url": url,
                "recommendation": "Add a descriptive title tag for SEO and accessibility.",
                "category": "Content Analysis"
            })

    except Exception as e:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "Content Analysis Failed",
            "description": f"Could not analyze page content: {str(e)[:100]}",
            "affected_url": url,
            "recommendation": "Verify URL accessibility.",
            "category": "Content Analysis"
        })
    return findings, content_detail


def check_performance(url):
    findings = []
    perf_detail = {}
    try:
        start = time.time()
        r = requests.get(url, timeout=15, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
        load_time = time.time() - start

        perf_detail = {
            'load_time_seconds': round(load_time, 2),
            'response_size_kb': round(len(r.content) / 1024, 1),
            'status_code': r.status_code,
            'server_timing': r.headers.get('Server-Timing', 'N/A'),
            'cache_control': r.headers.get('Cache-Control', 'None'),
            'cdn_detected': 'cloudflare' in str(r.headers).lower() or 'cf-ray' in r.headers,
            'content_encoding': r.headers.get('Content-Encoding', 'None'),
            'transfer_encoding': r.headers.get('Transfer-Encoding', 'N/A'),
        }

        if perf_detail['cdn_detected']:
            perf_detail['cdn_provider'] = 'Cloudflare'
        elif 'x-amz' in str(r.headers).lower():
            perf_detail['cdn_detected'] = True
            perf_detail['cdn_provider'] = 'AWS CloudFront'
        elif 'x-served-by' in r.headers:
            perf_detail['cdn_detected'] = True
            perf_detail['cdn_provider'] = 'Fastly/Other'

        if load_time > 5:
            findings.append({
                "severity": "medium",
                "cvss_score": 3.0,
                "title": "Slow Page Load",
                "description": f"Page took {perf_detail['load_time_seconds']}s to load ({perf_detail['response_size_kb']}KB). This may indicate server performance issues.",
                "affected_url": url,
                "recommendation": "Optimize server response time. Consider using a CDN, enabling compression, and caching.",
                "category": "Performance"
            })
        elif load_time > 3:
            findings.append({
                "severity": "low",
                "cvss_score": 1.0,
                "title": "Moderate Page Load Time",
                "description": f"Page load: {perf_detail['load_time_seconds']}s | Size: {perf_detail['response_size_kb']}KB | CDN: {'Yes' if perf_detail['cdn_detected'] else 'No'}",
                "affected_url": url,
                "recommendation": "Page performance is acceptable but could be improved.",
                "category": "Performance"
            })
        else:
            findings.append({
                "severity": "info",
                "cvss_score": 0.0,
                "title": "Good Performance",
                "description": f"Load time: {perf_detail['load_time_seconds']}s | Size: {perf_detail['response_size_kb']}KB | CDN: {'Yes (' + perf_detail.get('cdn_provider', '') + ')' if perf_detail['cdn_detected'] else 'No'} | Cache: {perf_detail['cache_control']}",
                "affected_url": url,
                "recommendation": "Performance is good. Continue monitoring.",
                "category": "Performance"
            })

        if perf_detail['content_encoding'] == 'None' and perf_detail['response_size_kb'] > 50:
            findings.append({
                "severity": "low",
                "cvss_score": 1.0,
                "title": "No Compression Detected",
                "description": f"Response is {perf_detail['response_size_kb']}KB without compression (gzip/brotli).",
                "affected_url": url,
                "recommendation": "Enable gzip or brotli compression to reduce transfer size.",
                "category": "Performance"
            })

    except Exception as e:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "Performance Check Failed",
            "description": f"Could not measure performance: {str(e)[:100]}",
            "affected_url": url,
            "recommendation": "Verify URL accessibility.",
            "category": "Performance"
        })
    return findings, perf_detail


def check_email_security(url):
    findings = []
    email_sec_detail = {}
    domain = get_domain(url)
    base_domain = domain.replace('www.', '')

    # MX Records
    try:
        mx = dns.resolver.resolve(base_domain, 'MX')
        email_sec_detail['mx_records'] = [str(r.exchange) for r in mx]
    except:
        email_sec_detail['mx_records'] = []

    # SPF
    try:
        txt = dns.resolver.resolve(base_domain, 'TXT')
        spf = [str(r) for r in txt if 'v=spf1' in str(r)]
        email_sec_detail['spf'] = spf[0] if spf else None
    except:
        email_sec_detail['spf'] = None

    # DMARC
    try:
        dmarc = dns.resolver.resolve(f'_dmarc.{base_domain}', 'TXT')
        email_sec_detail['dmarc'] = str(list(dmarc)[0])
    except:
        email_sec_detail['dmarc'] = None

    # Analyze results
    if not email_sec_detail['mx_records']:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "No MX Records",
            "description": f"No MX records found for {base_domain}. Domain may not receive email.",
            "affected_url": url,
            "recommendation": "If email is needed, configure MX records.",
            "category": "Email Security"
        })
    else:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": f"MX Records ({len(email_sec_detail['mx_records'])})",
            "description": f"Mail servers: {', '.join(email_sec_detail['mx_records'][:5])}",
            "affected_url": url,
            "recommendation": "Verify MX records point to legitimate mail servers.",
            "category": "Email Security"
        })

    if not email_sec_detail['spf']:
        findings.append({
            "severity": "medium",
            "cvss_score": 5.0,
            "title": "Missing SPF Record",
            "description": f"No SPF record found for {base_domain}. Email spoofing is possible.",
            "affected_url": url,
            "recommendation": "Add SPF record: v=spf1 include:_spf.google.com ~all (adjust for your mail provider).",
            "category": "Email Security"
        })
    else:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "SPF Record Present",
            "description": f"SPF: {email_sec_detail['spf'][:150]}",
            "affected_url": url,
            "recommendation": "Verify SPF includes all legitimate sending sources.",
            "category": "Email Security"
        })

    if not email_sec_detail['dmarc']:
        findings.append({
            "severity": "medium",
            "cvss_score": 5.0,
            "title": "Missing DMARC Record",
            "description": f"No DMARC record found for {base_domain}. Domain is vulnerable to email spoofing/phishing.",
            "affected_url": url,
            "recommendation": "Add DMARC record: _dmarc.domain.com TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@domain.com\"",
            "category": "Email Security"
        })
    else:
        # Check DMARC policy
        dmarc_val = email_sec_detail['dmarc']
        if 'p=none' in dmarc_val:
            findings.append({
                "severity": "low",
                "cvss_score": 3.0,
                "title": "DMARC Policy Set to None",
                "description": f"DMARC record exists but policy is 'none' (monitoring only): {dmarc_val[:150]}",
                "affected_url": url,
                "recommendation": "Upgrade DMARC policy to 'quarantine' or 'reject' for active protection.",
                "category": "Email Security"
            })
        else:
            findings.append({
                "severity": "info",
                "cvss_score": 0.0,
                "title": "DMARC Record Present",
                "description": f"DMARC: {dmarc_val[:150]}",
                "affected_url": url,
                "recommendation": "DMARC is configured. Monitor reports for issues.",
                "category": "Email Security"
            })

    return findings, email_sec_detail


def check_http_methods(url):
    findings = []
    methods_detail = []

    for method in DANGEROUS_METHODS:
        try:
            r = requests.request(method, url, timeout=5, verify=False)
            if r.status_code not in [405, 501, 404]:
                methods_detail.append({'method': method, 'status': r.status_code})
        except:
            pass

    if methods_detail:
        dangerous = [m for m in methods_detail if m['method'] in ['TRACE', 'TRACK', 'PUT', 'DELETE']]
        if dangerous:
            findings.append({
                "severity": "medium",
                "cvss_score": 5.3,
                "title": "Dangerous HTTP Methods Allowed",
                "description": f"Server allows potentially dangerous methods: {', '.join(m['method'] + '(' + str(m['status']) + ')' for m in dangerous)}",
                "affected_url": url,
                "recommendation": "Disable TRACE, TRACK, PUT, DELETE methods unless explicitly needed. Configure web server to reject these.",
                "category": "HTTP Methods"
            })
        else:
            findings.append({
                "severity": "info",
                "cvss_score": 0.0,
                "title": "HTTP Methods Check",
                "description": f"Non-standard methods allowed: {', '.join(m['method'] + '(' + str(m['status']) + ')' for m in methods_detail)}",
                "affected_url": url,
                "recommendation": "Review if all allowed methods are necessary.",
                "category": "HTTP Methods"
            })
    else:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "HTTP Methods Properly Restricted",
            "description": "Server correctly rejects dangerous HTTP methods (TRACE, TRACK, PUT, DELETE, PATCH, OPTIONS).",
            "affected_url": url,
            "recommendation": "Good practice - methods properly restricted.",
            "category": "HTTP Methods"
        })

    return findings, methods_detail


def check_social_presence(url):
    findings = []
    presence_detail = {}
    domain = get_domain(url)
    brand = domain.replace('www.', '').split('.')[0]

    platforms = {
        'twitter': f'https://twitter.com/{brand}',
        'facebook': f'https://facebook.com/{brand}',
        'instagram': f'https://instagram.com/{brand}',
        'linkedin': f'https://linkedin.com/company/{brand}',
        'github': f'https://github.com/{brand}',
        'youtube': f'https://youtube.com/@{brand}',
    }

    def check_platform(platform_info):
        platform, check_url = platform_info
        try:
            r = requests.head(check_url, timeout=5, allow_redirects=True,
                            headers={'User-Agent': 'Mozilla/5.0'})
            return platform, {'url': check_url, 'status': r.status_code, 'exists': r.status_code == 200}
        except:
            return platform, {'url': check_url, 'status': 0, 'exists': False}

    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = [executor.submit(check_platform, item) for item in platforms.items()]
        for future in as_completed(futures):
            platform, result = future.result()
            presence_detail[platform] = result

    found = [p for p, info in presence_detail.items() if info['exists']]
    not_found = [p for p, info in presence_detail.items() if not info['exists']]

    if found:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": f"Social Media Presence ({len(found)}/{len(platforms)})",
            "description": f"Brand '{brand}' found on: {', '.join(found)}. Not found: {', '.join(not_found) if not_found else 'None'}",
            "affected_url": url,
            "recommendation": "Verify these are your official accounts. Claim unclaimed profiles to prevent impersonation.",
            "category": "Social Presence"
        })
    else:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "No Social Media Presence Detected",
            "description": f"Brand '{brand}' not found on any checked platforms ({', '.join(platforms.keys())})",
            "affected_url": url,
            "recommendation": "Consider registering brand names on major platforms to prevent impersonation.",
            "category": "Social Presence"
        })

    return findings, presence_detail


def check_wayback(url):
    findings = []
    wayback_detail = {}
    domain = get_domain(url)
    base = domain.replace('www.', '')
    try:
        r = requests.get(f'http://archive.org/wayback/available?url={base}', timeout=8)
        data = r.json()
        snapshot = data.get('archived_snapshots', {}).get('closest', {})
        wayback_detail = {
            'available': snapshot.get('available', False),
            'url': snapshot.get('url', ''),
            'timestamp': snapshot.get('timestamp', ''),
            'status': snapshot.get('status', ''),
        }

        if wayback_detail['available']:
            ts = wayback_detail['timestamp']
            formatted_date = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts
            findings.append({
                "severity": "info",
                "cvss_score": 0.0,
                "title": "Wayback Machine Archive Found",
                "description": f"Site is archived. Latest snapshot: {formatted_date}. Archive URL: {wayback_detail['url'][:100]}",
                "affected_url": url,
                "recommendation": "Review archived versions for accidentally exposed sensitive information.",
                "category": "Archive History"
            })
        else:
            findings.append({
                "severity": "info",
                "cvss_score": 0.0,
                "title": "No Wayback Machine Archive",
                "description": "No archived snapshots found on the Wayback Machine.",
                "affected_url": url,
                "recommendation": "No action needed.",
                "category": "Archive History"
            })
    except Exception as e:
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "Wayback Machine Check Failed",
            "description": f"Could not query Wayback Machine: {str(e)[:100]}",
            "affected_url": url,
            "recommendation": "Service may be temporarily unavailable.",
            "category": "Archive History"
        })
        wayback_detail = {'available': False}
    return findings, wayback_detail


# ===================== CVE DATABASE CHECK =====================

def check_cve(tech_detail):
    """Check detected versions against known CVEs"""
    CVE_DB = {
        'php/7.3': ['CVE-2021-21703', 'CVE-2022-31625', 'CVE-2022-31626'],
        'php/7.4': ['CVE-2022-31625', 'CVE-2022-31626'],
        'php/8.0': ['CVE-2022-31625'],
        'apache/2.4.49': ['CVE-2021-41773', 'CVE-2021-42013'],
        'apache/2.4.50': ['CVE-2021-42013'],
        'apache/2.4.51': ['CVE-2021-44790'],
        'openssl/1.0': ['CVE-2016-0800', 'CVE-2014-0160'],
        'openssl/1.1.0': ['CVE-2017-3735', 'CVE-2017-3736'],
        'wordpress/5.0': ['CVE-2019-8942', 'CVE-2019-8943'],
        'wordpress/5.1': ['CVE-2019-8942'],
        'wordpress/5.2': ['CVE-2019-17671', 'CVE-2019-17672'],
        'jquery/1.': ['CVE-2020-11022', 'CVE-2020-11023', 'CVE-2015-9251'],
        'jquery/2.': ['CVE-2020-11022', 'CVE-2020-11023'],
        'jquery/3.0': ['CVE-2020-11022', 'CVE-2020-11023'],
        'jquery/3.1': ['CVE-2020-11022', 'CVE-2020-11023'],
        'jquery/3.2': ['CVE-2020-11022', 'CVE-2020-11023'],
        'jquery/3.3': ['CVE-2020-11022', 'CVE-2020-11023'],
        'jquery/3.4': ['CVE-2020-11022', 'CVE-2020-11023'],
        'angular/1.': ['CVE-2020-7676', 'CVE-2019-14863'],
        'nginx/1.14': ['CVE-2019-9511', 'CVE-2019-9513', 'CVE-2019-9516'],
        'nginx/1.16': ['CVE-2019-9511', 'CVE-2019-9516'],
        'iis/7.5': ['CVE-2017-7269', 'CVE-2014-4078'],
        'iis/8.0': ['CVE-2014-4078'],
    }
    findings = []

    # Build tech_stack from tech_detail
    tech_stack = {}
    if tech_detail.get('php_version'):
        tech_stack['PHP'] = tech_detail['php_version']
    if tech_detail.get('server'):
        server = tech_detail['server']
        # Extract Apache version
        import re as _re
        apache_match = _re.search(r'Apache[/ ]?([\d.]+)', server)
        if apache_match:
            tech_stack['Apache'] = apache_match.group(1)
        nginx_match = _re.search(r'nginx[/ ]?([\d.]+)', server)
        if nginx_match:
            tech_stack['nginx'] = nginx_match.group(1)
        iis_match = _re.search(r'IIS[/ ]?([\d.]+)', server, _re.IGNORECASE)
        if iis_match:
            tech_stack['IIS'] = iis_match.group(1)
    if tech_detail.get('cms_version') and tech_detail.get('cms'):
        tech_stack[tech_detail['cms']] = tech_detail['cms_version']
    if tech_detail.get('jquery_version'):
        tech_stack['jQuery'] = tech_detail['jquery_version']
    if tech_detail.get('angular_version'):
        tech_stack['Angular'] = tech_detail['angular_version']
    if tech_detail.get('powered_by'):
        openssl_match = re.search(r'OpenSSL[/ ]?([\d.]+)', tech_detail['powered_by'])
        if openssl_match:
            tech_stack['OpenSSL'] = openssl_match.group(1)

    for tech, version in tech_stack.items():
        key = f"{tech.lower()}/{version.lower()}"
        for db_key, cves in CVE_DB.items():
            if db_key in key or key.startswith(db_key):
                findings.append({
                    'severity': 'critical',
                    'cvss_score': 9.8,
                    'title': f'{tech} {version} - Known CVEs Detected',
                    'description': f'Detected {tech} version {version} has {len(cves)} known CVE(s): {", ".join(cves)}',
                    'affected_url': '',
                    'recommendation': f'Upgrade {tech} to the latest stable version immediately. Known vulnerabilities: {", ".join(cves)}',
                    'category': 'CVE Database',
                    'cves': cves,
                    'software': tech,
                    'version': version
                })
                break

    return findings


# ===================== REPUTATION CHECK =====================

def check_reputation(domain):
    """Check domain reputation via urlscan.io and Google Safe Browsing transparency"""
    findings = []
    reputation_detail = {}
    try:
        # urlscan.io submission (free, no key needed for public scans)
        try:
            headers = {'Content-Type': 'application/json'}
            r = requests.post('https://urlscan.io/api/v1/scan/',
                headers=headers,
                json={'url': f'https://{domain}', 'visibility': 'public'},
                timeout=10)
            reputation_detail['urlscan_submitted'] = r.status_code == 200
            if r.status_code == 200:
                reputation_detail['urlscan_uuid'] = r.json().get('uuid', '')
                reputation_detail['urlscan_url'] = r.json().get('result', '')
        except Exception:
            reputation_detail['urlscan_submitted'] = False

        # Google Safe Browsing Transparency Report (public endpoint)
        try:
            gsb = requests.get(
                f'https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status?site={domain}',
                timeout=8)
            if gsb.status_code == 200:
                text_lower = gsb.text.lower()
                if 'no unsafe content found' in text_lower or 'no available data' in text_lower:
                    reputation_detail['google_safe_browsing'] = 'clean'
                elif 'unsafe' in text_lower or 'dangerous' in text_lower:
                    reputation_detail['google_safe_browsing'] = 'flagged'
                else:
                    reputation_detail['google_safe_browsing'] = 'unknown'
            else:
                reputation_detail['google_safe_browsing'] = 'check_failed'
        except Exception:
            reputation_detail['google_safe_browsing'] = 'check_failed'

        # Determine severity
        gsb_status = reputation_detail.get('google_safe_browsing', 'unknown')
        if gsb_status == 'flagged':
            findings.append({
                "severity": "critical",
                "cvss_score": 9.0,
                "title": "Domain Flagged by Google Safe Browsing",
                "description": f"Domain {domain} has been flagged as potentially unsafe by Google Safe Browsing.",
                "affected_url": f"https://{domain}",
                "recommendation": "Investigate and remediate any malicious content. Request review from Google Search Console.",
                "category": "Reputation"
            })
        else:
            findings.append({
                "severity": "info",
                "cvss_score": 0.0,
                "title": "Domain Reputation Check",
                "description": f"Google Safe Browsing: {gsb_status}. URLScan submitted: {reputation_detail.get('urlscan_submitted', False)}.",
                "affected_url": f"https://{domain}",
                "recommendation": "Continue monitoring domain reputation regularly.",
                "category": "Reputation"
            })

    except Exception as e:
        reputation_detail['error'] = str(e)[:100]
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "Reputation Check Failed",
            "description": f"Could not complete reputation check: {str(e)[:100]}",
            "affected_url": f"https://{domain}",
            "recommendation": "Manually verify domain reputation.",
            "category": "Reputation"
        })

    return findings, reputation_detail


# ===================== CERTIFICATE TRANSPARENCY LOGS =====================

def check_cert_transparency(domain):
    """Find subdomains and certificates via Certificate Transparency logs (crt.sh)"""
    findings = []
    ct_detail = {}
    try:
        base = domain.replace('www.', '')
        r = requests.get(f'https://crt.sh/?q=%.{base}&output=json', timeout=15)
        if r.status_code == 200:
            certs = r.json()
            subdomains = set()
            for cert in certs[:100]:
                name = cert.get('name_value', '')
                for sub in name.split('\n'):
                    sub = sub.strip().replace('*.', '')
                    if base in sub and sub != base:
                        subdomains.add(sub)

            ct_detail = {
                'total_certs': len(certs),
                'subdomains_found': sorted(list(subdomains))[:30],
                'subdomains_count': len(subdomains),
                'earliest_cert': certs[-1].get('not_before', '') if certs else '',
                'latest_cert': certs[0].get('not_before', '') if certs else '',
            }

            if subdomains:
                findings.append({
                    "severity": "info",
                    "cvss_score": 0.0,
                    "title": f"Certificate Transparency: {len(subdomains)} Subdomains Found",
                    "description": f"Found {len(subdomains)} unique subdomains via CT logs from {len(certs)} certificates. Latest cert: {ct_detail['latest_cert']}",
                    "affected_url": f"https://{domain}",
                    "recommendation": "Review CT-discovered subdomains. Ensure all are intentional and properly secured.",
                    "category": "Certificate Transparency"
                })
            else:
                findings.append({
                    "severity": "info",
                    "cvss_score": 0.0,
                    "title": "Certificate Transparency: No Extra Subdomains",
                    "description": f"Found {len(certs)} certificates but no additional subdomains via CT logs.",
                    "affected_url": f"https://{domain}",
                    "recommendation": "No action needed.",
                    "category": "Certificate Transparency"
                })
        else:
            ct_detail = {'error': f'crt.sh returned status {r.status_code}'}
            findings.append({
                "severity": "info",
                "cvss_score": 0.0,
                "title": "Certificate Transparency Check Failed",
                "description": f"crt.sh returned HTTP {r.status_code}.",
                "affected_url": f"https://{domain}",
                "recommendation": "crt.sh may be temporarily unavailable. Try again later.",
                "category": "Certificate Transparency"
            })
    except Exception as e:
        ct_detail = {'error': str(e)[:100]}
        findings.append({
            "severity": "info",
            "cvss_score": 0.0,
            "title": "Certificate Transparency Check Failed",
            "description": f"Error querying CT logs: {str(e)[:100]}",
            "affected_url": f"https://{domain}",
            "recommendation": "crt.sh may be temporarily unavailable.",
            "category": "Certificate Transparency"
        })

    return findings, ct_detail


# ===================== MAIN SCAN FUNCTION =====================

def run_scan(url):
    url = normalize_url(url)
    scan_id = str(uuid.uuid4())
    start_time = time.time()

    all_findings = []
    details = {
        "headers_detail": {},
        "ssl_detail": {},
        "tech_list": [],
        "tech_detail": {},
        "exposed_files": [],
        "dns_detail": {},
        "open_ports": [],
        "emails": [],
        "social_links": {},
        "external_domains": [],
        "forms": [],
        "javascript": [],
        # New detail sections
        "whois_detail": {},
        "geo_detail": {},
        "subdomains": [],
        "content_detail": {},
        "performance_detail": {},
        "email_security": {},
        "http_methods": [],
        "social_presence": {},
        "wayback_detail": {},
        # v4.0 additions
        "reputation_detail": {},
        "ct_detail": {},
        "cve_findings": [],
    }

    # Run checks that return (findings, detail)
    def run_headers():
        f, d = check_security_headers(url)
        return "Security Headers", f, ("headers_detail", d)

    def run_ssl():
        f, d = check_ssl_tls(url)
        return "SSL/TLS", f, ("ssl_detail", d)

    def run_tech():
        f, tl, td = check_technology_stack(url)
        return "Technology Detection", f, ("tech", (tl, td))

    def run_exposed():
        f, d = check_exposed_files(url)
        return "Exposed Files", f, ("exposed_files", d)

    def run_dns():
        f, d = check_dns_info(url)
        return "DNS", f, ("dns_detail", d)

    def run_robots():
        f = check_robots_txt(url)
        return "Robots.txt", f, None

    def run_cookies():
        f = check_cookies(url)
        return "Cookies", f, None

    def run_cors():
        f = check_cors(url)
        return "CORS", f, None

    def run_server():
        f = check_server_disclosure(url)
        return "Server Disclosure", f, None

    def run_ports():
        f, d = check_ports(url)
        return "Port Scan", f, ("open_ports", d)

    def run_emails():
        f, d = check_emails(url)
        return "Email Harvesting", f, ("emails", d)

    def run_social():
        f, d = check_social_media(url)
        return "Social Media", f, ("social_links", d)

    def run_external():
        f, d = check_external_links(url)
        return "External Links", f, ("external_domains", d)

    def run_forms():
        f, d = check_forms(url)
        return "Form Analysis", f, ("forms", d)

    def run_js():
        f, d = check_javascript(url)
        return "JavaScript Analysis", f, ("javascript", d)

    # New module runners
    def run_whois():
        f, d = check_whois_info(url)
        return "WHOIS", f, ("whois_detail", d)

    def run_geo():
        f, d = check_ip_geolocation(url)
        return "IP Geolocation", f, ("geo_detail", d)

    def run_subdomains():
        f, d = check_subdomains(url)
        return "Subdomain Enumeration", f, ("subdomains", d)

    def run_content():
        f, d = check_content_analysis(url)
        return "Content Analysis", f, ("content_detail", d)

    def run_performance():
        f, d = check_performance(url)
        return "Performance", f, ("performance_detail", d)

    def run_email_security():
        f, d = check_email_security(url)
        return "Email Security", f, ("email_security", d)

    def run_http_methods():
        f, d = check_http_methods(url)
        return "HTTP Methods", f, ("http_methods", d)

    def run_social_presence():
        f, d = check_social_presence(url)
        return "Social Presence", f, ("social_presence", d)


    def run_wayback():
        f, d = check_wayback(url)
        return "Wayback Machine", f, ("wayback_detail", d)

    def run_reputation():
        domain = get_domain(url)
        f, d = check_reputation(domain)
        return "Reputation", f, ("reputation_detail", d)

    def run_ct():
        domain = get_domain(url)
        f, d = check_cert_transparency(domain)
        return "Certificate Transparency", f, ("ct_detail", d)

    checks = [
        run_headers, run_ssl, run_tech, run_exposed, run_dns,
        run_robots, run_cookies, run_cors, run_server,
        run_ports, run_emails, run_social, run_external,
        run_forms, run_js,
        # New modules
        run_whois, run_geo, run_subdomains, run_content,
        run_performance, run_email_security, run_http_methods,
        run_social_presence, run_wayback,
        # v4.0 modules
        run_reputation, run_ct,
    ]

    progress = []

    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = {executor.submit(func): func.__name__ for func in checks}

        for future in as_completed(futures):
            func_name = futures[future]
            try:
                result = future.result(timeout=45)
                check_name, findings, detail_info = result
                all_findings.extend(findings)
                progress.append({"check": check_name, "status": "done", "findings": len(findings)})

                if detail_info:
                    key = detail_info[0]
                    value = detail_info[1]
                    if key == "tech":
                        details["tech_list"] = value[0]
                        details["tech_detail"] = value[1]
                    else:
                        details[key] = value

            except Exception as e:
                progress.append({"check": func_name, "status": "error", "error": str(e)[:100]})

    # Post-processing: CVE check based on detected tech
    try:
        cve_findings = check_cve(details.get("tech_detail", {}))
        if cve_findings:
            all_findings.extend(cve_findings)
            details["cve_findings"] = cve_findings
            progress.append({"check": "CVE Database", "status": "done", "findings": len(cve_findings)})
    except Exception:
        pass

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
        "details": details,
        "progress": progress,
        "paths_checked": len(EXPOSED_FILES),
        "modules_count": len(checks),
    }

    return report
