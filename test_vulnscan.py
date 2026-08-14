import pytest
import json
import sys
sys.path.insert(0, '/root/workspace/vulnscan')

from scanner import (
    normalize_url, get_domain, EXPOSED_FILES, SECURITY_HEADERS,
    check_security_headers, check_ssl_tls, check_technology_stack,
    check_exposed_files, check_ports, check_emails, check_social_media,
    check_external_links, check_forms, check_javascript, run_scan,
    HIGH_SEVERITY_PATHS, COMMON_PORTS
)
from app import app


class TestScanner:
    def test_normalize_url_https(self):
        assert normalize_url("example.com") == "https://example.com"
        assert normalize_url("http://example.com/") == "http://example.com"
        assert normalize_url("https://example.com") == "https://example.com"

    def test_get_domain(self):
        assert get_domain("https://example.com/path") == "example.com"
        assert get_domain("http://sub.example.com") == "sub.example.com"

    def test_exposed_files_count(self):
        assert len(EXPOSED_FILES) >= 100

    def test_high_severity_paths_subset(self):
        for path in HIGH_SEVERITY_PATHS:
            assert path in EXPOSED_FILES, f"{path} not in EXPOSED_FILES"

    def test_security_headers_count(self):
        assert len(SECURITY_HEADERS) == 7
        assert "Strict-Transport-Security" in SECURITY_HEADERS
        assert "Content-Security-Policy" in SECURITY_HEADERS
        assert "X-Frame-Options" in SECURITY_HEADERS

    def test_security_headers_have_expected(self):
        for name, info in SECURITY_HEADERS.items():
            assert "expected" in info
            assert "fix" in info
            assert "severity" in info

    def test_common_ports(self):
        assert 80 in COMMON_PORTS
        assert 443 in COMMON_PORTS
        assert 8080 in COMMON_PORTS
        assert 3000 in COMMON_PORTS

    def test_run_scan_structure(self):
        # Quick test with a non-existent domain to verify structure
        result = run_scan("https://thisdomaindoesnotexist12345.com")
        assert "scan_id" in result
        assert "target" in result
        assert "stats" in result
        assert "findings" in result
        assert "details" in result
        assert "duration_seconds" in result
        assert "risk_level" in result
        assert "paths_checked" in result
        # Check details has all expected keys
        details = result["details"]
        assert "headers_detail" in details
        assert "ssl_detail" in details
        assert "tech_list" in details
        assert "tech_detail" in details
        assert "exposed_files" in details
        assert "open_ports" in details
        assert "emails" in details
        assert "social_links" in details
        assert "external_domains" in details
        assert "forms" in details
        assert "javascript" in details


class TestApp:
    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client

    def test_index_page(self, client):
        resp = client.get('/')
        assert resp.status_code == 200
        assert b'VULNSCAN' in resp.data
        assert b'100+ Checks' in resp.data

    def test_scan_endpoint_missing_url(self, client):
        resp = client.post('/scan', json={})
        assert resp.status_code == 400

    def test_scan_endpoint_empty_url(self, client):
        resp = client.post('/scan', json={"url": ""})
        assert resp.status_code == 400

    def test_scan_details_not_found(self, client):
        resp = client.get('/scan/nonexistent-id/details')
        assert resp.status_code == 404

    def test_scan_status_not_found(self, client):
        resp = client.get('/scan/nonexistent-id/status')
        assert resp.status_code == 404

    def test_report_not_found(self, client):
        resp = client.get('/report/nonexistent-id')
        assert resp.status_code == 404


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
