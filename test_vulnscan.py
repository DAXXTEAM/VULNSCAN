import pytest
import json
import sys
sys.path.insert(0, '/root/workspace/vulnscan')

from app import app
from scanner import normalize_url, get_domain, run_scan
from report import generate_html_report


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normalize_url():
    assert normalize_url("example.com") == "https://example.com"
    assert normalize_url("http://example.com") == "http://example.com"
    assert normalize_url("https://example.com/") == "https://example.com"


def test_get_domain():
    assert get_domain("https://www.google.com/path") == "www.google.com"
    assert get_domain("http://example.com:8080") == "example.com"


def test_index_page(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"VULNSCAN" in resp.data


def test_scan_missing_url(client):
    resp = client.post("/scan", json={})
    assert resp.status_code == 400
    data = json.loads(resp.data)
    assert "error" in data


def test_scan_empty_url(client):
    resp = client.post("/scan", json={"url": ""})
    assert resp.status_code == 400


def test_scan_valid_url(client):
    resp = client.post("/scan", json={"url": "https://www.google.com"})
    assert resp.status_code in (200, 202)
    data = json.loads(resp.data)
    assert "scan_id" in data


def test_scan_result_structure(client):
    resp = client.post("/scan", json={"url": "https://httpbin.org"})
    data = json.loads(resp.data)
    if resp.status_code == 200:
        assert "findings" in data
        assert "stats" in data
        assert "risk_level" in data
        assert "max_cvss" in data
        assert "duration_seconds" in data
        assert isinstance(data["findings"], list)
        if data["findings"]:
            f = data["findings"][0]
            assert "severity" in f
            assert "cvss_score" in f
            assert "title" in f
            assert "description" in f
            assert "affected_url" in f
            assert "recommendation" in f


def test_report_not_found(client):
    resp = client.get("/report/nonexistent-id")
    assert resp.status_code == 404


def test_report_generation(client):
    resp = client.post("/scan", json={"url": "https://www.google.com"})
    data = json.loads(resp.data)
    if "scan_id" in data and "findings" in data:
        report_resp = client.get(f"/report/{data['scan_id']}")
        assert report_resp.status_code == 200
        assert b"VULNSCAN" in report_resp.data
        assert b"Executive Summary" in report_resp.data


def test_generate_html_report_function():
    mock_result = {
        "scan_id": "test-123",
        "target": "https://example.com",
        "scan_date": "2026-08-14T12:00:00Z",
        "duration_seconds": 2.5,
        "risk_level": "MEDIUM",
        "max_cvss": 5.3,
        "stats": {"critical": 0, "high": 0, "medium": 2, "low": 1, "info": 3},
        "total_findings": 6,
        "findings": [
            {
                "severity": "medium",
                "cvss_score": 5.3,
                "title": "Test Finding",
                "description": "Test description",
                "affected_url": "https://example.com",
                "recommendation": "Test fix",
                "category": "Test"
            }
        ]
    }
    html = generate_html_report(mock_result)
    assert "VULNSCAN" in html
    assert "Executive Summary" in html
    assert "Test Finding" in html
    assert "MEDIUM" in html


def test_run_scan_returns_complete_report():
    result = run_scan("https://www.google.com")
    assert "scan_id" in result
    assert "target" in result
    assert "findings" in result
    assert "stats" in result
    assert result["target"] == "https://www.google.com"
    assert len(result["findings"]) > 0
