"""Tests for the PDF download feature addition."""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import pytest
from unittest.mock import patch, MagicMock
from app import app, scan_results


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def sample_scan_data():
    """Minimal scan result for testing."""
    return {
        "scan_id": "test-1234-5678-abcd-efgh",
        "target": "https://example.com",
        "findings": [
            {
                "title": "Missing X-Frame-Options",
                "severity": "medium",
                "cvss_score": 5.0,
                "category": "Headers",
                "description": "X-Frame-Options header not set",
                "recommendation": "Add X-Frame-Options: DENY",
                "affected_url": "https://example.com"
            }
        ],
        "stats": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
        "risk_level": "MEDIUM",
        "max_cvss": 5.0,
        "total_findings": 1,
        "duration_seconds": 10,
        "modules_count": 24,
        "scan_date": "2026-08-15T00:00:00Z",
        "details": {}
    }


def test_pdf_endpoint_exists(client):
    """Test that /report/<scan_id>/pdf route exists (returns 404 for missing scan)."""
    resp = client.get('/report/nonexistent-id/pdf')
    assert resp.status_code == 404


def test_pdf_endpoint_with_scan_data(client, sample_scan_data):
    """Test PDF endpoint with valid scan data (fallback to HTML if weasyprint not available)."""
    scan_id = sample_scan_data["scan_id"]
    scan_results[scan_id] = sample_scan_data

    resp = client.get(f'/report/{scan_id}/pdf')
    # Should return either PDF (200 with application/pdf) or HTML fallback (200 with text/html)
    assert resp.status_code == 200
    content_type = resp.content_type
    assert 'text/html' in content_type or 'application/pdf' in content_type

    # Clean up
    del scan_results[scan_id]


def test_pdf_endpoint_error_scan(client):
    """Test PDF endpoint with errored scan."""
    scan_results["error-scan"] = {"error": "Connection failed", "scan_id": "error-scan"}
    resp = client.get('/report/error-scan/pdf')
    assert resp.status_code == 500
    del scan_results["error-scan"]


def test_html_report_endpoint(client, sample_scan_data):
    """Test that the existing HTML report endpoint still works."""
    scan_id = sample_scan_data["scan_id"]
    scan_results[scan_id] = sample_scan_data

    resp = client.get(f'/report/{scan_id}')
    assert resp.status_code == 200
    assert 'text/html' in resp.content_type
    assert b'Security Audit Report' in resp.data or b'SECURITY AUDIT REPORT' in resp.data

    del scan_results[scan_id]


def test_pdf_with_weasyprint_mocked(client, sample_scan_data):
    """Test PDF generation with mocked weasyprint."""
    scan_id = sample_scan_data["scan_id"]
    scan_results[scan_id] = sample_scan_data

    mock_html_class = MagicMock()
    mock_html_instance = MagicMock()
    mock_html_class.return_value = mock_html_instance
    mock_html_instance.write_pdf.return_value = b'%PDF-1.4 fake pdf content'

    with patch.dict('sys.modules', {'weasyprint': MagicMock(HTML=mock_html_class)}):
        resp = client.get(f'/report/{scan_id}/pdf')
        assert resp.status_code == 200
        assert resp.content_type == 'application/pdf'
        assert resp.headers.get('Content-Disposition') is not None
        assert 'vulnscan_report_' in resp.headers.get('Content-Disposition', '')

    del scan_results[scan_id]


def test_index_has_download_buttons(client):
    """Test that index.html has the new download button elements."""
    resp = client.get('/')
    assert resp.status_code == 200
    html = resp.data.decode()
    assert 'dl-pdf' in html
    assert 'dl-html' in html
    assert 'dl-view' in html
    assert "downloadReport('pdf')" in html
    assert "downloadReport('html')" in html
    assert 'Download PDF Report' in html
    assert 'Download HTML Report' in html


def test_index_has_download_css(client):
    """Test that index.html has the CSS for download buttons."""
    resp = client.get('/')
    html = resp.data.decode()
    assert '.download-btns' in html
    assert '.dl-btn' in html
    assert '.dl-pdf' in html
    assert '.dl-html' in html
    assert '.dl-view' in html


def test_send_file_import():
    """Test that send_file is properly imported in app."""
    from flask import send_file as sf
    assert sf is not None
    # Verify it's in our app.py imports
    with open('app.py', 'r') as f:
        content = f.read()
    assert 'send_file' in content


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
