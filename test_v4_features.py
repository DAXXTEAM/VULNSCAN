"""Tests for VULNSCAN v4.0 features: CVE check, reputation, CT logs, history, bulk scan, API"""
import pytest
import json
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app
from history import save_scan, load_history, clear_history, HISTORY_FILE
from scanner import check_cve


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture(autouse=True)
def cleanup_history():
    """Clean history file before and after each test"""
    try:
        os.remove(HISTORY_FILE)
    except OSError:
        pass
    yield
    try:
        os.remove(HISTORY_FILE)
    except OSError:
        pass


# ===== HISTORY TESTS =====

class TestHistory:
    def test_save_and_load(self):
        save_scan('test-id-1', 'https://example.com', 5, 7.5, critical=2, high=1)
        history = load_history()
        assert len(history) == 1
        assert history[0]['scan_id'] == 'test-id-1'
        assert history[0]['url'] == 'https://example.com'
        assert history[0]['findings'] == 5
        assert history[0]['risk_score'] == 7.5
        assert history[0]['critical'] == 2
        assert history[0]['high'] == 1

    def test_multiple_saves(self):
        save_scan('id1', 'https://a.com', 3, 4.0)
        save_scan('id2', 'https://b.com', 8, 9.0)
        history = load_history()
        assert len(history) == 2
        assert history[1]['url'] == 'https://b.com'

    def test_max_50_entries(self):
        for i in range(55):
            save_scan(f'id-{i}', f'https://site{i}.com', i, float(i % 10))
        history = load_history()
        assert len(history) == 50
        # Should keep the last 50 (entries 5-54)
        assert history[0]['scan_id'] == 'id-5'

    def test_clear_history(self):
        save_scan('id1', 'https://test.com', 2, 3.0)
        clear_history()
        history = load_history()
        assert len(history) == 0

    def test_load_empty(self):
        history = load_history()
        assert history == []


# ===== CVE CHECK TESTS =====

class TestCVECheck:
    def test_php_7_3_detection(self):
        tech_detail = {'php_version': '7.3.11', 'server': 'Apache/2.4.41'}
        findings = check_cve(tech_detail)
        assert len(findings) >= 1
        php_finding = next((f for f in findings if 'PHP' in f['software']), None)
        assert php_finding is not None
        assert 'CVE-2021-21703' in php_finding['cves']
        assert php_finding['severity'] == 'critical'

    def test_apache_2_4_49(self):
        tech_detail = {'server': 'Apache/2.4.49'}
        findings = check_cve(tech_detail)
        assert len(findings) >= 1
        apache_finding = next((f for f in findings if 'Apache' in f['software']), None)
        assert apache_finding is not None
        assert 'CVE-2021-41773' in apache_finding['cves']

    def test_no_match(self):
        tech_detail = {'server': 'CloudFlare', 'php_version': ''}
        findings = check_cve(tech_detail)
        # May return 0 since no matching versions
        assert isinstance(findings, list)

    def test_jquery_detection(self):
        tech_detail = {'jquery_version': '1.12.4'}
        findings = check_cve(tech_detail)
        assert len(findings) >= 1
        jq_finding = next((f for f in findings if 'jQuery' in f['software']), None)
        assert jq_finding is not None
        assert 'CVE-2020-11022' in jq_finding['cves']

    def test_empty_tech_detail(self):
        findings = check_cve({})
        assert findings == []


# ===== API ENDPOINTS TESTS =====

class TestAPIEndpoints:
    def test_api_docs(self, client):
        resp = client.get('/api')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['version'] == '4.0'
        assert 'endpoints' in data
        assert 'POST /scan' in data['endpoints']
        assert 'POST /scan/bulk' in data['endpoints']
        assert 'GET /history' in data['endpoints']

    def test_history_endpoint_empty(self, client):
        resp = client.get('/history')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data == []

    def test_history_clear(self, client):
        save_scan('test-1', 'https://test.com', 5, 6.0)
        resp = client.post('/history/clear')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['ok'] == True
        # Verify cleared
        resp2 = client.get('/history')
        assert resp2.get_json() == []

    def test_bulk_scan_no_urls(self, client):
        resp = client.post('/scan/bulk',
                          json={'urls': []},
                          content_type='application/json')
        assert resp.status_code == 400
        assert 'error' in resp.get_json()

    def test_bulk_scan_no_body(self, client):
        resp = client.post('/scan/bulk',
                          json={},
                          content_type='application/json')
        assert resp.status_code == 400

    def test_bulk_scan_max_10(self, client):
        urls = [f'https://site{i}.com' for i in range(15)]
        resp = client.post('/scan/bulk',
                          json={'urls': urls},
                          content_type='application/json')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['ok'] == True
        assert data['total'] <= 10

    def test_scan_no_url(self, client):
        resp = client.post('/scan',
                          json={},
                          content_type='application/json')
        assert resp.status_code == 400

    def test_schedule_post(self, client):
        resp = client.post('/schedule',
                          json={'url': 'https://example.com', 'interval_hours': 12},
                          content_type='application/json')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['ok'] == True
        assert 'id' in data

    def test_schedule_get(self, client):
        # Add one
        client.post('/schedule',
                   json={'url': 'https://test.com', 'interval_hours': 24},
                   content_type='application/json')
        resp = client.get('/schedule')
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) >= 1

    def test_schedule_delete(self, client):
        # Add then delete
        resp = client.post('/schedule',
                          json={'url': 'https://del.com', 'interval_hours': 6},
                          content_type='application/json')
        sid = resp.get_json()['id']
        resp2 = client.delete(f'/schedule/{sid}')
        assert resp2.status_code == 200
        assert resp2.get_json()['ok'] == True

    def test_index_page(self, client):
        resp = client.get('/')
        assert resp.status_code == 200
        assert b'VULNSCAN' in resp.data
        assert b'v4.0' in resp.data

    def test_index_has_bulk_tab(self, client):
        resp = client.get('/')
        assert b'BULK' in resp.data
        assert b'bulkUrls' in resp.data

    def test_index_has_history_panel(self, client):
        resp = client.get('/')
        assert b'historyPanel' in resp.data
        assert b'RECENT SCANS' in resp.data


# ===== SCHEDULED FILE CLEANUP =====

@pytest.fixture(autouse=True)
def cleanup_scheduled():
    scheduled_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scheduled.json')
    yield
    try:
        os.remove(scheduled_file)
    except OSError:
        pass


if __name__ == '__main__':
    pytest.main([__file__, '-x', '-q'])
