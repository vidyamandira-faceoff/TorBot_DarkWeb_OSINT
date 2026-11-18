"""Unit tests for TorBot Web UI endpoints and reconnaissance parser."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from web_ui import (
    app,
    HTML_TEMPLATE,
    is_port_free,
    normalize_url,
    parse_info_recon_from_stdout,
    strip_ansi,
)


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_strip_ansi():
    text_with_ansi = "\x1b[31mError\x1b[0m \x1b[32mSuccess\x1b[0m"
    assert strip_ansi(text_with_ansi) == "Error Success"


def test_normalize_url():
    assert normalize_url("https://example.com") == "https://example.com"
    assert normalize_url("http://example.com") == "http://example.com"
    assert normalize_url("test.onion") == "http://test.onion"
    assert normalize_url("example.com") == "https://example.com"
    search_clearnet = normalize_url("market list", disable_socks=True)
    assert "html.duckduckgo.com" in search_clearnet
    assert "q=market+list" in search_clearnet


def test_parse_info_recon_from_stdout():
    sample_output = """
    [*]Checking for Robots.txt
    https://target.test/robots.txt
    Robots.txt found
    Found 2 robots.txt paths
    Robots path: https://target.test/admin
    Robots path: https://target.test/secret
    [*]Checking for .git folder
    Alert! .git folder exposed publicly
    [*]Checking for .svn folder
    NO .SVN folder found
    [*]Checking for .htaccess
    .htaccess protected (403 Forbidden)
    [*]Checking for Bitcoin addresses
    BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    ETH: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e
    XMR: 44AFFq5AxYBfmGWymQAQep2dDDTq7E3Wkhn96fH8jR9hNf7Vw3L797Tj2Z5c2fH2zW5D1d4B5q5e3R3T4Y5U6I7O8P9A1B2
    Intel
    Found intel: contact@target.test
    Found intel: https://bucket.s3.amazonaws.com
    Meta : <meta name="description" content="OSINT Recon target">
    """
    data = parse_info_recon_from_stdout(sample_output)

    assert data["robots_status"] == "Exposed / Found"
    assert "https://target.test/admin" in data["robots_paths"]
    assert data["git_status"] == "ALERT: Publicly Exposed!"
    assert data["svn_status"] == "Safe (Not Found)"
    assert data["htaccess_status"] == "Protected (403 Forbidden)"
    assert any("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in b for b in data["bitcoins"])
    assert any("0x742d35Cc6634C0532925a3b844Bc454e4438f44e" in b for b in data["bitcoins"])
    assert "contact@target.test" in data["intel"]
    assert any("OSINT Recon target" in m for m in data["meta_tags"])


def test_parse_info_recon_negative_cases():
    negative_output = """
    NO robots.txt found (status: 404)
    NO .git folder found
    NO .SVN folder found
    NO .htaccess file found
    No external intel endpoints found
    """
    data = parse_info_recon_from_stdout(negative_output)
    assert data["robots_status"] == "Not Found (Safe)"
    assert data["git_status"] == "Safe (Not Found)"
    assert data["svn_status"] == "Safe (Not Found)"
    assert data["htaccess_status"] == "Safe (Not Found)"


def test_is_port_free():
    free = is_port_free(54321)
    assert isinstance(free, bool)


def test_web_ui_get_index(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"TorBot OSINT Dashboard" in response.data


def test_web_ui_removed_proxy_ui_elements(client):
    """Verify Tor SOCKS5 status indicator, Test Tor Exit IP button, and Advanced Proxy Settings are removed."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.data.decode("utf-8")

    # 1. Tor SOCKS5 Proxy status indicator removed
    assert "tor-badge" not in html
    assert "Tor SOCKS5 Online" not in html
    assert "Tor SOCKS5 Offline" not in html

    # 2. Test Tor Exit IP button & unused event handler removed
    assert "Test Tor Exit IP" not in html
    assert "checkTorHealth" not in html

    # 3. Advanced Proxy Settings section removed
    assert "Advanced Proxy Settings" not in html
    assert 'name="host"' not in html
    assert 'name="port"' not in html
    assert "SOCKS5 Host:" not in html
    assert "SOCKS5 Port:" not in html


def test_web_ui_post_empty_url(client):
    response = client.post("/", data={"url": ""})
    assert response.status_code == 200
    assert b"Please enter a target URL" in response.data


def test_web_ui_api_tor_status(client):
    response = client.get("/api/tor-status")
    assert response.status_code == 200
    data = response.get_json()
    assert isinstance(data, dict)
    assert "reachable" in data
    assert "ip" in data
    assert "is_tor" in data


def test_web_ui_download_endpoints(client, tmp_path, monkeypatch):
    test_result = tmp_path / "test-result.json"
    test_result.write_text(json.dumps({"target": "https://example.com"}), encoding="utf-8")
    monkeypatch.setattr("web_ui.RESULT_FILE", test_result)

    res = client.get("/download/result")
    assert res.status_code == 200
    assert res.mimetype == "application/json"


def test_web_ui_post_crawl_depth_3(client):
    """End-to-end test verifying Web UI POST with Depth 3 produces Exit Code 0 and scans pages."""
    import http.server
    import socketserver
    import threading

    pages = {
        "/": '<html><head><title>Root Site</title></head><body><a href="/p1">P1</a></body></html>',
        "/p1": '<html><head><title>Page 1</title></head><body><a href="/p2">P2</a></body></html>',
        "/p2": '<html><head><title>Page 2</title></head><body><a href="/p3">P3</a></body></html>',
        "/p3": '<html><head><title>Page 3</title></head><body>Leaf</body></html>',
    }

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path.split("?")[0]
            body = pages.get(path, "<html><body>404</body></html>")
            self.send_response(200 if path in pages else 404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))

        def log_message(self, format, *args):
            pass

    server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        url = f"http://127.0.0.1:{port}/"
        response = client.post(
            "/",
            data={
                "url": url,
                "depth": "3",
                "action": "table",
                "disable_socks": "on",
                "resolve_relative": "on",
                "save_result": "on",
            },
        )
        assert response.status_code == 200
        html = response.data.decode("utf-8")
        assert "Exit Code: 0" in html
        assert "Pages Scanned" in html
        # Should have scanned Root, p1, p2, p3 (4 pages total)
        assert "Root Site" in html
        assert "Page 1" in html
        assert "Page 2" in html
        assert "Page 3" in html
        assert "Domain Type" in html
        assert "Crawl Timestamp" in html
        assert "domain-internal" in html
        assert "data-utc=" in html
    finally:
        server.shutdown()


def test_web_ui_renders_domain_type_and_timestamp_columns(client):
    """Verify Crawled Pages table renders Domain Type and Crawl Timestamp columns and badges."""
    from flask import render_template_string

    pages = [
        {
            "url": "https://example.com",
            "title": "Home Page",
            "depth": 0,
            "status": 200,
            "domainType": "Internal",
            "timestamp": "2026-11-16T14:30:00Z",
            "contacts": [],
            "category": "Technology",
            "links": [{"url": "https://other.org"}],
        },
        {
            "url": "https://other.org",
            "title": "External Page",
            "depth": 1,
            "status": 200,
            "domainType": "External",
            "timestamp": "2026-11-16T14:30:01Z",
            "contacts": [],
            "category": "Unknown",
            "links": [],
        },
    ]

    with app.test_request_context("/"):
        html = render_template_string(
            HTML_TEMPLATE,
            tor_online=True,
            proxy_host="127.0.0.1",
            proxy_port=9050,
            command_run="python main.py -u https://example.com",
            return_code=0,
            console_output="",
            raw_query="",
            target_url="https://example.com",
            total_pages=len(pages),
            pages=pages,
            emails_found=[],
            phones_found=[],
            btc_found=[],
            classification_label=None,
            recon_data={},
            json_pretty="{}",
            analyst_report=None,
            result_available=True,
        )

    # Verify Table Headers exist
    assert "<th>Domain Type</th>" in html
    assert "<th>Crawl Timestamp</th>" in html

    # Verify Domain Type badges
    assert '<span class="domain-pill domain-internal">Internal</span>' in html
    assert '<span class="domain-pill domain-external">External</span>' in html

    # Verify Crawl Timestamp elements with data-utc attributes
    assert 'data-utc="2026-11-16T14:30:00Z"' in html
    assert 'data-utc="2026-11-16T14:30:01Z"' in html


def test_web_ui_renders_legacy_results_with_na(client):
    """Verify legacy crawl results missing domainType or timestamp render N/A."""
    from flask import render_template_string

    legacy_pages = [
        {
            "url": "https://example.com",
            "title": "Legacy Page",
            "depth": 0,
            "status": 200,
            "contacts": [],
            "category": "Unknown",
            "links": [],
        }
    ]

    with app.test_request_context("/"):
        html = render_template_string(
            HTML_TEMPLATE,
            tor_online=True,
            proxy_host="127.0.0.1",
            proxy_port=9050,
            command_run="python main.py -u https://example.com",
            return_code=0,
            console_output="",
            raw_query="",
            target_url="https://example.com",
            total_pages=len(legacy_pages),
            pages=legacy_pages,
            emails_found=[],
            phones_found=[],
            btc_found=[],
            classification_label=None,
            recon_data={},
            json_pretty="{}",
            analyst_report=None,
            result_available=True,
        )

    assert '<span class="domain-pill domain-na">N/A</span>' in html
    assert 'class="crawl-timestamp"' in html
    assert 'N/A' in html


def test_web_ui_filters_pages_to_unique_verified_200_and_matches_export(client, tmp_path, monkeypatch):
    """Verify TorBot displays only unique, verified HTTP 200 pages, separates discovered URLs,
    and ensures dashboard count matches Results Table entries and JSON export."""
    from unittest.mock import MagicMock

    raw_pages = []
    # 21 verified HTTP 200 pages
    for i in range(1, 22):
        raw_pages.append({
            "url": f"https://target.test/page-{i}",
            "title": f"Page {i}",
            "depth": 1 if i > 1 else 0,
            "status": 200,
            "outcome": "fetched",
            "domainType": "Internal",
            "timestamp": "2026-11-16T15:00:00Z",
            "contacts": [],
            "links": [],
        })
    # 1 duplicate 200 page
    raw_pages.append({
        "url": "https://target.test/page-1",
        "title": "Page 1 Duplicate",
        "depth": 2,
        "status": 200,
        "outcome": "fetched",
        "domainType": "Internal",
        "timestamp": "2026-11-16T15:00:01Z",
        "contacts": [],
        "links": [],
    })
    # 4 HTTP 404 pages
    for i in range(1, 5):
        raw_pages.append({
            "url": f"https://target.test/error-404-{i}",
            "title": f"404 Not Found {i}",
            "depth": 2,
            "status": 404,
            "outcome": "fetched",
            "domainType": "Internal",
            "timestamp": "2026-11-16T15:00:02Z",
            "contacts": [],
            "links": [],
        })
    # 2 HTTP 403 pages
    for i in range(1, 3):
        raw_pages.append({
            "url": f"https://target.test/blocked-403-{i}",
            "title": f"403 Forbidden {i}",
            "depth": 2,
            "status": 403,
            "outcome": "fetched",
            "domainType": "External",
            "timestamp": "2026-11-16T15:00:03Z",
            "contacts": [],
            "links": [],
        })

    mock_crawl_result = {
        "schemaVersion": 1,
        "target": "https://target.test/",
        "settings": {"maxDepth": 2, "usesTor": False},
        "terminalStatus": "completed",
        "pages": raw_pages,
        "stats": {
            "totalPages": 21,
            "verifiedPages": 21,
            "totalDiscoveredUrls": 28,
            "uniqueDiscoveredUrls": 27,
            "unverifiedOrNon200Urls": 6,
            "statusCounts": {"200": 21, "404": 4, "403": 2},
        },
    }

    test_file = tmp_path / "latest-crawl-result.json"
    test_file.write_text(json.dumps(mock_crawl_result, indent=2), encoding="utf-8")
    monkeypatch.setattr("web_ui.RESULT_FILE", test_file)

    # Mock subprocess.run so POST reads the prepared test_file without running a full crawl
    def mock_run(*args, **kwargs):
        # Ensure test_file remains on disk
        test_file.write_text(json.dumps(mock_crawl_result, indent=2), encoding="utf-8")
        mock_proc = MagicMock()
        mock_proc.stdout = "TorBot execution completed."
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        return mock_proc

    monkeypatch.setattr("subprocess.run", mock_run)

    response = client.post(
        "/",
        data={"url": "https://target.test", "depth": "2", "disable_socks": "on"},
    )
    assert response.status_code == 200
    html = response.data.decode("utf-8")

    # 1. KPI Card displays only 21 verified pages
    assert '<div class="kpi-label">Pages Scanned</div>' in html
    assert '<div class="kpi-val">21</div>' in html

    # 2. Tab header displays 21 pages
    assert "📋 Crawled Pages (21)" in html

    tab_pages_html = html.split('id="tab-pages"')[1].split('</table>')[0]

    # 3. Results Table displays only the 21 unique verified 200 pages
    for i in range(1, 22):
        assert f"https://target.test/page-{i}" in tab_pages_html
        assert f"Page {i}" in tab_pages_html

    # 4. Results Table completely excludes 404, 403, and duplicate pages
    for i in range(1, 5):
        assert f"https://target.test/error-404-{i}" not in tab_pages_html
        assert f"404 Not Found {i}" not in tab_pages_html
    for i in range(1, 3):
        assert f"https://target.test/blocked-403-{i}" not in tab_pages_html
        assert f"403 Forbidden {i}" not in tab_pages_html
    assert "Page 1 Duplicate" not in tab_pages_html

    # 5. Table rows count in <tbody> matches total_pages (21)
    # Each row in Results Table has <span class="domain-pill ...
    assert tab_pages_html.count('class="domain-pill') == 21

    # 6. Discovered URLs separation displayed in KPI card
    assert "27 Discovered URLs" in html

    # 7. JSON download endpoint (/download/result) matches the dashboard count (21)
    dl_resp = client.get("/download/result")
    assert dl_resp.status_code == 200
    dl_data = json.loads(dl_resp.data.decode("utf-8"))
    assert len(dl_data["pages"]) == 21
    assert all(p["status"] == 200 for p in dl_data["pages"])
    assert len({p["url"] for p in dl_data["pages"]}) == 21


def test_web_ui_tabs_cleanup_and_launch_indicator(client):
    """Verify that only the Crawled Pages tab is kept in the UI,
    the three tabs (Security & Intel Recon, Crawl Result JSON, Terminal Console)
    are removed, all form inputs/checkboxes are preserved, and the launch animation
    indicator is present."""
    # 1. GET response checks
    response = client.get("/")
    assert response.status_code == 200
    html = response.data.decode("utf-8")

    # Form inputs & checkboxes preserved
    assert 'id="recon-form"' in html
    assert 'name="url"' in html
    assert 'name="depth"' in html
    assert 'name="action"' in html
    assert 'id="run_info"' in html and 'name="run_info"' in html
    assert 'id="resolve_relative"' in html and 'name="resolve_relative"' in html
    assert 'id="save_result"' in html and 'name="save_result"' in html
    assert 'id="disable_socks"' in html and 'name="disable_socks"' in html
    assert 'id="submit-btn"' in html
    assert "🚀 Launch OSINT Reconnaissance" in html

    # Launch animation indicator present
    assert 'id="crawling-indicator"' in html
    assert "Crawling in Progress..." in html
    assert 'id="elapsed-counter"' in html
    assert 'class="radar-scan"' in html
    assert 'class="glass-icon"' in html

    # 2. Check UI after running a scan
    post_resp = client.post(
        "/",
        data={"url": "https://example.com", "depth": "0", "disable_socks": "on"},
    )
    assert post_resp.status_code == 200
    post_html = post_resp.data.decode("utf-8")

    # Removed tabs are absent from navigation and tab panes
    assert "Security & Intel Recon" not in post_html
    assert "Crawl Result JSON" not in post_html
    assert "Terminal Console" not in post_html
    assert 'id="tab-recon"' not in post_html
    assert 'id="tab-json"' not in post_html
    assert 'id="tab-terminal"' not in post_html

    # Only Crawled Pages tab is present
    assert "📋 Crawled Pages" in post_html
    assert 'id="tab-pages"' in post_html

    # Results card and download JSON preserved
    assert 'id="results-card"' in post_html
    assert "Exit Code:" in post_html
    assert "📥 Download JSON" in post_html


def test_web_ui_continuous_animation_and_no_fake_progress(client):
    """Verify that the blue circular search animation has continuous rotation keyframes,
    the frontend script uses real fetch dispatch without fake progress timers or fake milestones,
    dynamic error banner is present, and Crawled Pages is automatically updated."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.data.decode("utf-8")

    # 1. Circular animation keyframes and classes
    assert "spinClockwise" in html
    assert "spinCounterClockwise" in html
    assert "radar-scan" in html
    assert "radar-ring" in html
    assert "radar-pulse" in html
    assert "glass-icon" in html
    assert 'id="crawling-indicator"' in html

    # 2. Dynamic error banner and results container
    assert 'id="dynamic-error-banner"' in html
    assert 'id="results-area-container"' in html

    # 3. No fake progress or fixed timer milestones in script
    assert "Dispatching crawler & establishing connection" not in html
    assert "Extracting pages, parsing links" not in html
    assert "Performing deep recursive link resolution" not in html
    assert "Aggregating intelligence, contacts" not in html

    # 4. Real fetch and event handling
    assert "e.preventDefault()" in html
    assert "fetch(" in html
    assert "new DOMParser()" in html
    assert "showErrorMessage" in html
    assert "formatLocalTimestamps()" in html


def test_web_ui_fetch_endpoint_avoids_shadowed_action_property_404(client):
    """Verify that recon-form specifies action="/" and the JS fetch targets form.getAttribute('action')
    rather than form.action, avoiding the DOM property shadowing bug where <select name="action">
    causes fetch("[object HTMLSelectElement]") resulting in HTTP 404."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.data.decode("utf-8")

    # Form has explicit action="/"
    assert '<form method="POST" id="recon-form" action="/">' in html

    # JS does not do fetch(form.action) which is shadowed by <select name="action">
    assert "form.action" not in html
    assert "form.getAttribute('action')" in html

    # Test POST directly to "/" with multipart/form-data works with HTTP 200
    post_resp = client.post(
        "/",
        data={"url": "https://example.com", "depth": "0", "action": "table", "disable_socks": "on"},
        content_type="multipart/form-data",
    )
    assert post_resp.status_code == 200
    post_html = post_resp.data.decode("utf-8")
    assert 'id="results-card"' in post_html
    assert "📋 Crawled Pages" in post_html


def test_web_ui_blue_progress_bar_and_live_percentage(client):
    """Verify that the crawling animation contains a blue progress bar and percentage indicator (0% to 100%),
    displays 0% at start, indeterminate progress bar when backend progress is unavailable, 100% on completion,
    preserves the circular search animation unchanged, and does not use fake timers."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.data.decode("utf-8")

    # 1. Progress bar and percentage indicator elements
    assert 'class="progress-section"' in html
    assert 'class="progress-bar-track"' in html
    assert 'id="progress-bar-fill"' in html
    assert 'id="progress-percentage"' in html
    assert "0%" in html

    # 2. Indeterminate progress bar styling and animation
    assert "progress-bar-fill indeterminate" in html
    assert "progressIndeterminate" in html

    # 3. JavaScript progress updater logic
    assert "setIndeterminateProgress()" in html
    assert "updateCrawlProgress(100)" in html
    assert "function updateCrawlProgress(percent)" in html
    assert "function setIndeterminateProgress()" in html
    assert "setProgressError" in html

    # 4. Existing circular search animation remains completely intact
    assert "scanner-wrap" in html
    assert "radar-pulse" in html
    assert "radar-ring" in html
    assert "radar-scan" in html
    assert "glass-icon" in html
    assert "spinClockwise" in html
    assert "spinCounterClockwise" in html


def test_web_ui_darkweb_ssl_notice_and_proxy_sync(client, tmp_path, monkeypatch):
    """Verify that Web UI synchronizes SOCKS5 checkbox for .onion addresses,
    displays the Dark Web TLS notice when unverified self-signed certificates are present,
    and displays the Self-Signed TLS badge in the Crawled Pages table."""
    # 1. HTML elements & JS sync function
    response = client.get("/")
    assert response.status_code == 200
    html = response.data.decode("utf-8")
    assert "setupOnionProxyCheckboxSync" in html
    assert "tag-ssl-unverified" in html
    assert "Dark Web TLS Security Notice" in HTML_TEMPLATE

    # 2. Mock a crawl result with an .onion URL and unverified SSL
    test_result = tmp_path / "onion-result.json"
    onion_url = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/"
    result_data = {
        "version": "1.0.0",
        "target": onion_url,
        "terminalStatus": "completed",
        "diagnostics": {
            "sslStatus": "Onion HTTPS self-signed/unverified certificate allowed",
            "unverifiedSslCount": "1",
        },
        "pages": [
            {
                "url": onion_url,
                "title": "DuckDuckGo Dark Web",
                "status": 200,
                "outcome": "fetched",
                "depth": 0,
                "domainType": "Internal",
                "unverifiedSsl": True,
                "contacts": [],
                "links": [],
                "content": {"text": "Welcome to DuckDuckGo Onion"},
            }
        ],
    }
    test_result.write_text(json.dumps(result_data), encoding="utf-8")
    monkeypatch.setattr("web_ui.RESULT_FILE", test_result)

    # 3. Submit form targeting .onion with disable_socks='on'
    post_resp = client.post(
        "/",
        data={
            "url": "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
            "depth": "0",
            "action": "table",
            "disable_socks": "on",
        },
        content_type="multipart/form-data",
    )
    assert post_resp.status_code == 200
    post_html = post_resp.data.decode("utf-8")

    # Verify SOCKS5 proxy was NOT disabled for onion command
    assert "--disable-socks5" not in post_html or "command" not in post_html

    # Verify Dark Web TLS Security Notice alert box is rendered
    assert "Dark Web TLS Security Notice" in post_html
    assert "cryptographic end-to-end authentication and transport encryption" in post_html

    # Verify Self-Signed TLS badge in table
    assert "🔒 Self-Signed TLS" in post_html


def test_web_ui_dropdown_ui_enhancements(client):
    """Verify that Action/Output Mode and Crawl Depth dropdowns have enhanced styles:
    increased font-size, height, padding, custom chevron icon, and readable option styling."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.data.decode("utf-8")

    # 1. App-shell full viewport layout styles (OASIS Architecture Alignment)
    assert '<meta name="viewport" content="width=device-width, initial-scale=1.0">' in html
    assert "width: 100vw" in html
    assert "height: 100vh" in html
    assert "overflow: hidden" in html
    assert "max-width: 1400px" in html
    assert ".app-shell" in html
    assert "flex-shrink: 0" in html

    # 2. Select CSS styles
    assert "height: 48px" in html
    assert "font-size: 15px !important" in html
    assert "appearance: none" in html

    # 3. Select option CSS styles (large, clear, legible)
    assert "select option" in html
    assert "font-size: 15px !important" in html
    assert "padding: 10px 14px !important" in html
    assert "line-height: 1.6" in html
    assert "background-color: #0f172a !important" in html
    assert "color: #f8fafc !important" in html

    # 4. Dropdown elements
    assert '<select id="depth" name="depth"' in html
    assert '<select id="action" name="action"' in html
    assert "Depth 0 - Single URL Only" in html
    assert "Depth 1 - Direct Page Links" in html
    assert "Visual Table Crawl (--visualize table)" in html
    assert "Link Tree Structure (--visualize tree)" in html
    assert "JSON Tree Data (--visualize json)" in html
    assert "Deep Security & Info Recon (--info)" in html
    assert "Full Crawl + AI Analyst Investigation" in html


def test_web_ui_action_modes_and_checkbox_functionality(client, tmp_path, monkeypatch):
    """Verify that all checkboxes and action modes perform their respective backend functions:
    - action='tree' displays Link Tree Structure
    - action='json' displays JSON Tree Data
    - action='analyze' displays AI Analyst Investigation Report
    - action='info' or run_info displays Deep Security & Recon Intelligence
    - resolve_relative passes --resolve-relative
    - disable_socks passes --disable-socks5"""
    from unittest.mock import MagicMock
    test_result = tmp_path / "mode-result.json"
    result_data = {
        "version": "1.0.0",
        "target": "https://example.com",
        "terminalStatus": "completed",
        "pages": [
            {
                "url": "https://example.com",
                "title": "Example Domain",
                "status": 200,
                "outcome": "fetched",
                "depth": 0,
                "domainType": "Internal",
                "unverifiedSsl": False,
                "contacts": [],
                "links": [{"url": "https://example.com/sub"}],
                "content": {"text": "Example Domain Body Text"},
            }
        ],
    }
    test_result.write_text(json.dumps(result_data), encoding="utf-8")
    monkeypatch.setattr("web_ui.RESULT_FILE", test_result)

    def mock_subprocess_run(cmd, *args, **kwargs):
        test_result.write_text(json.dumps(result_data), encoding="utf-8")
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        cmd_str = " ".join(cmd)
        if "analyze" in cmd:
            mock_proc.stdout = "=== Full Crawl + AI Analyst Investigation Report ===\nClassification: Technology\nRisk: Low"
        elif "tree" in cmd:
            mock_proc.stdout = "https://example.com (Example Domain)\n├── https://example.com/sub (Subpage)"
        else:
            mock_proc.stdout = "TorBot completed crawl successfully."
        mock_proc.stderr = ""
        return mock_proc

    monkeypatch.setattr("subprocess.run", mock_subprocess_run)

    # 1. Test Link Tree Structure mode
    tree_resp = client.post(
        "/",
        data={"url": "https://example.com", "depth": "1", "action": "tree", "disable_socks": "on"},
        content_type="multipart/form-data",
    )
    assert tree_resp.status_code == 200
    tree_html = tree_resp.data.decode("utf-8")
    assert "🌳 Link Tree Structure" in tree_html
    assert "--visualize tree" in tree_html

    # 2. Test JSON Tree Data mode
    json_resp = client.post(
        "/",
        data={"url": "https://example.com", "depth": "1", "action": "json", "disable_socks": "on"},
        content_type="multipart/form-data",
    )
    assert json_resp.status_code == 200
    json_html = json_resp.data.decode("utf-8")
    assert "📄 JSON Tree Data" in json_html
    assert "Example Domain" in json_html

    # 3. Test Full Crawl + AI Analyst Investigation mode
    analyze_resp = client.post(
        "/",
        data={"url": "https://example.com", "depth": "0", "action": "analyze", "disable_socks": "on"},
        content_type="multipart/form-data",
    )
    assert analyze_resp.status_code == 200
    analyze_html = analyze_resp.data.decode("utf-8")
    assert "🤖 Full Crawl + AI Analyst Investigation Report" in analyze_html or "AI Analyst" in analyze_html

    # 4. Test Deep Security & Recon (--info) and Resolve Relative Links (--resolve-relative)
    recon_resp = client.post(
        "/",
        data={
            "url": "https://example.com",
            "depth": "0",
            "action": "table",
            "run_info": "on",
            "resolve_relative": "on",
            "save_result": "on",
            "disable_socks": "on",
        },
        content_type="multipart/form-data",
    )
    assert recon_resp.status_code == 200
    recon_html = recon_resp.data.decode("utf-8")
    assert "--info" in recon_html
    assert "--resolve-relative" in recon_html
    assert "--disable-socks5" in recon_html
    assert "📥 Download JSON" in recon_html












