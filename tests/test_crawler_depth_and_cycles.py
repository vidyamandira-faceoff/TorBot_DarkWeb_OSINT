"""Tests for LinkTree crawl depths (0, 1, 2, 3, 5), cycle prevention, and link scoping."""
import pytest
from torbot.modules.linktree import LinkTree, is_internal_url, classify_crawl_error


class MockResponse:
    def __init__(self, url: str, text: str, status_code: int = 200):
        self.url = url
        self.text = text
        self.status_code = status_code


class CountingClient:
    def __init__(self, responses: dict[str, MockResponse]):
        self.responses = responses
        self.request_counts: dict[str, int] = {}

    def get(self, url: str, **kwargs) -> MockResponse:
        self.request_counts[url] = self.request_counts.get(url, 0) + 1
        if url in self.responses:
            return self.responses[url]
        return MockResponse(url, "<html><title>Not Found</title></html>", 404)


def test_is_internal_url_helper():
    assert is_internal_url("https://example.com/a", "https://example.com/b") is True
    assert is_internal_url("https://example.com", "https://sub.example.com/page") is True
    assert is_internal_url("https://www.example.com", "https://example.com/page") is True
    assert is_internal_url("https://example.com", "https://external.com/page") is False
    assert is_internal_url("http://test.onion/path", "http://test.onion/other") is True
    assert is_internal_url("http://test.onion", "http://another.onion") is False


def test_crawl_depth_0():
    """Depth 0 crawls target URL only and does not expand children."""
    html = '<html><title>Root Page</title><a href="https://example.com/sub">Sub</a></html>'
    client = CountingClient({"https://example.com": MockResponse("https://example.com", html)})

    tree = LinkTree("https://example.com", depth=0, client=client)
    tree.load()

    assert len(tree.all_nodes()) == 1
    assert tree.get_node("https://example.com") is not None
    assert tree.get_node("https://example.com/sub") is None
    assert client.request_counts["https://example.com"] == 1


def test_crawl_depth_1():
    """Depth 1 crawls root and direct links only."""
    root_html = '''
    <html><title>Root</title>
      <a href="https://example.com/p1">P1</a>
      <a href="https://example.com/p2">P2</a>
    </html>
    '''
    p1_html = '<html><title>P1</title><a href="https://example.com/p1_sub">P1 Sub</a></html>'
    p2_html = '<html><title>P2</title><a href="https://example.com/p2_sub">P2 Sub</a></html>'

    client = CountingClient({
        "https://example.com": MockResponse("https://example.com", root_html),
        "https://example.com/p1": MockResponse("https://example.com/p1", p1_html),
        "https://example.com/p2": MockResponse("https://example.com/p2", p2_html),
    })

    tree = LinkTree("https://example.com", depth=1, client=client)
    tree.load()

    assert tree.get_node("https://example.com") is not None
    assert tree.get_node("https://example.com/p1") is not None
    assert tree.get_node("https://example.com/p2") is not None
    assert tree.get_node("https://example.com/p1_sub") is None
    assert tree.get_node("https://example.com/p2_sub") is None
    assert len(tree.all_nodes()) == 3


def test_crawl_depth_2():
    """Depth 2 crawls root, level 1, and level 2, stopping before level 3."""
    root_html = '<html><title>Root</title><a href="https://example.com/l1">L1</a></html>'
    l1_html = '<html><title>L1</title><a href="https://example.com/l2">L2</a></html>'
    l2_html = '<html><title>L2</title><a href="https://example.com/l3">L3</a></html>'
    l3_html = '<html><title>L3</title></html>'

    client = CountingClient({
        "https://example.com": MockResponse("https://example.com", root_html),
        "https://example.com/l1": MockResponse("https://example.com/l1", l1_html),
        "https://example.com/l2": MockResponse("https://example.com/l2", l2_html),
        "https://example.com/l3": MockResponse("https://example.com/l3", l3_html),
    })

    tree = LinkTree("https://example.com", depth=2, client=client)
    tree.load()

    assert tree.get_node("https://example.com") is not None
    assert tree.get_node("https://example.com/l1") is not None
    assert tree.get_node("https://example.com/l2") is not None
    assert tree.get_node("https://example.com/l3") is None
    assert tree.depth("https://example.com/l2") == 2


def test_crawl_depth_3():
    """Depth 3 reaches level 3 correctly and stops before level 4."""
    root_html = '<html><title>Root</title><a href="https://example.com/l1">L1</a></html>'
    l1_html = '<html><title>L1</title><a href="https://example.com/l2">L2</a></html>'
    l2_html = '<html><title>L2</title><a href="https://example.com/l3">L3</a></html>'
    l3_html = '<html><title>L3</title><a href="https://example.com/l4">L4</a></html>'
    l4_html = '<html><title>L4</title></html>'

    client = CountingClient({
        "https://example.com": MockResponse("https://example.com", root_html),
        "https://example.com/l1": MockResponse("https://example.com/l1", l1_html),
        "https://example.com/l2": MockResponse("https://example.com/l2", l2_html),
        "https://example.com/l3": MockResponse("https://example.com/l3", l3_html),
        "https://example.com/l4": MockResponse("https://example.com/l4", l4_html),
    })

    tree = LinkTree("https://example.com", depth=3, client=client)
    tree.load()

    assert tree.get_node("https://example.com") is not None
    assert tree.get_node("https://example.com/l1") is not None
    assert tree.get_node("https://example.com/l2") is not None
    assert tree.get_node("https://example.com/l3") is not None
    assert tree.get_node("https://example.com/l4") is None
    assert tree.depth("https://example.com/l3") == 3


def test_crawl_depth_5():
    """Depth 5 reaches level 5 correctly and stops before level 6."""
    responses = {
        "https://example.com": MockResponse(
            "https://example.com",
            '<html><title>Root</title><a href="https://example.com/l1">L1</a></html>',
        ),
        "https://example.com/l1": MockResponse(
            "https://example.com/l1",
            '<html><title>L1</title><a href="https://example.com/l2">L2</a></html>',
        ),
        "https://example.com/l2": MockResponse(
            "https://example.com/l2",
            '<html><title>L2</title><a href="https://example.com/l3">L3</a></html>',
        ),
        "https://example.com/l3": MockResponse(
            "https://example.com/l3",
            '<html><title>L3</title><a href="https://example.com/l4">L4</a></html>',
        ),
        "https://example.com/l4": MockResponse(
            "https://example.com/l4",
            '<html><title>L4</title><a href="https://example.com/l5">L5</a></html>',
        ),
        "https://example.com/l5": MockResponse(
            "https://example.com/l5",
            '<html><title>L5</title><a href="https://example.com/l6">L6</a></html>',
        ),
        "https://example.com/l6": MockResponse(
            "https://example.com/l6",
            '<html><title>L6</title></html>',
        ),
    }

    client = CountingClient(responses)
    tree = LinkTree("https://example.com", depth=5, client=client)
    tree.load()

    assert tree.get_node("https://example.com") is not None
    assert tree.get_node("https://example.com/l1") is not None
    assert tree.get_node("https://example.com/l2") is not None
    assert tree.get_node("https://example.com/l3") is not None
    assert tree.get_node("https://example.com/l4") is not None
    assert tree.get_node("https://example.com/l5") is not None
    assert tree.get_node("https://example.com/l6") is None
    assert tree.depth("https://example.com/l5") == 5


def test_prevents_cyclic_graph_loops():
    """Verify that graph cycles (A -> B -> A) do not cause infinite loops or duplicate visits."""
    a_html = '''
    <html><title>Page A</title>
      <a href="https://example.com/b">Go to B</a>
      <a href="https://example.com/a">Self loop A</a>
    </html>
    '''
    b_html = '''
    <html><title>Page B</title>
      <a href="https://example.com/a">Go back to A</a>
      <a href="https://example.com/b">Self loop B</a>
    </html>
    '''

    client = CountingClient({
        "https://example.com/a": MockResponse("https://example.com/a", a_html),
        "https://example.com/b": MockResponse("https://example.com/b", b_html),
    })

    tree = LinkTree("https://example.com/a", depth=3, client=client)
    tree.load()

    # Both nodes are in the tree
    assert len(tree.all_nodes()) == 2
    assert tree.get_node("https://example.com/a") is not None
    assert tree.get_node("https://example.com/b") is not None
    # Neither page was fetched more than once
    assert client.request_counts["https://example.com/a"] == 1
    assert client.request_counts["https://example.com/b"] == 1


def test_no_double_fetching():
    """Verify pages are requested exactly once and cached across append and build phases."""
    root_html = '''
    <html><title>Root</title>
      <a href="https://example.com/child1">C1</a>
      <a href="https://example.com/child2">C2</a>
    </html>
    '''
    c1_html = '<html><title>C1</title></html>'
    c2_html = '<html><title>C2</title></html>'

    client = CountingClient({
        "https://example.com": MockResponse("https://example.com", root_html),
        "https://example.com/child1": MockResponse("https://example.com/child1", c1_html),
        "https://example.com/child2": MockResponse("https://example.com/child2", c2_html),
    })

    tree = LinkTree("https://example.com", depth=2, client=client)
    tree.load()

    assert client.request_counts["https://example.com"] == 1
    assert client.request_counts["https://example.com/child1"] == 1
    assert client.request_counts["https://example.com/child2"] == 1


def test_internal_links_crawled_and_external_collected_as_leaves():
    """Verify internal links are recursed into, while external links are collected as leaves."""
    root_html = '''
    <html><title>Target Root</title>
      <a href="https://target.onion/internal">Internal Link</a>
      <a href="https://external-social.com/profile">External Profile</a>
    </html>
    '''
    internal_html = '''
    <html><title>Internal Page</title>
      <a href="https://target.onion/deep">Deep Link</a>
    </html>
    '''
    external_html = '''
    <html><title>External Page</title>
      <a href="https://external-social.com/runaway1">Runaway 1</a>
      <a href="https://external-social.com/runaway2">Runaway 2</a>
    </html>
    '''
    deep_html = '<html><title>Deep Internal Page</title></html>'

    client = CountingClient({
        "https://target.onion": MockResponse("https://target.onion", root_html),
        "https://target.onion/internal": MockResponse("https://target.onion/internal", internal_html),
        "https://external-social.com/profile": MockResponse("https://external-social.com/profile", external_html),
        "https://target.onion/deep": MockResponse("https://target.onion/deep", deep_html),
    })

    # By default, crawl_external is False
    tree = LinkTree("https://target.onion", depth=3, client=client)
    tree.load()

    # External profile is in the tree as a leaf under root
    assert tree.get_node("https://external-social.com/profile") is not None
    assert tree.parent("https://external-social.com/profile").identifier == "https://target.onion"

    # Deep internal link was reached
    assert tree.get_node("https://target.onion/deep") is not None

    # External runaway links were NOT crawled
    assert tree.get_node("https://external-social.com/runaway1") is None
    assert tree.get_node("https://external-social.com/runaway2") is None
    assert "https://external-social.com/profile" in tree.external_links
    assert "https://target.onion/internal" in tree.internal_links


def test_crawl_external_explicitly_enabled():
    """Verify external domains are crawled when crawl_external=True."""
    root_html = '''
    <html><title>Target Root</title>
      <a href="https://external-site.org/page">External Site</a>
    </html>
    '''
    external_html = '''
    <html><title>External Page</title>
      <a href="https://external-site.org/subpage">External Subpage</a>
    </html>
    '''
    external_subpage_html = '<html><title>External Subpage</title></html>'

    client = CountingClient({
        "https://target.onion": MockResponse("https://target.onion", root_html),
        "https://external-site.org/page": MockResponse("https://external-site.org/page", external_html),
        "https://external-site.org/subpage": MockResponse("https://external-site.org/subpage", external_subpage_html),
    })

    tree = LinkTree("https://target.onion", depth=2, client=client, crawl_external=True)
    tree.load()

    assert tree.get_node("https://external-site.org/page") is not None
    assert tree.get_node("https://external-site.org/subpage") is not None


def test_linknode_domain_type_and_timestamps():
    """Verify nodes record domain_type and real UTC timestamps."""
    from datetime import datetime
    from torbot.crawl_result import CrawlResultAdapter

    root_html = '''
    <html><title>Main Site</title>
      <a href="https://example.com/subpage">Subpage</a>
      <a href="https://external.org/info">External Info</a>
    </html>
    '''
    sub_html = '<html><title>Subpage</title></html>'
    ext_html = '<html><title>External Info</title></html>'

    client = CountingClient({
        "https://example.com": MockResponse("https://example.com", root_html),
        "https://example.com/subpage": MockResponse("https://example.com/subpage", sub_html),
        "https://external.org/info": MockResponse("https://external.org/info", ext_html),
    })

    tree = LinkTree("https://example.com", depth=1, client=client)
    tree.load()

    root_node = tree.get_node("https://example.com")
    assert root_node.data.domain_type == "Internal"
    assert root_node.data.timestamp is not None
    # Parse timestamp to confirm it's valid ISO 8601 UTC
    dt_root = datetime.fromisoformat(root_node.data.timestamp.replace("Z", "+00:00"))
    assert dt_root.tzinfo is not None

    sub_node = tree.get_node("https://example.com/subpage")
    assert sub_node.data.domain_type == "Internal"
    assert sub_node.data.timestamp is not None
    dt_sub = datetime.fromisoformat(sub_node.data.timestamp.replace("Z", "+00:00"))
    assert dt_sub.tzinfo is not None

    ext_node = tree.get_node("https://external.org/info")
    assert ext_node.data.domain_type == "External"
    assert ext_node.data.timestamp is not None
    dt_ext = datetime.fromisoformat(ext_node.data.timestamp.replace("Z", "+00:00"))
    assert dt_ext.tzinfo is not None

    # Test CrawlResultAdapter exports domainType and timestamp
    payload = CrawlResultAdapter(tree, uses_tor=False).result()
    pages_by_url = {p["url"]: p for p in payload["pages"]}
    assert pages_by_url["https://example.com"]["domainType"] == "Internal"
    assert pages_by_url["https://example.com"]["timestamp"] == root_node.data.timestamp
    assert pages_by_url["https://example.com/subpage"]["domainType"] == "Internal"
    assert pages_by_url["https://external.org/info"]["domainType"] == "External"
    assert pages_by_url["https://external.org/info"]["timestamp"] == ext_node.data.timestamp


def test_only_http_200_pages_are_counted_and_non_200_not_recursed():
    """Verify non-200 pages are not queued for recursion and CrawlResultAdapter exports only 200 OK pages."""
    from torbot.crawl_result import CrawlResultAdapter

    root_html = '''
    <html><title>Root Site</title>
      <a href="https://example.com/ok-child">Child 200 OK</a>
      <a href="https://example.com/missing-404">Child 404</a>
      <a href="https://example.com/forbidden-403">Child 403</a>
    </html>
    '''
    ok_child_html = '''
    <html><title>OK Child</title>
      <a href="https://example.com/deep-from-ok">Deep Link</a>
    </html>
    '''
    missing_html = '''
    <html><title>404 Error Page</title>
      <a href="https://example.com/should-not-recurse">Should Never Recurse</a>
    </html>
    '''
    forbidden_html = '''
    <html><title>403 Forbidden</title>
      <a href="https://example.com/forbidden-link">Forbidden Link</a>
    </html>
    '''
    deep_html = '<html><title>Deep Page</title></html>'

    client = CountingClient({
        "https://example.com": MockResponse("https://example.com", root_html, status_code=200),
        "https://example.com/ok-child": MockResponse("https://example.com/ok-child", ok_child_html, status_code=200),
        "https://example.com/missing-404": MockResponse("https://example.com/missing-404", missing_html, status_code=404),
        "https://example.com/forbidden-403": MockResponse("https://example.com/forbidden-403", forbidden_html, status_code=403),
        "https://example.com/deep-from-ok": MockResponse("https://example.com/deep-from-ok", deep_html, status_code=200),
        "https://example.com/should-not-recurse": MockResponse("https://example.com/should-not-recurse", "never reached", status_code=200),
    })

    tree = LinkTree("https://example.com", depth=3, client=client)
    tree.load()

    # 1. 404 child was fetched once, but links inside 404 were NOT recursed into
    assert client.request_counts["https://example.com/missing-404"] == 1
    assert "https://example.com/should-not-recurse" not in client.request_counts

    # 2. 200 child links WERE recursed into
    assert client.request_counts["https://example.com/deep-from-ok"] == 1

    # 3. Verified pages count contains only 200 OK nodes
    verified_pages = tree.get_verified_pages()
    verified_urls = {p.identifier for p in verified_pages}
    assert verified_urls == {
        "https://example.com",
        "https://example.com/ok-child",
        "https://example.com/deep-from-ok",
    }
    assert "https://example.com/missing-404" not in verified_urls
    assert "https://example.com/forbidden-403" not in verified_urls

    # 4. URL stats separates verified 200 pages from non-200 / unverified URLs
    stats = tree.get_url_stats()
    assert stats["verifiedPages"] == 3
    assert stats["totalPages"] == 3
    assert stats["unverifiedOrNon200Urls"] == 2
    assert stats["statusCounts"] == {200: 3, 404: 1, 403: 1}

    # 5. CrawlResultAdapter exports ONLY verified 200 pages in the pages list
    result = CrawlResultAdapter(tree, uses_tor=False).result()
    exported_urls = [p["url"] for p in result["pages"]]
    assert len(exported_urls) == 3
    assert set(exported_urls) == {
        "https://example.com",
        "https://example.com/ok-child",
        "https://example.com/deep-from-ok",
    }
    # All exported pages have status 200
    for p in result["pages"]:
        assert p["status"] == 200

    assert result["stats"]["statusCounts"] == {200: 3, 404: 1, 403: 1}
    assert result["stats"]["unverifiedOrNon200Urls"] == 2
    assert len(result["discoveredUrls"]) >= 5


def test_crawler_handles_redirects_and_soft_404_responses():
    """Verify redirects are followed cleanly and soft-404 responses are identified and quarantined."""
    from torbot.crawl_result import CrawlResultAdapter

    root_html = '''
    <html><title>Main Hub</title>
      <a href="https://example.com/redirect-to-good">Redirect to Good</a>
      <a href="https://example.com/soft-404-error">Fake 200 Not Found</a>
    </html>
    '''
    good_page_html = '<html><title>Good Destination</title></html>'
    # Soft 404: Returns HTTP 200, but title is "404 Not Found"
    soft_404_html = '''
    <html><head><title>404 Not Found</title></head>
    <body><h1>404 Error</h1><p>Page does not exist</p>
      <a href="https://example.com/should-not-reach">Trap</a>
    </body></html>
    '''

    # Mock response with redirect history
    redirect_resp = MockResponse(
        "https://example.com/good-dest",
        good_page_html,
        status_code=200,
    )
    redirect_resp.url = "https://example.com/good-dest"

    soft_404_resp = MockResponse(
        "https://example.com/soft-404-error",
        soft_404_html,
        status_code=200,  # Server falsely returns 200
    )

    client = CountingClient({
        "https://example.com": MockResponse("https://example.com", root_html, status_code=200),
        "https://example.com/redirect-to-good": redirect_resp,
        "https://example.com/soft-404-error": soft_404_resp,
        "https://example.com/should-not-reach": MockResponse("https://example.com/should-not-reach", "trap", status_code=200),
    })

    tree = LinkTree("https://example.com", depth=2, client=client)
    tree.load()

    # 1. Soft-404 is identified as 404 and NOT recursed into
    assert "https://example.com/should-not-reach" not in client.request_counts

    # 2. Verified pages contains only Root and the Redirect destination
    verified_pages = tree.get_verified_pages()
    verified_urls = {p.identifier for p in verified_pages}
    assert "https://example.com" in verified_urls
    assert "https://example.com/redirect-to-good" in verified_urls
    assert "https://example.com/soft-404-error" not in verified_urls

    # 3. Stats records soft-404 in 404 counts and unverified URLs
    stats = tree.get_url_stats()
    assert stats["verifiedPages"] == 2
    assert stats["unverifiedOrNon200Urls"] == 1
    assert stats["statusCounts"].get(404) == 1

    # 4. CrawlResultAdapter exports only verified 200 pages
    res = CrawlResultAdapter(tree, uses_tor=False).result()
    assert len(res["pages"]) == 2
    assert all(p["status"] == 200 for p in res["pages"])


def test_validate_onion_url():
    """Test Tor v3 onion address validation and rejection of invalid/deprecated formats."""
    from torbot.modules.linktree import validate_onion_url

    # Valid v3 56-character base32 onion
    valid_v3 = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
    ok, err = validate_onion_url(f"http://{valid_v3}/path")
    assert ok is True
    assert err is None

    # Clearnet URL is passed through as valid
    ok, err = validate_onion_url("https://example.com/test")
    assert ok is True
    assert err is None

    # Invalid onion: too short (invalid format)
    ok, err = validate_onion_url("http://invalid.onion")
    assert ok is False
    assert "56 base32 characters" in err

    # Deprecated v2 onion (16 characters)
    ok, err = validate_onion_url("http://expyuz5wqqfdgah5.onion")
    assert ok is False
    assert "v2" in err.lower()

    # Empty URL
    ok, err = validate_onion_url("")
    assert ok is False


def test_classify_crawl_error():
    """Test classification of network and dark web crawler errors."""
    from torbot.modules.linktree import classify_crawl_error

    # Tor proxy connection refused
    cat, msg = classify_crawl_error("ConnectError: [Errno 111] Connection refused", "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion")
    assert cat == "proxy_offline"
    assert "offline" in msg.lower() or "connection" in msg.lower()

    # SOCKS5 server failure on onion (service down/non-existent)
    cat, msg = classify_crawl_error("ProxyError: General SOCKS server failure", "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion")
    assert cat == "onion_service_unavailable"
    assert "unreachable" in msg.lower() or "offline" in msg.lower()

    # Invalid onion URL
    cat, msg = classify_crawl_error("Any error", "http://invalid.onion")
    assert cat == "invalid_input"

    # Timeout
    cat, msg = classify_crawl_error("httpx.ReadTimeout: The read operation timed out", "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion")
    assert cat == "timeout"


def test_onion_relative_links_and_contact_extraction():
    """Verify onion websites resolve relative links against the onion base URL and extract contacts."""
    onion_base = "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
    root_html = f'''
    <html>
      <head><title>DuckDuckGo Onion</title></head>
      <body>
        <a href="/settings">Settings</a>
        <a href="about">About</a>
        <a href="https://example.com/external">Clearnet Link</a>
        <a href="mailto:privacy@duckduckgo.onion">Email</a>
        <a href="tel:+15551234567">Phone</a>
      </body>
    </html>
    '''
    settings_html = '<html><head><title>Settings</title></head><body><h1>Settings Page</h1></body></html>'
    about_html = '<html><head><title>About</title></head><body><h1>About Page</h1></body></html>'

    client = CountingClient({
        onion_base: MockResponse(onion_base, root_html),
        f"{onion_base}/settings": MockResponse(f"{onion_base}/settings", settings_html),
        f"{onion_base}/about": MockResponse(f"{onion_base}/about", about_html),
    })

    tree = LinkTree(onion_base, depth=1, client=client)
    tree.load()

    # Auto-resolves relative links
    assert tree.get_node(f"{onion_base}/settings") is not None
    assert tree.get_node(f"{onion_base}/about") is not None

    # Checks domain type classification
    root_node = tree.get_node(onion_base)
    assert root_node.data.domain_type == "Internal"
    assert "privacy@duckduckgo.onion" in root_node.data.emails

    # Clearnet link is marked External
    assert "https://example.com/external" in tree.external_links

    # Crawl result output
    result = tree.to_crawl_result(uses_tor=True)
    assert result["terminalStatus"] == "completed"
    assert len(result["pages"]) >= 3


def test_onion_seed_failure_terminal_status():
    # Valid v3 format (56 chars) but simulated unreachable
    onion_url = f"http://{'a'*56}.onion"

    class FailingClient:
        def get(self, url: str, **kwargs):
            raise Exception("ProxyError: Proxy Server could not connect: General SOCKS server failure.")

    tree = LinkTree(onion_url, depth=1, client=FailingClient())
    tree.load()

    assert tree.root is None
    assert len(tree.crawl_failures) == 1
    assert tree.crawl_failure_category == "onion_service_unavailable"

    result = tree.to_crawl_result(uses_tor=True)
    assert result["terminalStatus"] == "failed"
    assert "error" in result["diagnostics"]


def test_scoped_transport_mounts_configuration():
    """Verify that mounts dictionary configures scoped SSL bypass only for .onion,
    and strictly enforces verify=True for all clearnet HTTPS traffic."""
    import httpx
    socks5_proxy = "socks5://127.0.0.1:9050"
    onion_transport = httpx.HTTPTransport(
        proxy=socks5_proxy,
        verify=False,
    )
    default_transport = httpx.HTTPTransport(
        proxy=socks5_proxy,
        verify=True,
    )
    mounts = {
        "all://*.onion": onion_transport,
        "all://": default_transport,
    }

    # Verify mounts patterns
    assert "all://*.onion" in mounts
    assert "all://" in mounts

    # Verify .onion transport permits self-signed TLS over Tor SOCKS5 proxy
    onion_t = mounts["all://*.onion"]
    assert onion_t._pool._ssl_context.verify_mode == 0  # ssl.CERT_NONE / verify=False

    # Verify clearnet default transport strictly enforces CA verification
    default_t = mounts["all://"]
    assert default_t._pool._ssl_context.verify_mode != 0  # ssl.CERT_REQUIRED / verify=True


def test_onion_https_redirect_marks_unverified_ssl():
    """Verify that when an .onion HTTP URL redirects to HTTPS,
    LinkTree captures the URL, tracks it in unverified_ssl_urls,
    and sets unverified_ssl on the node."""
    http_onion = "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
    https_onion = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/"

    class RedirectClient:
        def get(self, url: str, **kwargs):
            return MockResponse(https_onion, "<html><title>DuckDuckGo Dark Web</title></html>", 200)

    tree = LinkTree(http_onion, depth=0, client=RedirectClient())
    tree.load()

    assert tree.root is not None
    root_node = tree.get_node(tree.root)
    assert getattr(root_node.data, "unverified_ssl", False) is True

    # Verify crawl result serialization
    result = tree.to_crawl_result(uses_tor=True)
    assert result["terminalStatus"] == "completed"
    assert "sslStatus" in result["diagnostics"]
    assert "unverifiedSslCount" in result["diagnostics"]

    page_entry = result["pages"][0]
    assert page_entry.get("unverifiedSsl") is True


def test_clearnet_https_not_marked_as_unverified_ssl():
    """Verify regular clearnet HTTPS URLs are NOT marked as unverified SSL."""
    clearnet_url = "https://example.com"

    class ClearnetClient:
        def get(self, url: str, **kwargs):
            return MockResponse(clearnet_url, "<html><title>Example</title></html>", 200)

    tree = LinkTree(clearnet_url, depth=0, client=ClearnetClient())
    tree.load()

    assert tree.root is not None
    root_node = tree.get_node(tree.root)
    assert getattr(root_node.data, "unverified_ssl", False) is False
    assert len(tree.unverified_ssl_urls) == 0

    result = tree.to_crawl_result(uses_tor=False)
    assert "sslStatus" not in result["diagnostics"]
    page_entry = result["pages"][0]
    assert page_entry.get("unverifiedSsl") is False


def test_classify_crawl_error_ssl_failure():
    """Verify classify_crawl_error categorizes standard SSL certificate errors."""
    err_str = "httpx.ConnectError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate (_ssl.c:1000)"
    cat, msg = classify_crawl_error(err_str, "https://expired.badssl.com")

    assert cat == "ssl_error"
    assert "SSL Certificate Verification Failed" in msg







