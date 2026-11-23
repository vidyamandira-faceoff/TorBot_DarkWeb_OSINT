"""Unit and integration tests for multi-URL scanning (up to 10 URLs) and
step-by-step Depth 0 to Depth 5 link discovery.
"""

import json
from unittest.mock import MagicMock

import pytest

from torbot.cli import parse_urls_input, set_arguments, _merge_crawl_results
from torbot.crawl_result import CrawlResultAdapter
from torbot.modules.linktree import LinkTree
from web_ui import app


class MockResponse:
    def __init__(self, url: str, text: str, status_code: int = 200):
        self.url = url
        self.text = text
        self.status_code = status_code


class MockClient:
    def __init__(self, responses: dict[str, MockResponse]):
        self.responses = responses
        self.request_counts: dict[str, int] = {}

    def get(self, url: str, **kwargs) -> MockResponse:
        self.request_counts[url] = self.request_counts.get(url, 0) + 1
        if url in self.responses:
            return self.responses[url]
        return MockResponse(url, "<html><title>Not Found</title></html>", 404)


# =====================================================================
# 1. Multi-URL Input Parsing & Upper Bound (10 URLs)
# =====================================================================

def test_parse_urls_input_empty_and_none():
    assert parse_urls_input(None) == []
    assert parse_urls_input("") == []
    assert parse_urls_input("   ") == []
    assert parse_urls_input([]) == []


def test_parse_urls_input_single_url():
    urls = parse_urls_input("https://example.com")
    assert urls == ["https://example.com"]


def test_parse_urls_input_delimiters():
    # Comma-delimited
    comma_raw = "https://site1.com, https://site2.com, https://site3.com"
    assert parse_urls_input(comma_raw) == [
        "https://site1.com",
        "https://site2.com",
        "https://site3.com",
    ]

    # Newline-delimited
    newline_raw = "https://site1.com\nhttps://site2.com\nhttps://site3.com"
    assert parse_urls_input(newline_raw) == [
        "https://site1.com",
        "https://site2.com",
        "https://site3.com",
    ]

    # Semicolon-delimited
    semi_raw = "https://site1.com; https://site2.com; https://site3.com"
    assert parse_urls_input(semi_raw) == [
        "https://site1.com",
        "https://site2.com",
        "https://site3.com",
    ]

    # Space-delimited
    space_raw = "https://site1.com https://site2.com https://site3.com"
    assert parse_urls_input(space_raw) == [
        "https://site1.com",
        "https://site2.com",
        "https://site3.com",
    ]

    # Mixed list input
    list_raw = ["https://site1.com, https://site2.com", "https://site3.com\nhttps://site4.com"]
    assert parse_urls_input(list_raw) == [
        "https://site1.com",
        "https://site2.com",
        "https://site3.com",
        "https://site4.com",
    ]


def test_parse_urls_input_deduplication():
    raw = "https://site1.com, https://site2.com, https://site1.com, https://site2.com"
    result = parse_urls_input(raw)
    assert result == ["https://site1.com", "https://site2.com"]


def test_parse_urls_input_caps_at_max_10_urls():
    # 15 distinct URLs
    urls_15 = [f"https://target{i}.test" for i in range(1, 16)]
    raw_str = "\n".join(urls_15)

    result = parse_urls_input(raw_str)
    assert len(result) == 10
    assert result == [f"https://target{i}.test" for i in range(1, 11)]

    # As a list of 15 strings
    result_list = parse_urls_input(urls_15)
    assert len(result_list) == 10
    assert result_list == [f"https://target{i}.test" for i in range(1, 11)]


# =====================================================================
# 2. CLI Multi-URL Argument Parser
# =====================================================================

def test_cli_accepts_multiple_urls():
    parser = set_arguments()

    # Space separated positional or multiple args to -u
    args1 = parser.parse_args(["-u", "https://site1.com", "https://site2.com"])
    assert args1.url == ["https://site1.com", "https://site2.com"]

    # Multiple -u flags
    args2 = parser.parse_args(["-u", "https://site1.com", "-u", "https://site2.com"])
    assert args2.url == ["https://site1.com", "https://site2.com"]

    # --urls flag
    args3 = parser.parse_args(["--urls", "https://site1.com", "https://site2.com", "https://site3.com"])
    assert args3.url == ["https://site1.com", "https://site2.com", "https://site3.com"]

    # Up to 10 URLs via CLI
    cli_10 = [f"https://site{i}.com" for i in range(10)]
    args10 = parser.parse_args(["--urls", *cli_10])
    parsed_10 = parse_urls_input(args10.url)
    assert len(parsed_10) == 10


# =====================================================================
# 3. Step-by-Step Crawl (Depth 0 through Depth 5) & Discovered Links
# =====================================================================

def test_depth_0_records_discovered_links():
    """Depth 0 crawls only the seed URL, but parses and tracks all outgoing links."""
    html_root = """
    <html>
        <head><title>Depth 0 Target</title></head>
        <body>
            <a href="https://example.com/p1">Page 1</a>
            <a href="https://example.com/p2">Page 2</a>
            <a href="https://other.com/ext">External</a>
        </body>
    </html>
    """
    client = MockClient({"https://example.com": MockResponse("https://example.com", html_root)})

    tree = LinkTree("https://example.com", depth=0, client=client)
    tree.load()

    # Tree should have only the root node (no expansion into children)
    assert len(tree.all_nodes()) == 1
    root_node = tree.get_node("https://example.com")
    assert root_node is not None
    assert root_node.data.discovered_links == [
        "https://example.com/p1",
        "https://example.com/p2",
        "https://other.com/ext",
    ]

    # Discovered links by depth level 0
    by_level = tree.get_discovered_links_by_level()
    assert 0 in by_level
    disc_lvl0 = [d["url"] for d in by_level[0]]
    assert disc_lvl0 == [
        "https://example.com/p1",
        "https://example.com/p2",
        "https://other.com/ext",
    ]
    # Levels 1 to 5 should be empty for Depth 0
    for lvl in range(1, 6):
        assert by_level[lvl] == []


def test_step_by_step_crawling_depth_0_to_5():
    """Verify crawler walks step-by-step from Depth 0 to Depth 5, recording
    discovered outgoing links at every depth level (0 through 5)."""
    # Build 6 levels of pages: Depth 0 (root) -> Depth 1 -> Depth 2 -> Depth 3 -> Depth 4 -> Depth 5 (leaf)
    site_pages = {
        "https://example.com": MockResponse(
            "https://example.com",
            '<html><title>D0</title><a href="https://example.com/d1">D1 Link</a><a href="https://example.com/d0_side">D0 Side</a></html>',
        ),
        "https://example.com/d0_side": MockResponse(
            "https://example.com/d0_side",
            '<html><title>D0 Side</title></html>',
        ),
        "https://example.com/d1": MockResponse(
            "https://example.com/d1",
            '<html><title>D1</title><a href="https://example.com/d2">D2 Link</a><a href="https://ext1.com/">Ext 1</a></html>',
        ),
        "https://example.com/d2": MockResponse(
            "https://example.com/d2",
            '<html><title>D2</title><a href="https://example.com/d3">D3 Link</a></html>',
        ),
        "https://example.com/d3": MockResponse(
            "https://example.com/d3",
            '<html><title>D3</title><a href="https://example.com/d4">D4 Link</a></html>',
        ),
        "https://example.com/d4": MockResponse(
            "https://example.com/d4",
            '<html><title>D4</title><a href="https://example.com/d5">D5 Link</a></html>',
        ),
        "https://example.com/d5": MockResponse(
            "https://example.com/d5",
            '<html><title>D5</title><a href="https://example.com/d6_beyond">D6 Beyond</a></html>',
        ),
        "https://example.com/d6_beyond": MockResponse(
            "https://example.com/d6_beyond",
            '<html><title>D6</title></html>',
        ),
    }

    client = MockClient(site_pages)
    tree = LinkTree("https://example.com", depth=5, client=client)
    tree.load()

    # 1. Depth 6 should NOT be fetched/expanded as a node
    assert tree.get_node("https://example.com/d6_beyond") is None
    assert "https://example.com/d6_beyond" not in client.request_counts

    # 2. Node at depth 5 exists and has its outgoing links parsed into data.discovered_links
    node_d5 = tree.get_node("https://example.com/d5")
    assert node_d5 is not None
    assert tree.depth(node_d5) == 5
    assert node_d5.data.discovered_links == ["https://example.com/d6_beyond"]

    # 3. Discovered by depth contains discovered links at each step from Level 0 to Level 5
    by_level = tree.get_discovered_links_by_level()

    # Level 0 (links from root)
    urls_lvl0 = [d["url"] for d in by_level[0]]
    assert "https://example.com/d1" in urls_lvl0
    assert "https://example.com/d0_side" in urls_lvl0

    # Level 1 (links from d1 & d0_side)
    urls_lvl1 = [d["url"] for d in by_level[1]]
    assert "https://example.com/d2" in urls_lvl1
    assert "https://ext1.com/" in urls_lvl1

    # Level 2 (links from d2)
    urls_lvl2 = [d["url"] for d in by_level[2]]
    assert "https://example.com/d3" in urls_lvl2

    # Level 3 (links from d3)
    urls_lvl3 = [d["url"] for d in by_level[3]]
    assert "https://example.com/d4" in urls_lvl3

    # Level 4 (links from d4)
    urls_lvl4 = [d["url"] for d in by_level[4]]
    assert "https://example.com/d5" in urls_lvl4

    # Level 5 (links from d5 leaf)
    urls_lvl5 = [d["url"] for d in by_level[5]]
    assert "https://example.com/d6_beyond" in urls_lvl5

    # 4. Check get_url_stats() includes discoveredUrlsByDepth
    stats = tree.get_url_stats()
    assert "discoveredUrlsByDepth" in stats
    for lvl in range(6):
        assert str(lvl) in stats["discoveredUrlsByDepth"]

    # 5. Check CrawlResultAdapter preserves discoveredByDepth
    adapter = CrawlResultAdapter(tree, uses_tor=False)
    crawl_result = adapter.result()
    assert "discoveredByDepth" in crawl_result
    assert len(crawl_result["discoveredByDepth"]["5"]) > 0


def test_linktree_show_discovered_links_by_level_output(capsys):
    """Verify showDiscoveredLinksByLevel and showTable output display depth breakdown."""
    html_root = '<html><title>Root</title><a href="https://example.com/child">Child</a></html>'
    html_child = '<html><title>Child</title><a href="https://example.com/grandchild">Grandchild</a></html>'

    client = MockClient({
        "https://example.com": MockResponse("https://example.com", html_root),
        "https://example.com/child": MockResponse("https://example.com/child", html_child),
    })

    tree = LinkTree("https://example.com", depth=1, client=client)
    tree.load()

    tree.showDiscoveredLinksByLevel()
    out = capsys.readouterr().out

    assert "DISCOVERED LINKS BREAKDOWN BY LEVEL" in out
    assert "Level 0" in out
    assert "https://example.com/child" in out
    assert "Level 1" in out
    assert "https://example.com/grandchild" in out

    tree.showTable()
    table_out = capsys.readouterr().out
    assert "Discovered" in table_out
    assert "DISCOVERED LINKS BREAKDOWN BY LEVEL" in table_out


# =====================================================================
# 4. Result Aggregation across Multiple Target URLs
# =====================================================================

def test_merge_crawl_results_combines_targets():
    import argparse
    client1 = MockClient({
        "https://site1.com": MockResponse("https://site1.com", '<a href="https://site1.com/a">A</a>'),
    })
    client2 = MockClient({
        "https://site2.com": MockResponse("https://site2.com", '<a href="https://site2.com/b">B</a>'),
    })
    t1 = LinkTree("https://site1.com", depth=1, client=client1)
    t1.load()
    t2 = LinkTree("https://site2.com", depth=1, client=client2)
    t2.load()

    args = argparse.Namespace(disable_socks5=True, depth=1)
    merged = _merge_crawl_results([t1, t2], targets=["https://site1.com", "https://site2.com"], args=args, version="1.0.0")
    assert merged["target"] == "https://site1.com"
    assert merged["targets"] == ["https://site1.com", "https://site2.com"]
    assert len(merged["pages"]) == 2
    assert len(merged["discoveredUrls"]) == 4
    assert len(merged["discoveredByDepth"]["0"]) == 2
    assert merged["stats"]["totalPages"] == 2
    assert merged["stats"]["statusCounts"][200] == 2


# =====================================================================
# 5. Web UI Multi-URL POST & Discovered Links By Level Tab
# =====================================================================

def test_web_ui_post_multiple_targets(monkeypatch, tmp_path):
    """Verify Web UI accepts up to 10 URLs in the form textarea and displays
    both the Tested Targets tab and the Discovered Links by Level tab."""
    target_urls_input = "https://alpha.test, https://beta.test\nhttps://gamma.test"
    result_file = tmp_path / "multi-target-result.json"

    mock_result_data = {
        "schemaVersion": 1,
        "target": "https://alpha.test",
        "targets": ["https://alpha.test", "https://beta.test", "https://gamma.test"],
        "terminalStatus": "completed",
        "pages": [
            {"url": "https://alpha.test", "title": "Alpha", "depth": 0, "status": 200, "outcome": "fetched"},
            {"url": "https://beta.test", "title": "Beta", "depth": 0, "status": 200, "outcome": "fetched"},
            {"url": "https://gamma.test", "title": "Gamma", "depth": 0, "status": 200, "outcome": "fetched"},
        ],
        "discoveredUrls": [
            {"url": "https://alpha.test/sub", "depth": 0, "status": 200, "parentUrl": "https://alpha.test"},
            {"url": "https://beta.test/sub", "depth": 1, "status": 200, "parentUrl": "https://beta.test"},
        ],
        "discoveredByDepth": {
            "0": [{"url": "https://alpha.test/sub", "depth": 0, "status": 200, "parentUrl": "https://alpha.test"}],
            "1": [{"url": "https://beta.test/sub", "depth": 1, "status": 200, "parentUrl": "https://beta.test"}],
            "2": [], "3": [], "4": [], "5": [],
        },
        "stats": {
            "totalPages": 3,
            "verifiedPages": 3,
            "totalDiscoveredUrls": 2,
            "uniqueDiscoveredUrls": 2,
            "unverifiedOrNon200Urls": 0,
            "statusCounts": {"200": 3},
        },
    }
    result_file.write_text(json.dumps(mock_result_data), encoding="utf-8")
    monkeypatch.setattr("web_ui.RESULT_FILE", result_file)

    def mock_subprocess_run(cmd, *args, **kwargs):
        result_file.write_text(json.dumps(mock_result_data), encoding="utf-8")
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "TorBot multi-target crawl completed."
        mock_proc.stderr = ""
        # Check that multiple URLs were passed as arguments to main.py
        assert "-u" in cmd
        u_idx = cmd.index("-u")
        assert cmd[u_idx + 1] == "https://alpha.test"
        assert cmd[u_idx + 2] == "https://beta.test"
        assert cmd[u_idx + 3] == "https://gamma.test"
        return mock_proc

    monkeypatch.setattr("subprocess.run", mock_subprocess_run)

    client = app.test_client()
    response = client.post(
        "/",
        data={
            "url": target_urls_input,
            "depth": "1",
            "action": "table",
            "disable_socks": "on",
        },
    )

    assert response.status_code == 200
    html = response.data.decode("utf-8")

    # 1. KPI Card displays Targets Tested = 3
    assert '<div class="kpi-label">Targets Tested</div>' in html
    assert '<div class="kpi-val">3</div>' in html

    # 2. Tab Navigation has Tested Targets (3) button
    assert "🎯 Tested Targets (3)" in html

    # 3. Discovered Links by Level tab is present and displays discovered links
    assert "🔗 Discovered Links by Level (2)" in html
    assert 'id="tab-discovered"' in html
    assert "Depth 0 (1)" in html
    assert "Depth 1 (1)" in html
    assert "https://alpha.test/sub" in html
    assert "https://beta.test/sub" in html

    # 4. Tested Targets tab is present and displays the 3 targets
    assert 'id="tab-targets"' in html
    assert "https://alpha.test" in html
    assert "https://beta.test" in html
    assert "https://gamma.test" in html
