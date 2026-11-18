import httpx
import pytest
from bs4 import BeautifulSoup

from torbot.modules.info import (
    get_robots_txt,
    get_intel,
    get_dot_git,
    get_dot_svn,
    get_dot_htaccess,
    get_bitcoin_address,
    display_webpage_description,
    execute_all,
)
from torbot.modules.linktree import LinkTree


def test_get_intel_with_response_object(capsys):
    html = """
    <html>
        <body>
            <p>Contact: admin@example.com</p>
            <p>Storage: mybucket.s3.amazonaws.com</p>
        </body>
    </html>
    """
    resp = httpx.Response(200, text=html)
    with httpx.Client() as client:
        get_intel(client, "https://example.com", resp)

    out = capsys.readouterr().out
    assert "admin@example.com" in out
    assert "mybucket.s3.amazonaws.com" in out


def test_get_bitcoin_address_extracts_addresses(capsys):
    html = """
    <html>
        <body>
            <p>Donate BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy</p>
            <p>Bech32: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq</p>
        </body>
    </html>
    """
    resp = httpx.Response(200, text=html)
    with httpx.Client() as client:
        get_bitcoin_address(client, "https://example.com", resp)

    out = capsys.readouterr().out
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in out
    assert "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy" in out
    assert "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" in out


def test_get_robots_txt_queries_robots_url(capsys):
    def mock_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nDisallow: /admin\nAllow: /public\n")
        return httpx.Response(404, text="Not Found")

    with httpx.Client(transport=httpx.MockTransport(mock_handler)) as client:
        get_robots_txt(client, "https://example.com/page", httpx.Response(200, text="<html></html>"))

    out = capsys.readouterr().out
    assert "Robots.txt found" in out


def test_execute_all_runs_without_exceptions(capsys):
    html = """
    <html>
        <head>
            <meta name="description" content="Test Page Description" />
        </head>
        <body>
            <p>Email: test@domain.com</p>
            <p>BTC: 1BoatSLRHtKNngkdXEeobR76b53LETtpyT</p>
        </body>
    </html>
    """
    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=html)

    with httpx.Client(transport=httpx.MockTransport(mock_handler)) as client:
        execute_all(client, "https://example.com")

    out = capsys.readouterr().out
    assert "Test Page Description" in out
    assert "test@domain.com" in out
    assert "1BoatSLRHtKNngkdXEeobR76b53LETtpyT" in out


def test_linktree_with_resolve_relative():
    root_html = """
    <html>
        <head><title>Root</title></head>
        <body>
            <a href="/subpath">Relative Link</a>
            <a href="https://external.test/page">External Link</a>
        </body>
    </html>
    """
    sub_html = "<html><head><title>Subpath Page</title></head></html>"
    ext_html = "<html><head><title>External Page</title></head></html>"

    def mock_handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == "https://example.com":
            return httpx.Response(200, text=root_html)
        elif url == "https://example.com/subpath":
            return httpx.Response(200, text=sub_html)
        elif url == "https://external.test/page":
            return httpx.Response(200, text=ext_html)
        return httpx.Response(404, text="Not Found")

    with httpx.Client(transport=httpx.MockTransport(mock_handler)) as client:
        tree = LinkTree("https://example.com", depth=1, client=client, resolve_relative=True)
        tree.load()

        assert tree.get_node("https://example.com") is not None
        assert tree.get_node("https://example.com/subpath") is not None
        assert tree.get_node("https://external.test/page") is not None
        assert tree.get_node("https://example.com/subpath").tag == "Subpath Page"
