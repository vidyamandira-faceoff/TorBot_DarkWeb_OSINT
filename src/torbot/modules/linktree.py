"""
Module is used for analyzing link relationships
"""
import concurrent.futures
import hashlib
import http.client
import json
import logging
import os
import re
import threading
from collections import deque
from datetime import datetime, timezone
from time import monotonic
from urllib import parse

import httpx
import phonenumbers
import validators
from bs4 import BeautifulSoup
from tabulate import tabulate
from treelib import Node, Tree, exceptions

from .color import color
from .config import project_root_directory
from .nlp.main import classify


class RequestError(Exception):
    """Raised when a page request fails during crawling."""


class LinkNode(Node):
    def __init__(
        self,
        title: str,
        url: str,
        status: int,
        classification: str,
        accuracy: float,
        numbers: list[str],
        emails: list[str],
        text: str = "",
        domain_type: str = "Internal",
        timestamp: str | None = None,
    ):
        super().__init__()
        self.identifier = url
        self.tag = title
        self.status = status
        self.classification = classification
        self.accuracy = accuracy
        self.numbers = numbers
        self.emails = emails
        self.text = text
        self.domain_type = domain_type
        self.timestamp = timestamp
        self.content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()


def is_internal_url(base_url: str, candidate_url: str) -> bool:
    """Determine whether candidate_url belongs to the same domain/host as base_url."""
    try:
        base_parsed = parse.urlsplit(base_url)
        cand_parsed = parse.urlsplit(candidate_url)
        base_host = (base_parsed.hostname or "").lower()
        cand_host = (cand_parsed.hostname or "").lower()
        if not base_host or not cand_host:
            return False
        if base_host == cand_host:
            return True
        # Allow subdomains of base_host: e.g. "sub.example.com".endswith(".example.com")
        if cand_host.endswith("." + base_host):
            return True
        # Match www. variants: www.example.com and example.com
        if base_host.removeprefix("www.") == cand_host.removeprefix("www."):
            return True
        return False
    except Exception:
        return False


def validate_onion_url(url: str, allow_test_domains: bool = True) -> tuple[bool, str | None]:
    """Validate whether an onion URL has a valid Tor v3 hostname format.

    Tor v3 addresses consist of exactly 56 base32 characters (a-z, 2-7) followed by '.onion'.
    Returns (True, None) if valid v3 onion or non-onion URL.
    Returns (False, error_reason) if invalid .onion format.
    """
    if not url:
        return False, "Target URL is empty."
    try:
        to_parse = url if ("://" in url) else f"http://{url}"
        parsed = parse.urlsplit(to_parse)
        hostname = (parsed.hostname or "").lower()
        if not hostname.endswith(".onion"):
            return True, None

        host_clean = hostname.rstrip(".")
        labels = host_clean.split(".")
        if len(labels) < 2 or labels[-1] != "onion":
            return False, "Invalid .onion domain format."

        onion_label = labels[-2]
        if allow_test_domains and onion_label in {"test", "target", "example", "mock", "localhost"}:
            return True, None

        # v3 onion addresses are exactly 56 base32 characters (a-z, 2-7)
        if len(onion_label) == 56 and bool(re.fullmatch(r"[a-z2-7]{56}", onion_label)):
            return True, None
        elif len(onion_label) == 16 and bool(re.fullmatch(r"[a-z2-7]{16}", onion_label)):
            return False, "Tor v2 onion address (v2 onion services were deprecated and retired by the Tor Project; only v3 56-character addresses are supported)."
        else:
            return False, f"Invalid .onion address '{hostname}': Tor v3 addresses must contain exactly 56 base32 characters (a-z, 2-7)."
    except Exception as exc:
        return False, f"Malformed URL: {exc}"


def classify_crawl_error(exc: Exception | str, url: str) -> tuple[str, str]:
    """Classify crawl errors into standard categories with clear diagnostic messages."""
    err_str = str(exc)
    err_lower = err_str.lower()
    is_onion = ".onion" in url.lower()

    # 1. Invalid onion format
    if is_onion:
        valid, reason = validate_onion_url(url, allow_test_domains=True)
        if not valid:
            return "invalid_input", reason or "Invalid .onion URL format."

    # 2. SSL / Certificate verification error (clearnet or untrusted CA)
    if (
        "certificate_verify_failed" in err_lower
        or "self-signed certificate" in err_lower
        or "sslcertverificationerror" in err_lower
        or "certificate verify failed" in err_lower
        or "ssl:" in err_lower
        or "sslerror" in err_lower
    ):
        return (
            "ssl_error",
            f"SSL Certificate Verification Failed for '{url}': {err_str}. Standard clearnet HTTPS requires a valid certificate from a trusted CA.",
        )

    # 3. Tor service / proxy offline or connection refused
    if (
        "connection refused" in err_lower
        or "errno 111" in err_lower
        or "connecterror" in err_lower
        or "failed to establish a new connection" in err_lower
        or "127.0.0.1:9050" in err_lower
    ):
        return (
            "proxy_offline",
            "Tor SOCKS5 proxy is offline or unreachable on 127.0.0.1:9050. Please ensure the Tor service is running (e.g., 'sudo systemctl start tor').",
        )

    # 4. SOCKS5 failure / Onion service unavailable
    if (
        "general socks server failure" in err_lower
        or "socks server failure" in err_lower
        or "host unreachable" in err_lower
        or "proxyerror" in err_lower
    ):
        if is_onion:
            return (
                "onion_service_unavailable",
                f"Tor onion service for '{url}' is unreachable, offline, or does not exist (Tor returned General SOCKS server failure).",
            )
        return (
            "proxy_error",
            f"Tor proxy error connecting to '{url}': {err_str}",
        )

    # 5. Timeout
    if "timeout" in err_lower or "timed out" in err_lower:
        return (
            "timeout",
            f"Connection timed out while fetching '{url}'. Dark web services may be experiencing high latency.",
        )

    # 6. Network / HTTP
    return (
        "network_error",
        f"Network error while requesting '{url}': {err_str}",
    )


class LinkTree(Tree):
    def __init__(
        self,
        url: str,
        depth: int,
        client: httpx.Client,
        resolve_relative: bool = False,
        crawl_external: bool = False,
        max_children_per_node: int = 25,
        max_pages: int = 100,
        result_file: str | None = None,
        uses_tor: bool = True,
    ) -> None:
        super().__init__()
        if url and not url.startswith("http://") and not url.startswith("https://"):
            if ".onion" in url.lower():
                url = f"http://{url}"
            else:
                url = f"https://{url}"
        self._url = url
        self._depth = depth
        self._client = client
        # Onion sites use relative links extensively; auto-enable relative link resolution for .onion
        self._resolve_relative = resolve_relative or (".onion" in url.lower())
        self._crawl_external = crawl_external
        self._max_children_per_node = max_children_per_node
        self._max_pages = max_pages
        self._result_file = result_file
        self._uses_tor = uses_tor
        self.crawl_failures: list[dict] = []
        self.crawl_failure_message: str | None = None
        self.crawl_failure_category: str | None = None
        self.internal_links: set[str] = set()
        self.external_links: set[str] = set()
        self.discovered_urls: set[str] = set()
        self.discovered_urls_raw: list[str] = []
        self.verified_200_urls: set[str] = set()
        self.unverified_urls: list[dict[str, Any]] = []
        self.unverified_ssl_urls: set[str] = set()
        self.status_counts: dict[int, int] = {}
        self._response_cache: dict[str, tuple[int, str]] = {}
        self._html_cache: dict[str, str] = {}
        self._visited_urls: set[str] = set()
        self._cache_lock = threading.Lock()
        self._fetch_errors: dict[str, Exception] = {}
        self._last_inc_save: float = 0.0

    def load(self) -> None:
        self.crawl_started_at = datetime.now(timezone.utc)
        self.crawl_started_monotonic = monotonic()
        clean_seed, _ = parse.urldefrag(self._url)
        if clean_seed:
            self.discovered_urls.add(clean_seed)
        self.discovered_urls_raw.append(self._url)

        # Validate onion syntax if applicable
        if ".onion" in self._url.lower():
            valid, reason = validate_onion_url(self._url)
            if not valid:
                from torbot.crawl_result import failed_page
                fail_ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                self.crawl_failure_category = "invalid_input"
                self.crawl_failure_message = reason
                self.crawl_failures.append(
                    failed_page(self._url, None, 0, reason or "invalid_input", domain_type="Internal", timestamp=fail_ts)
                )
                if self._result_file:
                    self._incremental_save(terminal_status="invalid")
                return

        try:
            self._append_node(id=self._url, parent_id=None)
        except RequestError as exc:
            from torbot.crawl_result import failed_page
            fail_ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            cat, msg = classify_crawl_error(exc, self._url)
            self.crawl_failure_category = cat
            self.crawl_failure_message = msg
            self.crawl_failures.append(
                failed_page(self._url, None, 0, cat, domain_type="Internal", timestamp=fail_ts)
            )
            term_status = "invalid" if cat == "invalid_input" else "failed"
            if self._result_file:
                self._incremental_save(terminal_status=term_status)
            return

        self._visited_urls.add(self._url)
        if self._result_file:
            self._incremental_save(terminal_status="completed")

        self._build_tree(url=self._url, depth=self._depth)

        if self._result_file:
            self._incremental_save(terminal_status="completed")

    def _append_node(self, id: str, parent_id: str or None) -> None:
        """
        Creates a node for a tree using the given ID which corresponds to a URL.
        If the parent_id is None, this will be considered a root node.
        """
        if self.contains(id):
            logging.debug(f"found a duplicate URL {id}")
            return

        if len(self.all_nodes()) >= self._max_pages:
            logging.info("Reached maximum crawl page limit (%d)", self._max_pages)
            return

        if id in self._response_cache:
            cached_item = self._response_cache[id]
            status_code = cached_item[0]
            body_text = cached_item[1]
            fetch_timestamp = (
                cached_item[2]
                if len(cached_item) > 2
                else datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            )
        elif id in self._fetch_errors and id not in self._response_cache:
            exc = self._fetch_errors[id]
            logging.warning("Skipping URL %s due to prefetch request error: %s", id, exc)
            raise RequestError(str(exc)) from exc
        else:
            try:
                fetch_timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                resp = self._client.get(id)
                status_code = getattr(resp, "status_code", 200)
                body_text = getattr(resp, "text", "") or ""
                self._response_cache[id] = (status_code, body_text, fetch_timestamp)
                self._html_cache[id] = body_text

                # Track final destination URL and intermediate redirect hops if redirected
                if hasattr(resp, "url"):
                    final_url = str(resp.url)
                    if final_url and final_url != id:
                        self._response_cache[final_url] = (status_code, body_text, fetch_timestamp)
                        self._html_cache[final_url] = body_text
                        self._visited_urls.add(final_url)
                if hasattr(resp, "history"):
                    for hop in resp.history:
                        hop_url = str(getattr(hop, "url", ""))
                        if hop_url:
                            self._visited_urls.add(hop_url)

                # Track if an HTTPS .onion endpoint was accessed with unverified/self-signed SSL
                resp_url_str = str(getattr(resp, "url", id))
                if (".onion" in id.lower() and id.lower().startswith("https://")) or (".onion" in resp_url_str.lower() and resp_url_str.lower().startswith("https://")):
                    self.unverified_ssl_urls.add(id)
                    self.unverified_ssl_urls.add(resp_url_str)
            except Exception as exc:
                logging.warning("Skipping URL %s due to request error: %s", id, exc)
                raise RequestError(str(exc)) from exc

        soup = BeautifulSoup(body_text, "html.parser") if body_text else None
        try:
            raw_title = (
                soup.title.text.strip()
                if (soup and soup.title and soup.title.text)
                else parse_hostname(id)
            )
            title = re.sub(r"\s+", " ", raw_title).strip() or parse_hostname(id)
        except Exception:
            title = id

        # Detect soft-404 responses (server returned HTTP 200, but page title/content is an error or not-found page)
        if status_code == 200 and soup:
            raw_t = (soup.title.text.strip().lower()) if (soup.title and soup.title.text) else ""
            t_norm = " ".join(re.sub(r"[^\w\s]", " ", raw_t).split())
            soft_404_titles = {
                "404 not found",
                "404 page not found",
                "page not found",
                "404 error",
                "error 404",
                "error 404 not found",
                "error 404 page not found",
                "404 file not found",
                "file not found",
            }
            if t_norm in soft_404_titles or re.match(r"^(error\s*)?404\s+(page\s+)?not\s+found\b", t_norm):
                status_code = 404
                if id in self._response_cache:
                    cached_item = self._response_cache[id]
                    self._response_cache[id] = (404, cached_item[1], cached_item[2])

        text = extract_visible_text(soup) if soup else ""

        try:
            # Pass pre-extracted text to classify to avoid redundant BeautifulSoup re-parsing
            [classification, accuracy] = classify(text if text else body_text) if (text or body_text) else ["Unknown", 0.0]
        except Exception as exc:
            logging.debug("Classification failed for %s: %s", id, exc)
            classification, accuracy = "Unknown", 0.0

        try:
            numbers = parse_phone_numbers(soup) if soup else []
        except Exception as exc:
            logging.debug("Phone parsing failed for %s: %s", id, exc)
            numbers = []

        try:
            emails = parse_emails(soup) if soup else []
        except Exception as exc:
            logging.debug("Email parsing failed for %s: %s", id, exc)
            emails = []

        is_internal = is_internal_url(self._url, id)
        domain_type = "Internal" if is_internal else "External"

        try:
            data = LinkNode(
                title,
                id,
                status_code,
                classification,
                accuracy,
                numbers,
                emails,
                text,
                domain_type=domain_type,
                timestamp=fetch_timestamp,
            )
            data.unverified_ssl = bool(
                id in self.unverified_ssl_urls
                or (id.lower().startswith("https://") and ".onion" in id.lower())
            )
            self.create_node(title, identifier=id, parent=parent_id, data=data)
            self.status_counts[status_code] = self.status_counts.get(status_code, 0) + 1
            if status_code == 200:
                self.verified_200_urls.add(id)
            else:
                self.unverified_urls.append({
                    "url": id,
                    "parentUrl": parent_id,
                    "status": status_code,
                    "domainType": domain_type,
                })
            if is_internal:
                self.internal_links.add(id)
            else:
                self.external_links.add(id)
            self._visited_urls.add(id)
        except exceptions.DuplicatedNodeIdError:
            logging.debug(f"found a duplicate URL {id}")
        except Exception as exc:
            logging.warning("Failed to create node %s: %s", id, exc)

    def _prefetch_urls(self, urls: list[str]) -> None:
        """Fetch a batch of candidate URLs concurrently to improve network throughput."""
        is_dark_web = (".onion" in self._url.lower()) or self._uses_tor
        max_workers = min(len(urls), 3 if is_dark_web else 8)
        if max_workers <= 1:
            return

        def _worker(target_url: str):
            if target_url in self._response_cache or target_url in self._fetch_errors:
                return
            try:
                fetch_ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                resp = self._client.get(target_url)
                status_code = getattr(resp, "status_code", 200)
                body_text = getattr(resp, "text", "") or ""
                with self._cache_lock:
                    self._response_cache[target_url] = (status_code, body_text, fetch_ts)
                    self._html_cache[target_url] = body_text

                    if hasattr(resp, "url"):
                        final_url = str(resp.url)
                        if final_url and final_url != target_url:
                            self._response_cache[final_url] = (status_code, body_text, fetch_ts)
                            self._html_cache[final_url] = body_text
                            self._visited_urls.add(final_url)
                    if hasattr(resp, "history"):
                        for hop in resp.history:
                            hop_u = str(getattr(hop, "url", ""))
                            if hop_u:
                                self._visited_urls.add(hop_u)

                    resp_url_str = str(getattr(resp, "url", target_url))
                    if (".onion" in target_url.lower() and target_url.lower().startswith("https://")) or (".onion" in resp_url_str.lower() and resp_url_str.lower().startswith("https://")):
                        self.unverified_ssl_urls.add(target_url)
                        self.unverified_ssl_urls.add(resp_url_str)
            except Exception as exc:
                with self._cache_lock:
                    self._fetch_errors[target_url] = exc

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                list(executor.map(_worker, urls))
        except Exception as exc:
            logging.debug("Concurrent prefetch pool exception: %s", exc)

    def _build_tree(self, url: str, depth: int) -> None:
        """
        Builds a tree from the root to the given depth using a bounded breadth-first queue.
        """
        if depth <= 0:
            return

        try:
            start_depth = self.depth(url)
        except Exception:
            start_depth = 0

        max_target_depth = start_depth + depth
        queue = deque([(url, start_depth)])

        while queue:
            curr_url, curr_depth = queue.popleft()

            if curr_depth >= max_target_depth:
                continue

            if len(self.all_nodes()) >= self._max_pages:
                logging.info("Reached maximum crawl page limit (%d)", self._max_pages)
                break

            # Retrieve cached HTML or fetch if missing
            html = self._html_cache.get(curr_url)
            if html is None:
                if curr_url in self._response_cache:
                    cached_item = self._response_cache[curr_url]
                    html = cached_item[1]
                    self._html_cache[curr_url] = html
                else:
                    try:
                        fetch_timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                        resp = self._client.get(curr_url)
                        html = getattr(resp, "text", "") or ""
                        status = getattr(resp, "status_code", 200)
                        self._response_cache[curr_url] = (status, html, fetch_timestamp)
                        self._html_cache[curr_url] = html
                        resp_url_str = str(getattr(resp, "url", curr_url))
                        if (".onion" in curr_url.lower() and curr_url.lower().startswith("https://")) or (".onion" in resp_url_str.lower() and resp_url_str.lower().startswith("https://")):
                            self.unverified_ssl_urls.add(curr_url)
                            self.unverified_ssl_urls.add(resp_url_str)
                    except Exception as exc:
                        logging.warning("Skipping subtree from %s due to request error: %s", curr_url, exc)
                        continue

            base_url = curr_url if getattr(self, "_resolve_relative", False) else None
            discovered_links = parse_links(html, base_url=base_url)
            for raw_link in discovered_links:
                self.discovered_urls_raw.append(raw_link)
                clean_link, _ = parse.urldefrag(raw_link)
                if clean_link:
                    self.discovered_urls.add(clean_link)

            # Deduplicate links while preserving order
            unique_links = []
            seen_in_page = set()
            for link in discovered_links:
                link_clean, _ = parse.urldefrag(link)
                if not link_clean:
                    continue
                if link_clean not in seen_in_page:
                    seen_in_page.add(link_clean)
                    unique_links.append(link_clean)

            effective_limit = self._max_children_per_node
            if depth >= 3 and curr_depth > 0:
                effective_limit = min(effective_limit, 8)

            # Identify candidate children within limits and prefetch uncached URLs concurrently
            candidate_children = []
            for child in unique_links:
                if len(candidate_children) >= effective_limit:
                    break
                if len(self.all_nodes()) + len(candidate_children) >= self._max_pages:
                    break
                if self.contains(child) or child in self._visited_urls:
                    continue
                candidate_children.append(child)

            uncached = [u for u in candidate_children if u not in self._response_cache and u not in self._fetch_errors]
            if len(uncached) > 1:
                self._prefetch_urls(uncached)

            processed_children = 0
            for child in unique_links:
                if processed_children >= effective_limit:
                    break

                if len(self.all_nodes()) >= self._max_pages:
                    break

                if self.contains(child) or child in self._visited_urls:
                    continue

                is_internal = is_internal_url(self._url, child)
                if is_internal:
                    self.internal_links.add(child)
                else:
                    self.external_links.add(child)

                # Attempt to append node
                try:
                    self._append_node(id=child, parent_id=curr_url)
                    processed_children += 1
                except RequestError as exc:
                    from torbot.crawl_result import failed_page
                    try:
                        p_depth = self.depth(curr_url)
                    except Exception:
                        p_depth = curr_depth
                    fail_ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                    domain_t = "Internal" if is_internal else "External"
                    self.crawl_failures.append(
                        failed_page(
                            child,
                            curr_url,
                            p_depth + 1,
                            exc,
                            domain_type=domain_t,
                            timestamp=fail_ts,
                        )
                    )
                    continue

                # Recurse/queue further ONLY if child returned HTTP 200 (verified OK) and within depth limit
                child_status = 200
                if child in self._response_cache:
                    child_status = self._response_cache[child][0]

                if (
                    child_status == 200
                    and (is_internal or self._crawl_external)
                    and (curr_depth + 1 < max_target_depth)
                ):
                    queue.append((child, curr_depth + 1))

            if self._result_file and self.root is not None:
                self._incremental_save()

    def get_verified_pages(self) -> list[Any]:
        """Return unique nodes that successfully fetched with HTTP 200 OK."""
        pages = []
        seen = set()
        for node in self.all_nodes_itr():
            if not getattr(node, "data", None):
                continue
            if getattr(node.data, "status", None) == 200:
                if node.identifier not in seen:
                    seen.add(node.identifier)
                    pages.append(node)
        return pages

    def get_url_stats(self) -> dict[str, Any]:
        """Return comprehensive discovered URL statistics for internal debugging."""
        verified = self.get_verified_pages()
        return {
            "totalPages": len(verified),
            "verifiedPages": len(verified),
            "totalDiscoveredUrls": len(self.discovered_urls_raw) or len(self.discovered_urls) or len(self.all_nodes()),
            "uniqueDiscoveredUrls": len(self.discovered_urls) or len(self.all_nodes()),
            "unverifiedUrls": len(self.unverified_urls),
            "unverifiedOrNon200Urls": len(self.unverified_urls),
            "statusCounts": dict(self.status_counts),
            "internalDiscovered": len(self.internal_links),
            "externalDiscovered": len(self.external_links),
        }

    def get_discovered_urls_details(self) -> list[dict[str, Any]]:
        """Return all discovered URLs with verification outcome for debugging."""
        details = []
        seen = set()
        for node in self.all_nodes_itr():
            if not getattr(node, "data", None):
                continue
            seen.add(node.identifier)
            status = getattr(node.data, "status", None)
            details.append({
                "url": node.identifier,
                "status": status,
                "title": getattr(node, "tag", None),
                "domainType": getattr(node.data, "domain_type", "Internal"),
                "timestamp": getattr(node.data, "timestamp", None),
                "isVerified200": status == 200,
                "unverifiedSsl": getattr(node.data, "unverified_ssl", False),
            })
        for u in self.unverified_urls:
            url_str = u.get("url")
            if url_str and url_str not in seen:
                seen.add(url_str)
                details.append({
                    "url": url_str,
                    "status": u.get("status"),
                    "title": None,
                    "domainType": u.get("domainType", "External"),
                    "timestamp": None,
                    "isVerified200": False,
                    "unverifiedSsl": False,
                })
        return details

    def _incremental_save(self, terminal_status: str | None = None) -> None:
        if not self._result_file:
            return
        now = monotonic()
        if terminal_status is None and getattr(self, "_last_inc_save", 0.0):
            if now - self._last_inc_save < 0.75:
                return
        self._last_inc_save = now
        try:
            from torbot.analyst import write_crawl_result
            if terminal_status is None:
                if self.root is None:
                    terminal_status = "invalid" if getattr(self, "crawl_failure_category", None) == "invalid_input" else "failed"
                else:
                    terminal_status = "completed"
            result = self.to_crawl_result(
                uses_tor=self._uses_tor,
                terminal_status=terminal_status,
                include_text=True,
            )
            write_crawl_result(self._result_file, result)
        except Exception as exc:
            logging.debug("Incremental save failed: %s", exc)

    def to_crawl_result(
        self,
        *,
        uses_tor: bool,
        terminal_status: str | None = None,
        include_text: bool = False,
    ) -> dict:
        """Return the shared versioned crawl-result representation.

        This is additive: ``saveJSON`` and the human-readable CLI views retain
        their existing legacy behavior.
        """
        from torbot.crawl_result import CrawlResultAdapter

        if terminal_status is None or (terminal_status == "completed" and self.root is None):
            if self.root is None:
                terminal_status = "invalid" if getattr(self, "crawl_failure_category", None) == "invalid_input" else "failed"
            else:
                terminal_status = "completed"

        diagnostics = {}
        if getattr(self, "crawl_failure_message", None):
            diagnostics["error"] = self.crawl_failure_message
        if getattr(self, "crawl_failure_category", None):
            diagnostics["errorCategory"] = self.crawl_failure_category
        if getattr(self, "unverified_ssl_urls", None):
            diagnostics["sslStatus"] = "Onion HTTPS self-signed/unverified certificate allowed (cryptographic transport security provided by Tor onion routing)"
            diagnostics["unverifiedSslCount"] = str(len(self.unverified_ssl_urls))

        return CrawlResultAdapter(self, uses_tor=uses_tor).result(
            terminal_status=terminal_status,
            include_text=include_text,
            diagnostics=diagnostics,
        )

    def _get_tree_file_name(self) -> str:
        root_id = self.root
        root_node = self.get_node(root_id)
        if root_node is None:
            raise Exception("no root node can be found.")

        # Page titles are untrusted text, never filesystem paths. Use a portable
        # filename component and bound its size before adding the export suffix.
        title = re.sub(r"[^A-Za-z0-9 _.-]", "_", str(root_node.tag))
        title = title.strip(" .")[:120].rstrip(" .") or "untitled"
        # Windows treats these names as devices even when an extension is added.
        if title.split(".", 1)[0].upper() in {
            "CON", "PRN", "AUX", "NUL",
            *(f"COM{i}" for i in range(1, 10)),
            *(f"LPT{i}" for i in range(1, 10)),
        }:
            title = f"_{title}"
        return os.path.join(
            project_root_directory, f"{title} - Depth {self._depth}"
        )

    def save(self) -> None:
        """
        Saves the tree to the current working directory under the given file name.
        """
        if self.root is None:
            logging.warning("Cannot save empty tree (no root node)")
            return
        file_name = self._get_tree_file_name()
        target_path = f"{file_name}.txt"
        if os.path.exists(target_path):
            try:
                os.remove(target_path)
            except OSError:
                pass
        self.save2file(target_path)

    def saveJSON(self) -> None:
        """
        Saves the tree to the current working directory under the given file name in JSON.
        """
        if self.root is None:
            logging.warning("Cannot save empty tree (no root node)")
            return
        json_data = self._to_json()
        file_name = self._get_tree_file_name()
        with open(f"{file_name}.json", "w+", encoding="utf-8") as f:
            f.write(json_data)

    def _to_json(self) -> str:
        if self.root is None:
            return "{}"
        try:
            json_data = self.to_json()
            return json.dumps(json.loads(json_data), indent=2)
        except Exception:
            return "{}"

    def showJSON(self) -> None:
        """
        Prints tree to console as JSON
        """
        print(self._to_json())

    def showTable(self) -> None:
        """
        Prints the status of a link based on its connection status
        """
        nodes = self.all_nodes_itr()
        table_data = []

        def insert(node, color_code):
            status = str(node.data.status)
            code = http.client.responses.get(node.data.status, "")
            status_message = f"{status} {code}".strip()
            table_data.append(
                [
                    node.tag,
                    node.identifier,
                    getattr(node.data, "domain_type", "Internal"),
                    color(status_message, color_code),
                    node.data.numbers,
                    node.data.emails,
                    node.data.classification,
                    getattr(node.data, "timestamp", "N/A") or "N/A",
                ]
            )

        for node in nodes:
            if not getattr(node, "data", None):
                continue
            status_code = getattr(node.data, "status", 0)
            if 200 <= status_code < 300:
                insert(node, "green")
            elif 300 <= status_code < 400:
                insert(node, "yellow")
            else:
                insert(node, "red")

        headers = [
            "Title",
            "URL",
            "Domain Type",
            "Status",
            "Phone Numbers",
            "Emails",
            "Category",
            "Crawl Timestamp",
        ]
        table = tabulate(table_data, headers=headers)
        print(table)


def parse_hostname(url: str) -> str:
    hostname = parse.urlsplit(url).hostname
    if hostname is not None:
        return hostname

    raise Exception("unable to parse hostname from URL")


def extract_visible_text(soup: BeautifulSoup, *, limit: int = 50_000) -> str:
    """Return bounded visible page text without scripts, styles, or markup."""
    for tag in soup(["script", "style", "noscript", "template"]):
        tag.decompose()
    text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True)).strip()
    return text[:limit]


def parse_links(html: str, base_url: str | None = None) -> list[str]:
    """
    Finds all anchor tags and parses the href attribute.

    Relative links are resolved against the page URL when a base URL is provided.
    Only absolute http(s) links are returned.
    """
    soup = BeautifulSoup(html or "", "html.parser")
    links = []
    for tag in soup.find_all("a"):
        href = tag.get("href")
        if not href or not isinstance(href, str):
            continue

        cleaned_href = href.strip()
        if not cleaned_href or cleaned_href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue

        if base_url:
            resolved = parse.urljoin(base_url, cleaned_href)
        else:
            resolved = cleaned_href

        if validators.url(resolved) and resolved.startswith(("http://", "https://")):
            links.append(resolved)
        elif base_url and validators.url(cleaned_href):
            links.append(cleaned_href)

    return links


def parse_emails(soup: BeautifulSoup) -> list[str]:
    """
    Finds all anchor tags and parses the email href attributes.
    example attribute: `mailto:example@example.com`
    """
    if not soup:
        return []
    tags = soup.find_all("a")

    emails = set()
    for tag in tags:
        if tag.has_attr("href") and tag["href"] and "mailto:" in tag["href"]:
            raw_email = tag["href"].split("mailto:", 1)[1]
            email = raw_email.split("?", 1)[0].split("&", 1)[0].strip()
            if validators.email(email):
                emails.add(email)

    return list(emails)


def parse_phone_numbers(soup: BeautifulSoup) -> list[str]:
    """
    Finds all anchor tags and parses the href attribute.
    example attribute: `tel:+45651112331` or possiby the href attribute itself.
    """
    if not soup:
        return []
    tags = soup.find_all("a")
    numbers = set()

    def validate_phone_number(phone_number: str) -> bool:
        try:
            possible_number = phonenumbers.parse(phone_number)
            return phonenumbers.is_possible_number(possible_number)
        except phonenumbers.NumberParseException:
            return False

    for tag in tags:
        if tag.has_attr("href") and tag["href"] and "tel:" in tag["href"]:
            number = tag["href"].split("tel:", 1)[1].split("?", 1)[0].strip()
            if validate_phone_number(number):
                numbers.add(number)

    return list(numbers)
