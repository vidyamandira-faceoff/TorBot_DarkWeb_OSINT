"""
API Module

Provides access to external services using API wrappers
"""
import httpx
import logging

from bs4 import BeautifulSoup, Tag


logging.getLogger("httpx").setLevel(logging.WARNING)


def get_ip(client: httpx.Client) -> dict:
    """
    Returns the IP address of the current Tor client the service is using.
    """
    try:
        resp = client.get("https://check.torproject.org/")
        soup = BeautifulSoup(resp.text, "html.parser")

        content = soup.find("div", {"class": "content"})
        if content:
            header_tag = content.find("h1")
            body_tag = content.find("p")
            if (
                header_tag
                and body_tag
                and isinstance(header_tag, Tag)
                and isinstance(body_tag, Tag)
            ):
                return {
                    "header": header_tag.get_text().strip(),
                    "body": body_tag.get_text().strip(),
                }
    except Exception as exc:
        logging.debug("HTML scraping of check.torproject.org failed: %s", exc)

    # Fallback to official JSON API
    try:
        api_resp = client.get("https://check.torproject.org/api/ip")
        if api_resp.status_code == 200:
            data = api_resp.json()
            is_tor = data.get("IsTor", False)
            ip = data.get("IP", "Unknown")
            header = (
                "Congratulations. This browser is configured to use Tor."
                if is_tor
                else "Sorry. You are not using Tor."
            )
            body = f"Your IP address appears to be:  {ip}"
            return {"header": header, "body": body}
    except Exception as exc:
        logging.debug("JSON API check also failed: %s", exc)

    raise Exception("unable to find content to parse IP.")
