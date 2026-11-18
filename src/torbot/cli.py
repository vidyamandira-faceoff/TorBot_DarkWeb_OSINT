import argparse
import logging
import sys
from importlib import metadata
from pathlib import Path

import httpx
import toml

import socket
from torbot.analyst import AnalysisError, analyze_file, write_crawl_result
from torbot.modules.api import get_ip
from torbot.modules.app_launcher import launch_torbot_app
from torbot.modules.color import color
from torbot.modules.info import execute_all, fetch_html
from torbot.modules.linktree import LinkTree, validate_onion_url
from torbot.modules.updater import check_version


def get_version() -> str:
    """Return the installed TorBot version with a source checkout fallback."""
    try:
        return metadata.version("torbot")
    except metadata.PackageNotFoundError:
        repo_root = Path(__file__).resolve().parents[2]
        config_file_path = repo_root / "pyproject.toml"
        try:
            with config_file_path.open("r", encoding="utf-8") as handle:
                data = toml.load(handle)
                return data["project"]["version"]
        except Exception as exc:
            raise RuntimeError("unable to find version from pyproject.toml.") from exc


def print_tor_ip_address(client: httpx.Client) -> None:
    """
    https://check.torproject.org/ tells you if you are using tor and it
    displays your IP address which we scrape and display
    """
    try:
        resp = get_ip(client)
        print(resp["header"])
        print(color(resp["body"], "yellow"))
    except Exception as exc:
        logging.debug("Unable to verify Tor IP status: %s", exc)
        print(color("[*] Warning: Could not verify Tor IP from check.torproject.org", "yellow"))
        print(color("[*] If Tor proxy is not running, start it or use --disable-socks5", "yellow"))


def print_header(version: str) -> None:
    """
    Prints the TorBot banner including version and license.
    """
    license_msg = color("LICENSE: GNU Public License v3", "red")
    banner = r"""
                            __  ____  ____  __        ______
                            / /_/ __ \/ __ \/ /_  ____/_  __/
                        / __/ / / / /_/ / __ \/ __ \/ /
                        / /_/ /_/ / _, _/ /_/ / /_/ / /
                        \__/\____/_/ |_/_____/\____/_/  v{VERSION}
            """.format(VERSION=version)
    banner = color(banner, "red")

    title = r"""
                                    {banner}
                    #######################################################
                    #  TorBot - Dark Web OSINT Tool                       #
                    #  GitHub : https://github.com/DedsecInside/TorBot    #
                    #  Help : use -h for help text                        #
                    #######################################################
                                {license_msg}
            """

    title = title.format(license_msg=license_msg, banner=banner)
    print(title)


def normalize_url(url: str, disable_socks: bool = False) -> str:
    """Normalize input URL or search query into a valid absolute HTTP/HTTPS URL."""
    url = url.strip()
    if not url:
        return url
    if url.startswith("http://") or url.startswith("https://"):
        return url
    if ".onion" in url.lower():
        return f"http://{url}"
    if "." in url and " " not in url:
        return f"https://{url}"
    # Search query: route to dark web search engine
    import urllib.parse
    q = urllib.parse.quote_plus(url)
    if disable_socks:
        return f"https://html.duckduckgo.com/html/?q={q}"
    return f"https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/html/?q={q}"


def run(arg_parser: argparse.ArgumentParser, version: str) -> None:
    args = arg_parser.parse_args()

    # setup logging
    date_fmt = "%d-%b-%y %H:%M:%S"
    logging_fmt = "%(asctime)s - %(levelname)s - %(message)s"
    logging_lvl = logging.DEBUG if args.v else logging.INFO
    logging.basicConfig(level=logging_lvl, format=logging_fmt, datefmt=date_fmt)

    # Print verison then exit
    if args.version:
        print(f"TorBot Version: {version}")
        sys.exit()

    # check version and update if necessary
    if args.update:
        check_version()
        sys.exit()

    if args.command == "app" or args.app:
        repo_root = Path(__file__).resolve().parents[2]
        sys.exit(launch_torbot_app(repo_root, args.app_dir))

    if args.command == "analyze":
        if not args.input:
            arg_parser.error("analyze requires a crawl-result JSON file")
        try:
            report = analyze_file(
                args.input,
                args.output,
                provider=args.provider,
                model=args.model,
                base_url=args.base_url,
                allow_remote=args.allow_remote,
                keyword=args.keyword,
                redact_pattern=args.redact_pattern,
            )
        except (AnalysisError, OSError) as exc:
            arg_parser.error(str(exc))
        print(f"Investigation report written to {Path(args.output).resolve()}")
        if report["warnings"]:
            print("Completed with warnings: " + "; ".join(report["warnings"]))
        return

    # URL is required for crawl-related actions
    if not args.url:
        arg_parser.print_help()
        sys.exit()

    args.url = normalize_url(args.url, disable_socks=args.disable_socks5)

    is_onion = ".onion" in args.url.lower()

    # Reject invalid onion URLs immediately
    if is_onion:
        valid_onion, onion_err = validate_onion_url(args.url)
        if not valid_onion:
            print(color(f"[-] Error: Invalid .onion URL: {onion_err}", "red"))
            if args.save == "result":
                from torbot.crawl_result import invalid_result
                inv_res = invalid_result(args.url)
                inv_res["diagnostics"] = {"error": onion_err or "Invalid .onion URL"}
                write_crawl_result(args.result_file, inv_res)
            sys.exit(1)

        if args.disable_socks5:
            print(color("[*] Warning: .onion addresses require Tor proxy. Ignoring --disable-socks5.", "yellow"))
            args.disable_socks5 = False

    socks5_host = args.host
    socks5_port = str(args.port)
    socks5_proxy = f"socks5://{socks5_host}:{socks5_port}"

    # Pre-check Tor SOCKS5 proxy availability when targeting dark web (.onion)
    if is_onion:
        try:
            with socket.create_connection((socks5_host, int(socks5_port)), timeout=3.0):
                pass
        except OSError:
            print(color(f"[-] Error: Tor SOCKS5 proxy is offline or unreachable on {socks5_host}:{socks5_port}.", "red"))
            print(color("[*] Cannot crawl .onion dark web addresses without a running Tor service.", "yellow"))
            print(color("[*] Hint: Start Tor service (e.g. 'sudo systemctl start tor') or check proxy host/port.", "yellow"))
            if args.save == "result":
                from datetime import datetime, timezone
                from uuid import uuid4
                from torbot.crawl_result import SCHEMA_VERSION, ENGINE, failed_page
                now_str = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                fail_res = {
                    "schemaVersion": SCHEMA_VERSION,
                    "runId": str(uuid4()),
                    "engine": ENGINE,
                    "engineVersion": version,
                    "target": args.url,
                    "settings": {"maxDepth": args.depth, "usesTor": True},
                    "terminalStatus": "failed",
                    "cancelled": False,
                    "startedAt": now_str,
                    "endedAt": now_str,
                    "durationMs": 0,
                    "pages": [failed_page(args.url, None, 0, "proxy offline", domain_type="Internal", timestamp=now_str)],
                    "diagnostics": {"error": f"Tor proxy unreachable on {socks5_host}:{socks5_port}"},
                }
                write_crawl_result(args.result_file, fail_res)
            sys.exit(1)

    req_timeout = httpx.Timeout(35.0, connect=20.0) if is_onion else httpx.Timeout(20.0, connect=10.0)

    # Scoped transport configuration:
    # 1. Tor onion routing provides end-to-end cryptographic authentication and transport encryption.
    # 2. Public CAs do not issue TLS certificates for .onion domains; onion services using TLS almost universally use self-signed certificates.
    # 3. Handle self-signed certificates safely and ONLY within the scoped .onion transport (verify=False for all://*.onion).
    # 4. Standard clearnet HTTPS requests strictly preserve normal CA certificate verification (verify=True).
    # 5. All .onion requests are always routed through the Tor SOCKS5 proxy (socks5://host:port).
    onion_transport = httpx.HTTPTransport(
        proxy=socks5_proxy,
        verify=False,
    )
    default_proxy = socks5_proxy if not args.disable_socks5 else None
    default_transport = httpx.HTTPTransport(
        proxy=default_proxy,
        verify=True,  # Normal HTTPS certificate verification preserved for all regular websites
    )
    mounts = {
        "all://*.onion": onion_transport,
        "all://": default_transport,
    }

    if is_onion and not args.quiet:
        print(color("[*] Scoped .onion transport active: routed via Tor SOCKS5 proxy with self-signed TLS support.", "cyan"))
        print(color("[*] Note: .onion TLS certificate verification is bypassed (cryptographic security is provided by Tor onion routing).", "yellow"))

    with httpx.Client(
        timeout=req_timeout,
        mounts=mounts,
        follow_redirects=True,
    ) as client:
        # print header and IP address if not set to quiet
        if not args.quiet:
            print_header(version)
            print_tor_ip_address(client)

        if args.info:
            execute_all(client, args.url)

        tree = LinkTree(
            url=args.url,
            depth=args.depth,
            client=client,
            resolve_relative=getattr(args, "resolve_relative", False),
            crawl_external=getattr(args, "crawl_external", False),
            max_pages=getattr(args, "max_pages", 100),
            result_file=args.result_file if args.save == "result" else None,
            uses_tor=not args.disable_socks5,
        )
        try:
            tree.load()
        finally:
            if args.save == "result" and (tree.root is not None or tree.crawl_failures):
                try:
                    result = tree.to_crawl_result(
                        uses_tor=not args.disable_socks5,
                        include_text=True,
                    )
                    write_crawl_result(args.result_file, result)
                    print(f"Crawl result written to {Path(args.result_file).resolve()}")
                except Exception as exc:
                    logging.warning("Failed to save crawl result: %s", exc)

        if tree.root is None:
            fail_msg = getattr(tree, "crawl_failure_message", None) or "Unable to fetch seed URL"
            print(color(f"[-] Crawl failed: {fail_msg}", "red"))
            sys.exit(1)

        # save data if desired
        if args.save == "tree":
            tree.save()
        elif args.save == "json":
            tree.saveJSON()

        if args.html == "display":
            fetch_html(client, args.url, tree)
        elif args.html == "save":
            fetch_html(client, args.url, tree, save_html=True)

        # always print something, table is the default
        if args.visualize == "table" or not args.visualize:
            tree.showTable()
        elif args.visualize == "tree":
            print(tree)
        elif args.visualize == "json":
            tree.showJSON()

    print("\n\n")


def set_arguments() -> argparse.ArgumentParser:
    """
    Parses user flags passed to TorBot
    """
    parser = argparse.ArgumentParser(
        prog="TorBot", usage="Gather and analayze data from Tor sites."
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=["app", "analyze"],
        help="Run the desktop app or analyze a crawl-result file",
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="Versioned crawl-result JSON file used by the analyze command",
    )
    parser.add_argument(
        "-u",
        "--url",
        type=str,
        default=None,
        help="Specifiy a website link to crawl",
    )
    parser.add_argument(
        "--depth", type=int, help="Specifiy max depth of crawler (default 1)", default=1
    )
    parser.add_argument(
        "--host", type=str, help="IP address for SOCKS5 proxy", default="127.0.0.1"
    )
    parser.add_argument("--port", type=int, help="Port for SOCKS5 proxy", default=9050)
    parser.add_argument(
        "--save",
        type=str,
        choices=["tree", "json", "result"],
        help="Save legacy tree data or a versioned crawl result",
    )
    parser.add_argument(
        "--result-file",
        default="crawl-result.json",
        help="Path used by --save result (default: crawl-result.json)",
    )
    parser.add_argument(
        "--visualize",
        type=str,
        choices=["table", "tree", "json"],
        help="Visualizes data collection.",
    )
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument(
        "--version", action="store_true", help="Show current version of TorBot."
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="Update TorBot to the latest stable version",
    )
    parser.add_argument(
        "--app",
        action="store_true",
        help="Run optional TorBot desktop app",
    )
    parser.add_argument(
        "--app-dir",
        type=str,
        help="Path to a TorBotApp checkout",
    )
    parser.add_argument(
        "--info",
        action="store_true",
        help="Info displays basic info of the scanned site. Only supports a single URL at a time.",
    )
    parser.add_argument("-v", action="store_true", help="verbose logging")
    parser.add_argument(
        "--disable-socks5",
        action="store_true",
        help="Executes HTTP requests without using SOCKS5 proxy",
    )
    parser.add_argument(
        "--resolve-relative",
        action="store_true",
        default=False,
        help="Resolve relative links against the current page URL during crawl",
    )
    parser.add_argument(
        "--crawl-external",
        action="store_true",
        default=False,
        help="Allow crawling external domains recursively (default: False)",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=100,
        help="Maximum number of pages to crawl (default: 100)",
    )
    parser.add_argument(
        "--html",
        choices=["save", "display"],
        help="Saves / Displays the html of the onion link",
    )
    parser.add_argument(
        "--provider",
        choices=["none", "ollama", "openai-compatible"],
        default="ollama",
        help="AI provider for analyze (default: ollama on localhost)",
    )
    parser.add_argument(
        "--model",
        default="qwen3",
        help="Model name passed to the selected provider",
    )
    parser.add_argument(
        "--base-url",
        help="OpenAI-compatible provider base URL",
    )
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="Explicitly allow evidence excerpts to be sent to a remote provider",
    )
    parser.add_argument(
        "--output",
        default="investigation",
        help="Directory for Analyst outputs (default: investigation)",
    )
    parser.add_argument(
        "--keyword",
        action="append",
        default=[],
        help="Record deterministic keyword matches; repeat for multiple keywords",
    )
    parser.add_argument(
        "--redact-pattern",
        action="append",
        default=[],
        help="Additional regex redacted before remote transmission; repeat as needed",
    )

    return parser


def main() -> None:
    """Run the TorBot CLI from an installed entry point."""
    run(set_arguments(), get_version())


if __name__ == "__main__":
    main()
