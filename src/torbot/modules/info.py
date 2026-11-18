"""
Module that contains methods for collecting all relevant data from links,
and saving data to file.
"""

import re
import httpx
import logging

from urllib.parse import urlsplit
from bs4 import BeautifulSoup
from termcolor import cprint

from torbot.modules.linktree import LinkTree

keys = set()  # high entropy strings, prolly secret keys
files = set()  # pdf, css, png etc.
intel = set()  # emails, website accounts, aws buckets etc.
robots = set()  # entries of robots.txt
custom = set()  # string extracted by custom regex pattern
failed = set()  # urls that photon failed to crawl
scripts = set()  # javascript files
external = set()  # urls that don't belong to the target i.e. out-of-scope
fuzzable = set()  # urls that have get params in them e.g. example.com/page.php?id=2
endpoints = set()  # urls found from javascript files
processed = set()  # urls that have been crawled

everything = []
bad_intel = set()  # unclean intel urls
bad_scripts = set()  # unclean javascript file urls
datasets = [
    files,
    intel,
    robots,
    custom,
    failed,
    scripts,
    external,
    fuzzable,
    endpoints,
    keys,
]
dataset_names = [
    "files",
    "intel",
    "robots",
    "custom",
    "failed",
    "scripts",
    "external",
    "fuzzable",
    "endpoints",
    "keys",
]


def execute_all(
    client: httpx.Client, link: str, *, display_status: bool = False
) -> None:
    """Initialise datasets and functions to retrieve data, and execute
    each for a given link.

    Args:
        link (str): Link to be interrogated.
        display_status (bool, optional): Whether to print connection
            attempts to terminal.
    """
    for dataset in datasets:
        dataset.clear()

    try:
        resp = client.get(url=link)
    except Exception as exc:
        cprint(f"Error connecting to target {link}: {exc}", "red")
        return

    soup = BeautifulSoup(resp.text, "html.parser")
    validation_functions = [
        get_robots_txt,
        get_dot_git,
        get_dot_svn,
        get_intel,
        get_dot_htaccess,
        get_bitcoin_address,
    ]
    for validate_func in validation_functions:
        try:
            validate_func(client, link, resp)
        except Exception as e:
            logging.debug("Error in %s: %s", validate_func.__name__, e)
            cprint(f"Error checking {validate_func.__name__}", "red")

    display_webpage_description(soup)


def fetch_html(
    client: httpx.Client, link: str, tree: LinkTree, save_html: bool = False
) -> None:
    try:
        resp = client.get(url=link)
    except Exception as exc:
        cprint(f"Error fetching HTML for {link}: {exc}", "red")
        return

    soup = BeautifulSoup(resp.text, "html.parser")

    if save_html is False:
        print(f"""
            HTML file
              {soup}
        """)
    else:  # save_html is True
        file_name = tree._get_tree_file_name()
        print(f"SAVED to {file_name}.html\n\n")
        with open(f"{file_name}.html", "w+", encoding="utf-8") as f:
            f.write(str(soup))


def display_headers(response):
    """Print all headers in response object.

    Args:
        response (object): Response object.
    """
    print(
        """
          RESPONSE HEADERS
          __________________
          """
    )
    for key, val in response.headers.items():
        print("*", key, ":", val)


def get_robots_txt(client: httpx.Client, target: str, response: object) -> None:
    """Check link for robots.txt, and if found, add rules to robots dataset.

    Args:
        target (str): URL to be checked.
        response (object): Response object of main page.
    """
    cprint("[*]Checking for Robots.txt", "yellow")
    parsed = urlsplit(target)
    base_target = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    robots_url = f"{base_target}/robots.txt"
    print(robots_url)
    try:
        robots_resp = client.get(robots_url)
        if robots_resp.status_code == 200 and robots_resp.text:
            cprint("Robots.txt found", "blue")
            matches = re.findall(r"(?:Allow|Disallow):\s*([^\s#]+)", robots_resp.text, re.IGNORECASE)
            for match in matches:
                match = match.strip()
                if match and "*" not in match:
                    entry = f"{base_target}/{match.lstrip('/')}"
                    robots.add(entry)
            if robots:
                print(f"Found {len(robots)} robots.txt paths")
                for r_path in sorted(robots):
                    print("Robots path:", r_path)
        else:
            cprint(f"NO robots.txt found (status: {robots_resp.status_code})", "blue")
    except Exception as exc:
        logging.debug("Error checking robots.txt: %s", exc)
        cprint("Robots.txt check skipped (unreachable)", "blue")


def get_intel(client: httpx.Client, url: str, response: object) -> None:
    """Check link for intel (emails, S3 buckets, etc.).

    Args:
        url (str): URL to be checked.
        response (object): Response object containing data to check.
    """
    cprint("[*]Checking for intel", "yellow")
    resp_text = response.text if hasattr(response, "text") else str(response)
    intel_found = set()
    regex = r"""([\w\.-]+s[\w\.-]*\.amazonaws\.com)|([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)"""
    matches = re.findall(regex, resp_text)
    for match in matches:
        for item in match:
            if item:
                intel_found.add(item)
                intel.add(item)

    print("Intel\n--------\n")
    if intel_found:
        for item in sorted(intel_found):
            print("Found intel:", item)
    else:
        print("No external intel endpoints found")


def get_dot_git(client: httpx.Client, target: str, response: object) -> None:
    """Check link for .git folders exposed on public domain.

    Args:
        target (str): URL to be checked.
        response (object): Response object containing data to check.
    """
    cprint("[*]Checking for .git folder", "yellow")
    parsed = urlsplit(target)
    base_target = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    git_url = f"{base_target}/.git/config"
    try:
        resp = client.get(git_url)
        if resp.status_code == 200 and ("core" in resp.text or "repositoryformatversion" in resp.text):
            cprint("Alert!", "red")
            cprint(".git folder exposed publicly", "red")
        else:
            cprint("NO .git folder found", "blue")
    except Exception as exc:
        logging.debug("Error checking .git: %s", exc)
        cprint("NO .git folder found", "blue")


def get_bitcoin_address(client: httpx.Client, target: str, response: object) -> None:
    """Check link for Bitcoin addresses, and if found, print.

    Args:
        target (str): URL to be checked.
        response (object): Response object containing data to check.
    """
    cprint("[*]Checking for Bitcoin addresses", "yellow")
    resp_text = response.text if hasattr(response, "text") else str(response)
    btc_pattern = r"\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,59})\b"
    bitcoins = set(re.findall(btc_pattern, resp_text))
    print("BTC FOUND: ", len(bitcoins))
    for bitcoin in sorted(bitcoins):
        print("BTC: ", bitcoin)


def get_dot_svn(client: httpx.Client, target: str, response: object) -> None:
    """Check link for .svn folders exposed on public domain.

    Args:
        target (str): URL to be checked.
        response (object): Response object containing data to check.
    """
    cprint("[*]Checking for .svn folder", "yellow")
    parsed = urlsplit(target)
    base_target = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    svn_url = f"{base_target}/.svn/entries"
    try:
        resp = client.get(svn_url)
        if resp.status_code == 200 and ("svn" in resp.text.lower() or "dir" in resp.text):
            cprint("Alert!", "red")
            cprint(".SVN folder exposed publicly", "red")
        else:
            cprint("NO .SVN folder found", "blue")
    except Exception as exc:
        logging.debug("Error checking .svn: %s", exc)
        cprint("NO .SVN folder found", "blue")


def get_dot_htaccess(client: httpx.Client, target: str, response: object) -> None:
    """Check link for .htaccess files on public domain.

    Args:
        target (str): URL to be checked.
        response (object): Response object containing data to check.
    """
    cprint("[*]Checking for .htaccess", "yellow")
    parsed = urlsplit(target)
    base_target = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    htaccess_url = f"{base_target}/.htaccess"
    try:
        resp = client.get(htaccess_url)
        if resp.status_code == 403:
            cprint(".htaccess protected (403 Forbidden)", "blue")
        elif resp.status_code == 200 and any(keyword in resp.text.lower() for keyword in ("rewriteengine", "authuserfile", "order deny,allow", "deny from")):
            cprint("Alert!! .htaccess file found!", "red")
        else:
            cprint("NO .htaccess file found", "blue")
    except Exception as exc:
        logging.debug("Error checking .htaccess: %s", exc)
        cprint("NO .htaccess file found", "blue")


def display_webpage_description(soup: BeautifulSoup) -> None:
    """Print all meta tags found in page.

    Args:
        soup (object): Processed HTML object.
    """
    cprint("[*]Checking for meta tag", "yellow")
    metatags = soup.find_all("meta")
    for meta in metatags:
        print("Meta : ", meta)


def writer(datasets, dataset_names, output_dir):
    """Write content of all datasets to file.

    Args:
        datasets (list): List of datasets containing relevant content.
        dataset_names (list): Identifiers for each dataset.
        output_dir (str): Path where data file should be saved.
    """
    import os
    os.makedirs(output_dir, exist_ok=True)
    for dataset, dataset_name in zip(datasets, dataset_names):
        if dataset:
            filepath = os.path.join(output_dir, f"{dataset_name}.txt")
            with open(filepath, "w+", encoding="utf-8") as f:
                f.write("\n".join(str(item) for item in sorted(dataset)))
                f.write("\n")
            # else:
            #     with open(filepath, 'w+') as f:
            #         joined = '\n'.join(dataset)
            #         f.write(str(joined.encode('utf-8')))
            #         f.write('\n')
