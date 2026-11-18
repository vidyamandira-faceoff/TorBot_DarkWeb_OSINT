#!/usr/bin/env python3
"""
TorBot Web UI
A comprehensive, local web dashboard for running and viewing TorBot OSINT scans
via any modern web browser.
"""

import json
import logging
import os
import re
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

import httpx
from flask import Flask, jsonify, render_template_string, request, send_file

app = Flask(__name__)

REPO_DIR = Path(__file__).parent.resolve()
OUTPUT_DIR = REPO_DIR / "web_results"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
RESULT_FILE = OUTPUT_DIR / "latest-crawl-result.json"
INVESTIGATION_DIR = OUTPUT_DIR / "investigation"


def strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from terminal output."""
    ansi_regex = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
    return ansi_regex.sub("", text)


def check_tor_service(host: str = "127.0.0.1", port: int = 9050) -> bool:
    """Check if the local Tor SOCKS5 proxy is listening."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.0)
            return sock.connect_ex((host, port)) == 0
    except Exception:
        return False


def get_tor_network_ip(host: str = "127.0.0.1", port: int = 9050) -> Dict[str, Any]:
    """Query check.torproject.org via SOCKS5 proxy to verify exit IP and Tor status."""
    if check_tor_service(host, port):
        proxy_url = f"socks5://{host}:{port}"
        try:
            with httpx.Client(proxy=proxy_url, timeout=8.0) as client:
                resp = client.get("https://check.torproject.org/api/ip")
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "reachable": True,
                        "ip": data.get("IP", "Unknown"),
                        "is_tor": data.get("IsTor", False),
                    }
        except Exception as exc:
            logging.debug("Error querying Tor network IP via proxy: %s", exc)

    # Fallback: check clearnet IP
    try:
        with httpx.Client(timeout=4.0) as client:
            resp = client.get("https://check.torproject.org/api/ip")
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "reachable": False,
                    "ip": data.get("IP", "Unknown"),
                    "is_tor": False,
                }
    except Exception:
        pass

    return {"reachable": False, "ip": "Unreachable", "is_tor": False}


def parse_info_recon_from_stdout(text: str) -> Dict[str, Any]:
    """Extract security and recon data found by TorBot info module."""
    info_data: Dict[str, Any] = {
        "robots_status": "Not Checked",
        "robots_paths": [],
        "git_status": "Not Checked",
        "svn_status": "Not Checked",
        "htaccess_status": "Not Checked",
        "bitcoins": [],
        "intel": [],
        "meta_tags": [],
    }

    clean = strip_ansi(text)

    # Robots.txt
    if "Robots.txt check skipped" in clean or "robots.txt check skipped" in clean.lower():
        info_data["robots_status"] = "Unreachable / Skipped"
    elif "NO robots.txt found" in clean or "no robots.txt found" in clean.lower():
        info_data["robots_status"] = "Not Found (Safe)"
    elif "Robots.txt found" in clean:
        info_data["robots_status"] = "Exposed / Found"

    robots_matches = re.findall(r"(?:https?://[^\s]+/robots\.txt)", clean)
    if robots_matches:
        info_data["robots_url"] = robots_matches[0]

    path_matches = re.findall(r"Robots path:\s*([^\s\n\r]+)", clean)
    if path_matches:
        info_data["robots_paths"] = sorted(set(path_matches))

    # .git
    if "NO .git folder found" in clean or "no .git folder found" in clean.lower():
        info_data["git_status"] = "Safe (Not Found)"
    elif ".git folder exposed publicly" in clean or "Alert! .git" in clean:
        info_data["git_status"] = "ALERT: Publicly Exposed!"
    elif "Error checking get_dot_git" in clean:
        info_data["git_status"] = "Unreachable / Error"

    # .svn
    if "NO .SVN folder found" in clean or "no .svn folder found" in clean.lower():
        info_data["svn_status"] = "Safe (Not Found)"
    elif ".SVN folder exposed publicly" in clean or "Alert! .SVN" in clean:
        info_data["svn_status"] = "ALERT: Publicly Exposed!"
    elif "Error checking get_dot_svn" in clean:
        info_data["svn_status"] = "Unreachable / Error"

    # .htaccess
    if ".htaccess protected (403 Forbidden)" in clean or "403 Forbidden" in clean:
        info_data["htaccess_status"] = "Protected (403 Forbidden)"
    elif "NO .htaccess file found" in clean or "no .htaccess file found" in clean.lower():
        info_data["htaccess_status"] = "Safe (Not Found)"
    elif ".htaccess file found" in clean or "Alert!! .htaccess" in clean:
        info_data["htaccess_status"] = "ALERT: Publicly Exposed!"
    elif "Error checking get_dot_htaccess" in clean:
        info_data["htaccess_status"] = "Unreachable / Error"

    # Crypto (Bitcoin, Ethereum, Monero)
    crypto_set = set()
    for btc in re.findall(r"\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,59})\b", clean):
        crypto_set.add(f"BTC: {btc}")
    for eth in re.findall(r"\b(0x[a-fA-F0-9]{40})\b", clean):
        crypto_set.add(f"ETH: {eth}")
    for xmr in re.findall(r"\b(4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b", clean):
        crypto_set.add(f"XMR: {xmr}")
    info_data["bitcoins"] = sorted(crypto_set)

    # Intel
    intel_matches = re.findall(r"(?:Found intel:\s*|Intel found:\s*)([^\s\n\r]+)", clean)
    if intel_matches:
        info_data["intel"] = sorted(set(intel_matches))

    # Meta tags
    meta_lines = re.findall(r"Meta\s*(?:\([^)]+\))?\s*:\s*(.+)", clean)
    for ml in meta_lines:
        line_clean = ml.strip()
        if line_clean and line_clean not in info_data["meta_tags"]:
            info_data["meta_tags"].append(line_clean)

    return info_data


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


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TorBot OSINT Web Dashboard</title>
    <style>
        :root {
            --bg-base: #070d19;
            --bg-card: #0f172a;
            --bg-card-hover: #16223b;
            --bg-input: #0b1222;
            --border-color: #1e293b;
            --border-subtle: #243552;
            --border-focus: #38bdf8;
            --accent: #38bdf8;
            --accent-glow: rgba(56, 189, 248, 0.25);
            --accent-dim: #0284c7;
            --accent-cyan: #06b6d4;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --danger: #f87171;
            --warning: #fbbf24;
            --info: #38bdf8;
            --success: #34d399;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        html, body {
            margin: 0;
            padding: 0;
            width: 100vw;
            height: 100vh;
            overflow: hidden;
            box-sizing: border-box;
            background-color: var(--bg-base);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Inter", "Helvetica Neue", sans-serif;
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
        }

        *, *:before, *:after {
            box-sizing: inherit;
            margin: 0;
            padding: 0;
        }

        /* Structured App Shell Layout (OASIS Architecture Alignment) */
        .app-shell {
            display: flex;
            flex-direction: column;
            height: 100vh;
            width: 100%;
            overflow: hidden;
        }

        /* Fixed Top Header Bar */
        .header {
            flex-shrink: 0;
            width: 100%;
            background: rgba(15, 23, 42, 0.96);
            backdrop-filter: blur(14px);
            -webkit-backdrop-filter: blur(14px);
            border-bottom: 1px solid var(--border-color);
            padding: 20px 32px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
            z-index: 100;
        }

        .header-inner {
            width: 100%;
            max-width: 1400px;
            margin: 0 auto;
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 16px;
        }

        .header-title h1 {
            color: var(--accent);
            font-size: 1.85rem;
            letter-spacing: 0.3px;
            display: flex;
            align-items: center;
            gap: 10px;
            background: linear-gradient(135deg, #38bdf8 0%, #06b6d4 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin: 0;
        }

        .header-title p {
            color: var(--text-muted);
            font-size: 0.9rem;
            margin-top: 4px;
        }

        .header-status {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background-color: var(--accent);
            box-shadow: 0 0 8px var(--accent);
            display: inline-block;
        }

        .status-dot-offline {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background-color: var(--danger);
            box-shadow: 0 0 8px var(--danger);
            display: inline-block;
        }

        .badge {
            font-size: 0.82rem;
            padding: 6px 14px;
            border-radius: 20px;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        .badge-online {
            background: rgba(56, 189, 248, 0.12);
            color: var(--accent);
            border: 1px solid rgba(56, 189, 248, 0.4);
        }

        .badge-offline {
            background: rgba(248, 113, 113, 0.12);
            color: var(--danger);
            border: 1px solid rgba(248, 113, 113, 0.4);
        }

        /* Constant Main Content Workspace Area */
        .main-workspace, .main-content {
            flex: 1;
            width: 100%;
            max-width: 1400px;
            margin: 0 auto;
            padding: 24px 32px;
            overflow-y: auto;
            overflow-x: hidden;
            box-sizing: border-box;
        }

        .container {
            width: 100%;
            max-width: 1400px;
            margin: 0 auto;
            padding-bottom: 40px;
            box-sizing: border-box;
        }

        /* Full-Width Cards */
        .card {
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 26px;
            margin-bottom: 24px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4), 0 0 1px rgba(56, 189, 248, 0.15);
            transition: border-color 0.25s ease;
            width: 100%;
            box-sizing: border-box;
        }

        .card:hover {
            border-color: var(--border-subtle);
        }

        .card-title {
            font-size: 1.18rem;
            font-weight: 600;
            color: var(--text-main);
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            flex-wrap: wrap;
        }

        /* Form */
        .form-group {
            margin-bottom: 18px;
            width: 100%;
        }

        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            font-size: 0.95rem;
            color: var(--text-main);
            letter-spacing: 0.2px;
        }

        .label-hint {
            color: var(--text-muted);
            font-size: 0.85rem;
            font-weight: normal;
            margin-left: 6px;
        }

        input[type="text"], input[type="number"] {
            width: 100%;
            height: 48px;
            min-height: 48px;
            padding: 10px 14px;
            background: var(--bg-input);
            border: 1.5px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-main);
            font-size: 15px;
            outline: none;
            transition: all 0.2s ease;
            box-sizing: border-box;
        }

        input[type="text"]:focus, input[type="number"]:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-glow);
        }

        /* Explicit, highly legible Dropdown Selectors and Options */
        select {
            width: 100%;
            height: 48px;
            min-height: 48px;
            padding: 10px 40px 10px 14px;
            background-color: #0f172a;
            border: 1.5px solid var(--border-subtle);
            border-radius: 8px;
            color: #f8fafc;
            font-size: 15px !important;
            font-weight: 500;
            line-height: 1.6;
            outline: none;
            cursor: pointer;
            appearance: none;
            -webkit-appearance: none;
            -moz-appearance: none;
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%2338bdf8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='6 9 12 15 18 9'%3E%3C/polyline%3E%3C/svg%3E");
            background-repeat: no-repeat;
            background-position: right 14px center;
            background-size: 16px 16px;
            transition: all 0.2s ease;
            box-sizing: border-box;
        }

        select:hover {
            border-color: rgba(56, 189, 248, 0.7);
            background-color: #162035;
        }

        select:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-glow);
            background-color: #162035;
        }

        select option {
            background-color: #0f172a !important;
            color: #f8fafc !important;
            font-size: 15px !important;
            font-family: inherit;
            padding: 10px 14px !important;
            line-height: 1.6;
            margin: 2px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }

        select option:checked, select option:hover {
            background-color: #1e3a5f !important;
            color: #38bdf8 !important;
            font-weight: 600;
        }

        /* Specific enhanced styling for Crawl Depth and Action / Output Mode */
        #depth, #action {
            height: 48px;
            min-height: 48px;
            font-size: 15px !important;
            font-weight: 500;
            padding: 10px 40px 10px 14px;
            line-height: 1.6;
            color: #f8fafc;
            background-color: #0f172a;
        }

        #depth option, #action option {
            font-size: 15px !important;
            padding: 10px 14px !important;
            line-height: 1.6;
            background-color: #0f172a !important;
            color: #f8fafc !important;
        }

        .grid-2 {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            width: 100%;
        }

        @media (max-width: 800px) {
            .grid-2 {
                grid-template-columns: 1fr;
                gap: 16px;
            }
        }

        .checkbox-container {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin: 20px 0;
            padding: 14px 18px;
            background: rgba(11, 18, 34, 0.6);
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }

        .checkbox-item {
            display: flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
        }

        .checkbox-item input {
            cursor: pointer;
            width: 16px;
            height: 16px;
            accent-color: var(--accent);
        }

        .checkbox-item label {
            margin: 0;
            cursor: pointer;
            font-size: 0.88rem;
            color: var(--text-main);
        }

        .btn {
            background: linear-gradient(135deg, #0284c7 0%, #06b6d4 100%);
            color: #ffffff;
            border: 1px solid rgba(56, 189, 248, 0.4);
            padding: 12px 28px;
            font-weight: 600;
            font-size: 0.98rem;
            letter-spacing: 0.3px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
            display: inline-flex;
            align-items: center;
            gap: 8px;
            text-decoration: none;
            box-shadow: 0 4px 16px rgba(2, 132, 199, 0.35);
        }

        .btn:hover {
            background: linear-gradient(135deg, #0369a1 0%, #0891b2 100%);
            box-shadow: 0 6px 22px rgba(56, 189, 248, 0.45);
            transform: translateY(-1px);
        }

        .btn-secondary {
            background-color: #1e293b;
            color: #e2e8f0;
            border: 1px solid #334155;
            font-size: 0.88rem;
            padding: 8px 16px;
            box-shadow: none;
            border-radius: 6px;
        }

        .btn-secondary:hover {
            background-color: #334155;
            border-color: #475569;
            color: #ffffff;
            transform: translateY(-1px);
        }

        /* Launch Animation Indicator */
        .crawling-indicator {
            background: var(--bg-card);
            border: 1px solid var(--accent);
            box-shadow: 0 0 25px rgba(56, 189, 248, 0.2), inset 0 0 15px rgba(56, 189, 248, 0.05);
            border-radius: 12px;
            padding: 36px 24px;
            margin-top: 24px;
            margin-bottom: 24px;
            text-align: center;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            animation: fadeIn 0.3s ease-out;
        }

        .scanner-wrap {
            position: relative;
            width: 100px;
            height: 100px;
            margin-bottom: 18px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .radar-pulse {
            position: absolute;
            width: 100%;
            height: 100%;
            border-radius: 50%;
            background: radial-gradient(circle, rgba(56, 189, 248, 0.25) 0%, rgba(6, 182, 212, 0) 70%);
            animation: radarPulse 2s infinite ease-out;
        }

        .radar-ring {
            position: absolute;
            width: 100%;
            height: 100%;
            border-radius: 50%;
            border: 2px dashed rgba(56, 189, 248, 0.35);
            animation: spinCounterClockwise 6s linear infinite;
        }

        .radar-scan {
            position: absolute;
            width: 100%;
            height: 100%;
            border-radius: 50%;
            border: 3.5px solid rgba(56, 189, 248, 0.15);
            border-top: 3.5px solid #38bdf8;
            border-right: 3.5px solid #06b6d4;
            box-shadow: 0 0 18px rgba(56, 189, 248, 0.6);
            animation: spinClockwise 1.1s linear infinite;
        }

        .glass-icon {
            position: relative;
            z-index: 2;
            width: 30px;
            height: 30px;
            color: #38bdf8;
            filter: drop-shadow(0 0 8px rgba(56, 189, 248, 0.7));
            animation: glassPulse 1.8s ease-in-out infinite alternate;
        }

        @keyframes spinClockwise {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }

        @keyframes spinCounterClockwise {
            from { transform: rotate(360deg); }
            to { transform: rotate(0deg); }
        }

        @keyframes radarPulse {
            0% { transform: scale(0.75); opacity: 0.9; }
            50% { transform: scale(1.25); opacity: 0.35; }
            100% { transform: scale(1.6); opacity: 0; }
        }

        @keyframes glassPulse {
            from { transform: scale(0.92); opacity: 0.85; filter: drop-shadow(0 0 6px rgba(56, 189, 248, 0.5)); }
            to { transform: scale(1.08); opacity: 1; filter: drop-shadow(0 0 12px rgba(6, 182, 212, 0.95)); }
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(6px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .indicator-text h3 {
            font-size: 1.25rem;
            font-weight: 700;
            color: #f1f5f9;
            letter-spacing: 0.4px;
            margin-bottom: 6px;
        }

        .indicator-sub {
            font-size: 0.9rem;
            color: var(--text-muted);
            max-width: 600px;
            word-break: break-all;
            margin-bottom: 12px;
        }

        .live-status-pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(56, 189, 248, 0.12);
            border: 1px solid rgba(56, 189, 248, 0.3);
            padding: 6px 14px;
            border-radius: 20px;
            font-family: "JetBrains Mono", Consolas, monospace;
            font-size: 0.82rem;
            color: #38bdf8;
        }

        .pulse-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background-color: #38bdf8;
            box-shadow: 0 0 8px #38bdf8;
            animation: blink 1.2s infinite;
        }

        @keyframes blink {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.4; transform: scale(0.7); }
        }

        /* Progress Bar & Percentage Indicator */
        .progress-section {
            margin-top: 14px;
            width: 100%;
            max-width: 520px;
        }

        .progress-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 6px;
            font-size: 0.82rem;
            font-family: "JetBrains Mono", Consolas, monospace;
        }

        .progress-title {
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.6px;
            font-weight: 600;
            font-size: 0.76rem;
        }

        .progress-percent {
            color: #38bdf8;
            font-weight: 700;
            font-size: 0.95rem;
            text-shadow: 0 0 10px rgba(56, 189, 248, 0.5);
            letter-spacing: 0.5px;
            display: inline-flex;
            align-items: center;
        }

        .progress-percent.indeterminate {
            font-size: 0.82rem;
            font-weight: 600;
        }

        .indeterminate-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            color: #38bdf8;
            letter-spacing: 0.4px;
        }

        .spin-dot-sm {
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background-color: #38bdf8;
            box-shadow: 0 0 8px #38bdf8;
            animation: blink 1.1s infinite;
        }

        .progress-bar-fill.error {
            width: 100% !important;
            background: linear-gradient(90deg, #ef4444 0%, #f87171 100%) !important;
            box-shadow: 0 0 12px rgba(239, 68, 68, 0.6) !important;
        }

        .progress-percent.error {
            color: #f87171 !important;
            text-shadow: 0 0 8px rgba(248, 113, 113, 0.5) !important;
        }

        .progress-bar-track {
            width: 100%;
            height: 10px;
            background: #070d19;
            border: 1px solid rgba(56, 189, 248, 0.25);
            border-radius: 6px;
            overflow: hidden;
            position: relative;
            box-shadow: inset 0 1px 4px rgba(0, 0, 0, 0.7);
        }

        .progress-bar-fill {
            height: 100%;
            background: linear-gradient(90deg, #0284c7 0%, #38bdf8 65%, #22d3ee 100%);
            border-radius: 5px;
            transition: width 0.35s ease-in-out;
            box-shadow: 0 0 12px rgba(56, 189, 248, 0.75);
            position: relative;
        }

        .progress-bar-fill.indeterminate {
            width: 100% !important;
            background: linear-gradient(
                90deg,
                rgba(2, 132, 199, 0.15) 0%,
                rgba(56, 189, 248, 0.85) 50%,
                rgba(34, 211, 238, 0.15) 100%
            );
            background-size: 200% 100%;
            animation: progressIndeterminate 1.8s linear infinite;
        }

        @keyframes progressIndeterminate {
            0% { background-position: 200% 0; }
            100% { background-position: -200% 0; }
        }

        /* Alert Box */
        .alert-box {
            display: flex;
            align-items: flex-start;
            gap: 12px;
            padding: 16px 18px;
            border-radius: 8px;
            margin-bottom: 22px;
            font-size: 0.9rem;
            line-height: 1.5;
        }

        .alert-danger {
            background: rgba(248, 113, 113, 0.12);
            border: 1px solid rgba(248, 113, 113, 0.35);
            color: #fca5a5;
        }

        .alert-icon {
            font-size: 1.2rem;
            flex-shrink: 0;
            line-height: 1;
        }

        .alert-title {
            font-weight: 700;
            color: #f87171;
            margin-bottom: 4px;
        }

        .alert-body {
            font-family: "JetBrains Mono", Consolas, monospace;
            font-size: 0.84rem;
            white-space: pre-wrap;
            word-break: break-word;
            color: #fecaca;
        }

        /* KPI Cards */
        .kpi-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }

        .kpi-card {
            background: rgba(11, 18, 34, 0.7);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 18px 14px;
            text-align: center;
            transition: all 0.2s ease;
        }

        .kpi-card:hover {
            border-color: rgba(56, 189, 248, 0.4);
            box-shadow: 0 4px 16px rgba(56, 189, 248, 0.12);
            transform: translateY(-2px);
        }

        .kpi-val {
            font-size: 1.85rem;
            font-weight: 700;
            color: var(--accent);
            margin: 4px 0;
            letter-spacing: -0.5px;
        }

        .kpi-label {
            font-size: 0.78rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.8px;
            font-weight: 600;
        }

        /* Tabs */
        .tab-nav {
            display: flex;
            gap: 8px;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 20px;
            overflow-x: auto;
            padding-bottom: 4px;
        }

        .tab-btn {
            background: none;
            border: none;
            padding: 10px 18px;
            font-size: 0.92rem;
            font-weight: 600;
            color: var(--text-muted);
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.2s;
            white-space: nowrap;
        }

        .tab-btn:hover {
            color: var(--text-main);
        }

        .tab-btn.active {
            color: var(--accent);
            border-bottom: 2px solid var(--accent);
        }

        .tab-pane {
            display: none;
        }

        .tab-pane.active {
            display: block;
        }

        /* Table */
        .table-responsive {
            width: 100%;
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            background: var(--bg-card);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }

        th, td {
            padding: 13px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
            vertical-align: middle;
        }

        th {
            background: #0b1220;
            color: #94a3b8;
            font-weight: 700;
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 0.6px;
        }

        tr:hover {
            background: var(--bg-card-hover);
        }

        .status-pill {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
        }

        .status-200 { background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); }
        .status-300 { background: rgba(251, 191, 36, 0.15); color: #fbbf24; border: 1px solid rgba(251, 191, 36, 0.3); }
        .status-400 { background: rgba(248, 113, 113, 0.15); color: #f87171; border: 1px solid rgba(248, 113, 113, 0.3); }
        .status-500 { background: rgba(248, 113, 113, 0.25); color: #f87171; border: 1px solid rgba(248, 113, 113, 0.4); }

        /* Domain Type Badges */
        .domain-pill {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.74rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .domain-internal {
            background: rgba(56, 189, 248, 0.12);
            color: #38bdf8;
            border: 1px solid rgba(56, 189, 248, 0.35);
        }

        .domain-external {
            background: rgba(6, 182, 212, 0.12);
            color: #22d3ee;
            border: 1px solid rgba(6, 182, 212, 0.35);
        }

        .domain-na {
            background: rgba(148, 163, 184, 0.12);
            color: #94a3b8;
            border: 1px solid rgba(148, 163, 184, 0.25);
        }

        .crawl-timestamp {
            font-family: "JetBrains Mono", Consolas, "Courier New", monospace;
            font-size: 0.78rem;
            color: #cbd5e1;
            white-space: nowrap;
        }

        .tag-pill {
            background: #172554;
            border: 1px solid rgba(56, 189, 248, 0.25);
            padding: 2px 7px;
            border-radius: 4px;
            font-size: 0.75rem;
            color: #38bdf8;
            margin-right: 4px;
            display: inline-block;
        }

        .tag-ssl-unverified {
            background: rgba(234, 179, 8, 0.15);
            border: 1px solid rgba(234, 179, 8, 0.4);
            color: #facc15;
            padding: 2px 7px;
            border-radius: 4px;
            font-size: 0.72rem;
            display: inline-flex;
            align-items: center;
            gap: 4px;
            margin-top: 4px;
            font-weight: 600;
        }

        a.out-link {
            color: #38bdf8;
            text-decoration: none;
            word-break: break-all;
            transition: color 0.2s;
        }

        a.out-link:hover {
            color: #7dd3fc;
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="app-shell">
        <!-- Fixed Top Header Bar (Anchored Top Bar) -->
        <header class="header">
            <div class="header-inner">
                <div class="header-title">
                    <h1>⚡ TorBot OSINT Dashboard</h1>
                    <p>Dark Web (.onion) & Clearnet Reconnaissance Intelligence Suite</p>
                </div>
                <div class="header-status">
                    <span class="badge badge-online">
                        <span class="status-dot"></span> OSINT Engine Active
                    </span>
                </div>
            </div>
        </header>

        <!-- Constant Main Content Workspace Area -->
        <main class="main-workspace main-content">
            <div class="container">
                <!-- Scan Form Card -->
                <div class="card">
            <div class="card-title">
                <span>🎯 Launch New Target Reconnaissance</span>
            </div>
            <form method="POST" id="recon-form" action="/">
                <div class="form-group">
                    <label for="url">Target Link / .Onion Address / Dark Web Search: <span class="label-hint">(URL, .onion, or search keyword)</span></label>
                    <input type="text" id="url" name="url" placeholder="Enter .onion address, URL, or dark web search query (e.g. cyber, market, hidden wiki)..." value="{{ request.form.get('url', '') }}" required>
                </div>

                <div class="grid-2">
                    <div class="form-group">
                        <label for="depth">Crawl Depth: <span class="label-hint">(0 = Single URL, 1 = Direct links, 2 = 2 levels)</span></label>
                        <select id="depth" name="depth">
                            <option value="0" {% if request.form.get('depth') == '0' %}selected{% endif %}>Depth 0 - Single URL Only (Fastest)</option>
                            <option value="1" {% if request.form.get('depth') == '1' or not request.form.get('depth') %}selected{% endif %}>Depth 1 - Direct Page Links (Recommended)</option>
                            <option value="2" {% if request.form.get('depth') == '2' %}selected{% endif %}>Depth 2 - Subtree Links (2 Levels)</option>
                            <option value="3" {% if request.form.get('depth') == '3' %}selected{% endif %}>Depth 3 - Deep Crawl (3 Levels)</option>
                            <option value="4" {% if request.form.get('depth') == '4' %}selected{% endif %}>Depth 4 - Deep Crawl (4 Levels)</option>
                            <option value="5" {% if request.form.get('depth') == '5' %}selected{% endif %}>Depth 5 - Maximum Recursive Crawl (5 Levels)</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label for="action">Action / Output Mode:</label>
                        <select id="action" name="action">
                            <option value="table" {% if request.form.get('action') == 'table' or not request.form.get('action') %}selected{% endif %}>Visual Table Crawl (--visualize table)</option>
                            <option value="tree" {% if request.form.get('action') == 'tree' %}selected{% endif %}>Link Tree Structure (--visualize tree)</option>
                            <option value="json" {% if request.form.get('action') == 'json' %}selected{% endif %}>JSON Tree Data (--visualize json)</option>
                            <option value="info" {% if request.form.get('action') == 'info' %}selected{% endif %}>Deep Security & Info Recon (--info)</option>
                            <option value="analyze" {% if request.form.get('action') == 'analyze' %}selected{% endif %}>Full Crawl + AI Analyst Investigation</option>
                        </select>
                    </div>
                </div>

                <!-- Checkboxes -->
                <div class="checkbox-container">
                    <div class="checkbox-item">
                        <input type="checkbox" id="run_info" name="run_info" {% if request.form.get('run_info') or request.method == 'GET' %}checked{% endif %}>
                        <label for="run_info">Deep Security & Recon (--info)</label>
                    </div>
                    <div class="checkbox-item">
                        <input type="checkbox" id="resolve_relative" name="resolve_relative" {% if request.form.get('resolve_relative') or request.method == 'GET' %}checked{% endif %}>
                        <label for="resolve_relative">Resolve Relative Links (--resolve-relative)</label>
                    </div>
                    <div class="checkbox-item">
                        <input type="checkbox" id="save_result" name="save_result" {% if request.form.get('save_result') or request.method == 'GET' %}checked{% endif %}>
                        <label for="save_result">Generate Versioned Crawl Bundle (--save result)</label>
                    </div>
                    <div class="checkbox-item">
                        <input type="checkbox" id="disable_socks" name="disable_socks" {% if request.form.get('disable_socks') and '.onion' not in (request.form.get('url', '')|lower) %}checked{% endif %}>
                        <label for="disable_socks" id="disable_socks_label">Disable SOCKS5 Proxy (Direct Clearnet)</label>
                    </div>
                </div>

                <div style="margin-top: 20px;">
                    <button type="submit" id="submit-btn" class="btn">🚀 Launch OSINT Reconnaissance</button>
                </div>
            </form>
        </div>

        <!-- Launch Animation Indicator (shows during active crawl) -->
        <div id="crawling-indicator" class="crawling-indicator" style="display: none;">
            <div class="scanner-wrap">
                <div class="radar-pulse"></div>
                <div class="radar-ring"></div>
                <div class="radar-scan"></div>
                <svg class="glass-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="11" cy="11" r="8"></circle>
                    <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                </svg>
            </div>
            <div class="indicator-text">
                <h3>Crawling in Progress...</h3>
                <p class="indicator-sub">Target: <strong id="indicator-target" style="color: var(--accent);">(initializing...)</strong></p>
                <div class="live-status-pill">
                    <span class="pulse-dot"></span>
                    <span id="elapsed-counter">Elapsed: 00:00</span>
                    <span style="opacity: 0.5;">|</span>
                    <span id="status-hint">Active crawl running...</span>
                </div>
                <div class="progress-section">
                    <div class="progress-header">
                        <span class="progress-title">Crawl Progress</span>
                        <span id="progress-percentage" class="progress-percent">0%</span>
                    </div>
                    <div class="progress-bar-track">
                        <div id="progress-bar-fill" class="progress-bar-fill indeterminate" style="width: 0%;"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Dynamic Error Banner (for frontend errors / failures) -->
        <div id="dynamic-error-banner" class="alert-box alert-danger" style="display: none;"></div>

        <!-- Results Area -->
        <div id="results-area-container">
            {% if command_run %}
            <div class="card" id="results-card">
                <div class="card-title">
                    <span>📊 Scan Results for: <code>{{ raw_query or target_url }}</code>{% if raw_query and raw_query != target_url %} <small style="color: var(--text-muted); font-size: 0.8rem;">(Resolved: {{ target_url }})</small>{% endif %}</span>
                    <div>
                        <span class="badge {% if return_code == 0 %}badge-online{% else %}badge-offline{% endif %}">
                            Exit Code: {{ return_code }}
                        </span>
                        {% if result_available %}
                        <a href="/download/result" class="btn btn-secondary" style="margin-left: 8px;">📥 Download JSON</a>
                        {% endif %}
                    </div>
                </div>

                {% if command_run and not command_run.startswith('(aborted:') %}
                <div style="font-family: 'JetBrains Mono', Consolas, monospace; font-size: 0.78rem; color: var(--text-muted); margin-bottom: 16px; word-break: break-all; background: rgba(7, 13, 25, 0.6); padding: 8px 12px; border-radius: 6px; border: 1px solid var(--border-color);">
                    <strong style="color: var(--accent);">Command:</strong> <code>{{ command_run }}</code>
                </div>
                {% endif %}

                {% if return_code != 0 %}
                <div class="alert-box alert-danger">
                    <div class="alert-icon">⚠️</div>
                    <div style="flex: 1;">
                        <div class="alert-title">Scan Failed or Incomplete (Exit Code {{ return_code }})</div>
                        <div class="alert-body">{{ console_output or "Target crawl terminated with errors. Verify connectivity, URL format, or Tor proxy service." }}</div>
                    </div>
                </div>
                {% endif %}

                {% if ssl_notice %}
                <div class="alert-box alert-info" style="background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.3); color: #38bdf8; margin-bottom: 18px; padding: 12px 16px; border-radius: 8px; font-size: 0.85rem; display: flex; align-items: center; gap: 10px;">
                    <span style="font-size: 1.15rem;">🔒</span>
                    <div>
                        <strong>Dark Web TLS Security Notice:</strong>
                        <span>.onion HTTPS self-signed / unverified certificate safely accepted within scoped Tor transport. Tor onion routing provides cryptographic end-to-end authentication and transport encryption.</span>
                    </div>
                </div>
                {% endif %}

                <!-- KPI Row -->
                <div class="kpi-row">
                    <div class="kpi-card">
                        <div class="kpi-label">Pages Scanned</div>
                        <div class="kpi-val">{{ total_pages }}</div>
                        {% if url_stats and url_stats.uniqueDiscoveredUrls and url_stats.uniqueDiscoveredUrls > total_pages %}
                        <div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 2px;" title="Discovered URLs (Internal Debugging)">
                            {{ url_stats.uniqueDiscoveredUrls }} Discovered URLs
                        </div>
                        {% endif %}
                    </div>
                    <div class="kpi-card">
                        <div class="kpi-label">Emails Found</div>
                        <div class="kpi-val">{{ emails_found|length }}</div>
                    </div>
                    <div class="kpi-card">
                        <div class="kpi-label">Phones Found</div>
                        <div class="kpi-val">{{ phones_found|length }}</div>
                    </div>
                    <div class="kpi-card">
                        <div class="kpi-label">BTC Wallets</div>
                        <div class="kpi-val">{{ btc_found|length }}</div>
                    </div>
                    <div class="kpi-card">
                        <div class="kpi-label">AI Classification</div>
                        <div class="kpi-val" style="font-size: 1.15rem; color: var(--info);">
                            {{ classification_label or "N/A" }}
                        </div>
                    </div>
                </div>

                <!-- Tab Navigation (Only Crawled Pages) -->
                <div class="tab-nav">
                    <button type="button" class="tab-btn active" onclick="switchTab('tab-pages')">📋 Crawled Pages ({{ total_pages }})</button>
                </div>

                <!-- Tab 1: Pages Table -->
                <div id="tab-pages" class="tab-pane active">
                    <div class="table-responsive">
                        <table>
                            <thead>
                                <tr>
                                    <th>Page Title</th>
                                    <th>URL</th>
                                    <th>Domain Type</th>
                                    <th>Depth</th>
                                    <th>Status</th>
                                    <th>Contacts (Emails / Phones)</th>
                                    <th>Category</th>
                                    <th>Links</th>
                                    <th>Crawl Timestamp</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for page in pages %}
                                <tr>
                                    <td><strong>{{ page.title or "Untitled" }}</strong></td>
                                    <td><a href="{{ page.url }}" target="_blank" rel="noopener noreferrer" class="out-link">{{ page.url }}</a></td>
                                    <td>
                                        {% set dt = (page.domainType or page.domain_type or '')|lower %}
                                        {% if dt == 'internal' %}
                                            <span class="domain-pill domain-internal">Internal</span>
                                        {% elif dt == 'external' %}
                                            <span class="domain-pill domain-external">External</span>
                                        {% elif page.domainType or page.domain_type %}
                                            <span class="domain-pill domain-na">{{ page.domainType or page.domain_type }}</span>
                                        {% else %}
                                            <span class="domain-pill domain-na">N/A</span>
                                        {% endif %}
                                    </td>
                                    <td>{{ page.depth }}</td>
                                    <td>
                                        {% if page.status %}
                                            <span class="status-pill status-{{ page.status // 100 * 100 }}">{{ page.status }}</span>
                                        {% else %}
                                            <span class="status-pill status-500">{{ page.outcome }}</span>
                                        {% endif %}
                                        {% if page.unverifiedSsl or (page.url and page.url.startswith('https://') and '.onion' in page.url|lower) %}
                                            <br><span class="tag-ssl-unverified" title="Tor onion routing provides cryptographic end-to-end transport encryption; TLS certificate is self-signed/unverified">🔒 Self-Signed TLS</span>
                                        {% endif %}
                                    </td>
                                    <td>
                                        {% for c in page.contacts %}
                                            <span class="tag-pill">{{ c.source }}: {{ c.value }}</span>
                                        {% else %}
                                            <span style="color: var(--text-muted);">-</span>
                                        {% endfor %}
                                    </td>
                                    <td>
                                        {% if page.classification and page.classification.label %}
                                            {{ page.classification.label }} ({{ (page.classification.accuracy * 100)|round(1) }}%)
                                        {% else %}
                                            -
                                        {% endif %}
                                    </td>
                                    <td>{{ page.links|length }}</td>
                                    <td>
                                        {% set ts = page.timestamp or page.crawledAt or page.crawled_at %}
                                        {% if ts %}
                                            <span class="crawl-timestamp" data-utc="{{ ts }}">{{ ts }}</span>
                                        {% else %}
                                            <span class="crawl-timestamp" style="color: var(--text-muted);">N/A</span>
                                        {% endif %}
                                    </td>
                                </tr>
                                {% else %}
                                <tr>
                                    <td colspan="9" style="text-align: center; color: var(--text-muted);">No structured pages recorded. Check terminal console output.</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>

                    {% if action_mode == 'tree' and tree_output %}
                    <div style="margin-top: 22px; padding: 18px; background: rgba(7, 13, 25, 0.85); border: 1px solid rgba(56, 189, 248, 0.35); border-radius: 8px;">
                        <div style="font-weight: 600; font-size: 0.95rem; color: var(--accent); margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                            <span>🌳 Link Tree Structure (--visualize tree)</span>
                        </div>
                        <pre style="font-family: 'JetBrains Mono', Consolas, monospace; font-size: 0.88rem; line-height: 1.6; color: #7dd3fc; white-space: pre-wrap; margin: 0; overflow-x: auto;">{{ tree_output }}</pre>
                    </div>
                    {% endif %}

                    {% if action_mode == 'json' and json_pretty and json_pretty != '{}' %}
                    <div style="margin-top: 22px; padding: 18px; background: rgba(7, 13, 25, 0.85); border: 1px solid rgba(56, 189, 248, 0.35); border-radius: 8px;">
                        <div style="font-weight: 600; font-size: 0.95rem; color: var(--accent); margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                            <span>📄 JSON Tree Data (--visualize json)</span>
                        </div>
                        <pre style="font-family: 'JetBrains Mono', Consolas, monospace; font-size: 0.84rem; line-height: 1.5; color: #a5f3fc; white-space: pre-wrap; margin: 0; overflow-x: auto; max-height: 500px;">{{ json_pretty }}</pre>
                    </div>
                    {% endif %}

                    {% if analyst_report %}
                    <div style="margin-top: 22px; padding: 18px; background: rgba(7, 13, 25, 0.85); border: 1px solid rgba(56, 189, 248, 0.4); border-radius: 8px;">
                        <div style="font-weight: 600; font-size: 0.95rem; color: var(--accent); margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                            <span>🤖 Full Crawl + AI Analyst Investigation Report</span>
                        </div>
                        <div style="font-family: 'JetBrains Mono', Consolas, monospace; font-size: 0.86rem; line-height: 1.6; color: #e2e8f0; white-space: pre-wrap; overflow-x: auto;">{{ analyst_report }}</div>
                    </div>
                    {% endif %}

                    {% if (action_mode == 'info' or request.form.get('run_info')) and recon_data and (recon_data.robots_status or recon_data.git_status or recon_data.svn_status or recon_data.htaccess_status) %}
                    <div style="margin-top: 22px; padding: 18px; background: rgba(7, 13, 25, 0.85); border: 1px solid rgba(56, 189, 248, 0.35); border-radius: 8px;">
                        <div style="font-weight: 600; font-size: 0.95rem; color: var(--accent); margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                            <span>🛡️ Deep Security & Recon Intelligence (--info)</span>
                        </div>
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; font-size: 0.85rem;">
                            <div style="background: rgba(15, 23, 42, 0.7); padding: 10px 14px; border-radius: 6px; border: 1px solid var(--border-color);">
                                <span style="color: var(--text-muted); display: block; font-size: 0.75rem; text-transform: uppercase;">Robots.txt</span>
                                <strong style="color: #38bdf8;">{{ recon_data.robots_status or "Not Found" }}</strong>
                            </div>
                            <div style="background: rgba(15, 23, 42, 0.7); padding: 10px 14px; border-radius: 6px; border: 1px solid var(--border-color);">
                                <span style="color: var(--text-muted); display: block; font-size: 0.75rem; text-transform: uppercase;">.git Folder</span>
                                <strong style="color: #38bdf8;">{{ recon_data.git_status or "Safe" }}</strong>
                            </div>
                            <div style="background: rgba(15, 23, 42, 0.7); padding: 10px 14px; border-radius: 6px; border: 1px solid var(--border-color);">
                                <span style="color: var(--text-muted); display: block; font-size: 0.75rem; text-transform: uppercase;">.svn Folder</span>
                                <strong style="color: #38bdf8;">{{ recon_data.svn_status or "Safe" }}</strong>
                            </div>
                            <div style="background: rgba(15, 23, 42, 0.7); padding: 10px 14px; border-radius: 6px; border: 1px solid var(--border-color);">
                                <span style="color: var(--text-muted); display: block; font-size: 0.75rem; text-transform: uppercase;">.htaccess</span>
                                <strong style="color: #38bdf8;">{{ recon_data.htaccess_status or "Safe" }}</strong>
                            </div>
                        </div>
                    </div>
                    {% endif %}
                </div>
            </div>
            {% endif %}
        </div>
        </div>
        </main>
    </div>

    <script>
        function switchTab(tabId) {
            document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            const targetPane = document.getElementById(tabId);
            if (targetPane) {
                targetPane.classList.add('active');
            }
            if (window.event && window.event.currentTarget) {
                window.event.currentTarget.classList.add('active');
            }
        }

        function showErrorMessage(msg) {
            let dynamicErr = document.getElementById('dynamic-error-banner');
            if (!dynamicErr) {
                dynamicErr = document.createElement('div');
                dynamicErr.id = 'dynamic-error-banner';
                dynamicErr.className = 'alert-box alert-danger';
                const indicator = document.getElementById('crawling-indicator');
                if (indicator && indicator.parentNode) {
                    indicator.parentNode.insertBefore(dynamicErr, indicator.nextSibling);
                }
            }
            dynamicErr.innerHTML = '<div class="alert-icon">⚠️</div><div style="flex: 1;"><div class="alert-title">Crawling Error</div><div class="alert-body">' + escapeHtml(msg) + '</div></div>';
            dynamicErr.style.display = 'flex';
            dynamicErr.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text || '';
            return div.innerHTML;
        }

        // Live progress bar and percentage updater (0% to 100%)
        function updateCrawlProgress(percent) {
            const percentEl = document.getElementById('progress-percentage');
            const fillEl = document.getElementById('progress-bar-fill');

            if (percent === null || percent === undefined || percent === 'indeterminate') {
                setIndeterminateProgress();
                return;
            }

            const p = Math.max(0, Math.min(100, Math.round(Number(percent))));
            if (percentEl) {
                percentEl.classList.remove('indeterminate', 'error');
                percentEl.textContent = p + '%';
            }
            if (fillEl) {
                fillEl.classList.remove('indeterminate', 'error');
                fillEl.style.width = p + '%';
            }
        }

        // Indeterminate progress mode when backend progress data is unavailable
        function setIndeterminateProgress() {
            const percentEl = document.getElementById('progress-percentage');
            const fillEl = document.getElementById('progress-bar-fill');
            if (fillEl) {
                fillEl.classList.remove('error');
                fillEl.classList.add('indeterminate');
                fillEl.style.width = '100%';
            }
            if (percentEl) {
                percentEl.classList.remove('error');
                percentEl.classList.add('indeterminate');
                percentEl.innerHTML = '<span class="indeterminate-badge"><span class="spin-dot-sm"></span>Crawling...</span>';
            }
        }

        // Progress error state helper
        function setProgressError(msg) {
            const percentEl = document.getElementById('progress-percentage');
            const fillEl = document.getElementById('progress-bar-fill');
            if (fillEl) {
                fillEl.classList.remove('indeterminate');
                fillEl.classList.add('error');
                fillEl.style.width = '100%';
            }
            if (percentEl) {
                percentEl.classList.remove('indeterminate');
                percentEl.classList.add('error');
                percentEl.textContent = 'Failed';
            }
            showErrorMessage(msg || 'Crawling encountered an error.');
        }

        window.updateCrawlProgress = updateCrawlProgress;
        window.setIndeterminateProgress = setIndeterminateProgress;
        window.setProgressError = setProgressError;

        // Setup launch animation on form submit
        function setupLaunchAnimation() {
            const form = document.getElementById('recon-form');
            if (!form) return;

            form.addEventListener('submit', function(e) {
                const urlInput = document.getElementById('url');
                const targetVal = urlInput ? urlInput.value.trim() : '';
                if (!targetVal) return;

                // Prevent page reload so rotating blue circular animation continues uninterrupted
                e.preventDefault();

                const indicator = document.getElementById('crawling-indicator');
                const targetSpan = document.getElementById('indicator-target');
                const elapsedSpan = document.getElementById('elapsed-counter');
                const submitBtn = document.getElementById('submit-btn');
                const resultsContainer = document.getElementById('results-area-container');
                const dynamicErr = document.getElementById('dynamic-error-banner');

                // Clear previous dynamic error banner
                if (dynamicErr) {
                    dynamicErr.style.display = 'none';
                    dynamicErr.innerHTML = '';
                }

                // If existing results are present, dim them while new crawl executes
                if (resultsContainer) {
                    resultsContainer.style.opacity = '0.35';
                    resultsContainer.style.pointerEvents = 'none';
                }

                // If actual progress data is unavailable from backend during crawl,
                // activate indeterminate progress indicator instead of remaining stuck at 0%
                setIndeterminateProgress();

                // Show continuously rotating blue circular animation
                if (targetSpan) targetSpan.textContent = targetVal;
                if (indicator) {
                    indicator.style.display = 'flex';
                    indicator.scrollIntoView({ behavior: 'smooth', block: 'center' });
                }

                // Update submit button state
                if (submitBtn) {
                    submitBtn.disabled = true;
                    submitBtn.textContent = '⏳ Crawling in Progress...';
                    submitBtn.style.opacity = '0.7';
                    submitBtn.style.cursor = 'not-allowed';
                }

                // Track actual elapsed time (no fake progress milestones or timers)
                let elapsedSecs = 0;
                if (elapsedSpan) elapsedSpan.textContent = 'Elapsed: 00:00';
                const startTime = Date.now();
                const timer = setInterval(function() {
                    elapsedSecs = Math.floor((Date.now() - startTime) / 1000);
                    const mins = String(Math.floor(elapsedSecs / 60)).padStart(2, '0');
                    const secs = String(elapsedSecs % 60).padStart(2, '0');
                    if (elapsedSpan) elapsedSpan.textContent = 'Elapsed: ' + mins + ':' + secs;
                }, 1000);

                // Ensure SOCKS5 proxy is never disabled for .onion addresses
                const urlInputEl = form.querySelector('#url');
                const urlVal = (urlInputEl ? urlInputEl.value : '').trim().toLowerCase();
                if (urlVal.includes('.onion')) {
                    const disableSocksCb = form.querySelector('#disable_socks');
                    if (disableSocksCb) {
                        disableSocksCb.checked = false;
                    }
                }

                // Dispatch real POST request to backend
                // Use getAttribute('action') because input <select name="action"> shadows action property
                const targetEndpoint = form.getAttribute('action') || window.location.pathname || '/';
                const formData = new FormData(form);

                fetch(targetEndpoint, {
                    method: 'POST',
                    body: formData,
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                })
                .then(function(response) {
                    if (!response.ok) {
                        throw new Error('Server returned HTTP ' + response.status + ' (' + response.statusText + ')');
                    }
                    return response.text();
                })
                .then(function(htmlText) {
                    // Parse returned response
                    const parser = new DOMParser();
                    const doc = parser.parseFromString(htmlText, 'text/html');
                    const newResultsCard = doc.getElementById('results-card');

                    // Check if crawl execution encountered a failure
                    const alertBox = doc.querySelector('.alert-box.alert-danger');
                    const offlineBadge = doc.querySelector('.badge-offline');
                    const isCrawlFailure = alertBox !== null || (offlineBadge && !offlineBadge.textContent.includes('Exit Code: 0'));

                    if (isCrawlFailure) {
                        // Crawling failed - show error state instead of 100%
                        clearInterval(timer);
                        if (indicator) indicator.style.display = 'none';
                        if (submitBtn) {
                            submitBtn.disabled = false;
                            submitBtn.textContent = '🚀 Launch OSINT Reconnaissance';
                            submitBtn.style.opacity = '1';
                            submitBtn.style.cursor = 'pointer';
                        }
                        if (newResultsCard && resultsContainer) {
                            resultsContainer.innerHTML = newResultsCard.outerHTML;
                            resultsContainer.style.opacity = '1';
                            resultsContainer.style.pointerEvents = 'auto';
                            formatLocalTimestamps();
                            resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
                        } else {
                            const errorMsg = alertBox ? alertBox.textContent.trim() : 'Crawling encountered an error.';
                            setProgressError(errorMsg);
                        }
                        return;
                    }

                    // Accurately show 100% when crawl completes successfully
                    updateCrawlProgress(100);

                    // Smooth completion pause so 100% is displayed before revealing Crawled Pages
                    setTimeout(function() {
                        clearInterval(timer);
                        if (indicator) indicator.style.display = 'none';
                        if (submitBtn) {
                            submitBtn.disabled = false;
                            submitBtn.textContent = '🚀 Launch OSINT Reconnaissance';
                            submitBtn.style.opacity = '1';
                            submitBtn.style.cursor = 'pointer';
                        }

                        if (newResultsCard && resultsContainer) {
                            resultsContainer.innerHTML = newResultsCard.outerHTML;
                            resultsContainer.style.opacity = '1';
                            resultsContainer.style.pointerEvents = 'auto';

                            // Format timestamps to local date & time
                            formatLocalTimestamps();

                            // Automatically scroll to Crawled Pages results
                            resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
                        } else if (newResultsCard) {
                            const fallbackDiv = document.createElement('div');
                            fallbackDiv.id = 'results-area-container';
                            fallbackDiv.innerHTML = newResultsCard.outerHTML;
                            indicator.parentNode.insertBefore(fallbackDiv, indicator.nextSibling);
                            formatLocalTimestamps();
                            fallbackDiv.scrollIntoView({ behavior: 'smooth', block: 'start' });
                        } else {
                            const errorMsg = alertBox ? alertBox.textContent.trim() : 'Crawling completed but no result structure was generated.';
                            setProgressError(errorMsg);
                        }
                    }, 350);
                })
                .catch(function(err) {
                    // Stop animation immediately on failure and show error
                    clearInterval(timer);
                    if (indicator) indicator.style.display = 'none';
                    if (submitBtn) {
                        submitBtn.disabled = false;
                        submitBtn.textContent = '🚀 Launch OSINT Reconnaissance';
                        submitBtn.style.opacity = '1';
                        submitBtn.style.cursor = 'pointer';
                    }
                    if (resultsContainer) {
                        resultsContainer.style.opacity = '1';
                        resultsContainer.style.pointerEvents = 'auto';
                    }
                    setProgressError('Crawling failed: ' + (err.message || err));
                });
            });
        }

        // Format UTC ISO timestamps to user local readable date and time
        function formatLocalTimestamps() {
            document.querySelectorAll('.crawl-timestamp[data-utc]').forEach(function(el) {
                const raw = el.getAttribute('data-utc');
                if (!raw || raw === 'None' || raw === 'N/A' || raw.trim() === '') {
                    el.textContent = 'N/A';
                    return;
                }
                try {
                    const dt = new Date(raw);
                    if (isNaN(dt.getTime())) {
                        el.textContent = raw || 'N/A';
                    } else {
                        el.textContent = dt.toLocaleString();
                        el.title = "UTC: " + raw;
                    }
                } catch(e) {
                    el.textContent = raw || 'N/A';
                }
            });
        }

        // Auto uncheck & lock "Disable SOCKS5 Proxy" when an .onion address is entered
        function setupOnionProxyCheckboxSync() {
            const urlInput = document.getElementById('url');
            const disableSocksCb = document.getElementById('disable_socks');
            const disableSocksLabel = document.getElementById('disable_socks_label');
            if (!urlInput || !disableSocksCb) return;

            function syncProxyCheckbox() {
                const isDarkWeb = (urlInput.value || '').trim().toLowerCase().includes('.onion');
                if (isDarkWeb) {
                    disableSocksCb.checked = false;
                    disableSocksCb.disabled = true;
                    if (disableSocksLabel) {
                        disableSocksLabel.style.opacity = '0.55';
                        disableSocksLabel.title = 'Tor SOCKS5 proxy is required for .onion dark web addresses.';
                    }
                } else {
                    disableSocksCb.disabled = false;
                    if (disableSocksLabel) {
                        disableSocksLabel.style.opacity = '1';
                        disableSocksLabel.title = '';
                    }
                }
            }

            urlInput.addEventListener('input', syncProxyCheckbox);
            urlInput.addEventListener('change', syncProxyCheckbox);
            syncProxyCheckbox();
        }

        document.addEventListener('DOMContentLoaded', function() {
            setupLaunchAnimation();
            setupOnionProxyCheckboxSync();
            formatLocalTimestamps();
        });
        formatLocalTimestamps();
    </script>
</body>
</html>
"""


def extract_tree_from_stdout(text: str) -> str:
    """Extract LinkTree hierarchy from console stdout."""
    clean = strip_ansi(text)
    lines = clean.splitlines()
    tree_lines = []
    capture = False
    for line in lines:
        if "Crawl result written to" in line or "Investigation report" in line or "Title " in line or "----------------" in line:
            if capture:
                break
            continue
        if ("├──" in line or "└──" in line or "│" in line) or (capture and line.strip()):
            capture = True
            tree_lines.append(line)
        elif not capture and ("http://" in line or "https://" in line) and ("(" in line and ")" in line):
            capture = True
            tree_lines.append(line)
    return "\n".join(tree_lines).strip()


@app.route("/", methods=["GET", "POST"])
def index():
    tor_host = "127.0.0.1"
    tor_port = 9050
    tor_online = check_tor_service(tor_host, tor_port)

    output = ""
    command_run = None
    return_code = 0
    pages: List[Dict[str, Any]] = []
    emails_found: List[str] = []
    phones_found: List[str] = []
    btc_found: List[str] = []
    classification_label = None
    recon_data: Dict[str, Any] = {}
    json_pretty = "{}"
    analyst_report = None
    tree_output = None
    action_mode = "table"
    result_available = False
    raw_query = ""
    target_url = ""
    url_stats: Dict[str, Any] = {}

    if request.method == "POST":
        raw_query = request.form.get("url", "").strip()
        if not raw_query:
            output = "Error: Please enter a target URL, .onion address, or search query."
            return_code = 1
            command_run = "(none)"
        else:
            raw_depth = request.form.get("depth", "1").strip()
            try:
                depth = max(0, min(5, int(raw_depth)))
            except ValueError:
                depth = 1

            action = request.form.get("action", "table").strip()
            run_info = request.form.get("run_info")
            resolve_relative = request.form.get("resolve_relative")
            save_result = request.form.get("save_result")
            disable_socks = request.form.get("disable_socks")
            target_url = normalize_url(raw_query, disable_socks=bool(disable_socks))
            tor_host = request.form.get("host", "127.0.0.1").strip() or "127.0.0.1"
            try:
                tor_port = int(request.form.get("port", "9050").strip() or "9050")
            except ValueError:
                tor_port = 9050

            # Guard: .onion addresses must always route through Tor SOCKS5 proxy
            if ".onion" in target_url.lower():
                disable_socks = None
                if not tor_online:
                    output = (
                        f"Error: Tor SOCKS5 proxy is offline or unreachable on {tor_host}:{tor_port}.\n\n"
                        f"Cannot crawl .onion dark web addresses without an active Tor service.\n"
                        f"Please start Tor (e.g. 'sudo systemctl start tor') and retry."
                    )
                    return_code = 1
                    command_run = f"(aborted: Tor offline on {tor_host}:{tor_port})"

            if RESULT_FILE.exists():
                try:
                    RESULT_FILE.unlink()
                except Exception:
                    pass

            if not (command_run and command_run.startswith("(aborted:")):
                script_path = REPO_DIR / "main.py"
                venv_py = REPO_DIR / ".venv" / "bin" / "python"
                python_exec = str(venv_py) if venv_py.exists() else sys.executable

                cmd = [python_exec, str(script_path), "-u", target_url, "-q"]
                cmd.extend(["--depth", str(depth)])
                cmd.extend(["--host", tor_host, "--port", str(tor_port)])

                if action == "info" or run_info:
                    cmd.append("--info")

                if action in ("table", "tree", "json"):
                    cmd.extend(["--visualize", action])

                if resolve_relative:
                    cmd.append("--resolve-relative")

                if disable_socks:
                    cmd.append("--disable-socks5")

                # Always save crawl result for rich UI display
                cmd.extend(["--save", "result", "--result-file", str(RESULT_FILE)])

                command_run = " ".join(cmd)

                try:
                    res = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=300,
                        cwd=str(REPO_DIR),
                    )
                    stdout_str = res.stdout or ""
                    stderr_str = res.stderr or ""
                    output = stdout_str + ("\n" + stderr_str if stderr_str else "")
                    return_code = res.returncode
                    if not output.strip():
                        output = "Command finished with no output."
                except subprocess.TimeoutExpired as exc:
                    stdout_str = exc.stdout or ""
                    stderr_str = exc.stderr or ""
                    if isinstance(stdout_str, bytes):
                        stdout_str = stdout_str.decode("utf-8", errors="replace")
                    if isinstance(stderr_str, bytes):
                        stderr_str = stderr_str.decode("utf-8", errors="replace")
                    output = (
                        "Warning: Crawl execution reached 300 second timeout limit.\n"
                        + (stdout_str + ("\n" + stderr_str if stderr_str else ""))
                    ).strip()
                    return_code = 0 if (RESULT_FILE.exists() and RESULT_FILE.stat().st_size > 0) else -1
                except Exception as exc:
                    output = f"Execution failed: {exc}"
                    return_code = -1

            # Read generated crawl result JSON if available
            if RESULT_FILE.exists() and RESULT_FILE.stat().st_size > 0:
                try:
                    with open(RESULT_FILE, "r", encoding="utf-8") as f:
                        crawl_data = json.load(f)
                    result_available = True
                    term_status = crawl_data.get("terminalStatus", "completed")
                    if term_status in ("failed", "invalid"):
                        return_code = 1
                        diag_err = crawl_data.get("diagnostics", {}).get("error")
                        if diag_err and diag_err not in output:
                            output = f"Crawl {term_status.capitalize()}: {diag_err}\n\n" + output
                    raw_pages = crawl_data.get("pages", [])

                    # Filter strictly to unique, verified HTTP 200 pages
                    seen_page_urls = set()
                    verified_pages = []
                    status_counts = {}
                    for p in raw_pages:
                        st = p.get("status")
                        oc = p.get("outcome")
                        u = p.get("url")
                        if st is not None:
                            status_counts[st] = status_counts.get(st, 0) + 1
                        if st == 200 and oc in ("fetched", None) and u and u not in seen_page_urls:
                            seen_page_urls.add(u)
                            verified_pages.append(p)

                    pages = verified_pages

                    # Build URL statistics for internal debugging & diagnostics tab
                    saved_stats = crawl_data.get("stats") or {}
                    raw_urls_set = {p.get("url") for p in raw_pages if p.get("url")}
                    total_discovered = (
                        saved_stats.get("totalDiscoveredUrls")
                        or len(crawl_data.get("discoveredUrls", []))
                        or len(raw_pages)
                    )
                    unique_discovered = (
                        saved_stats.get("uniqueDiscoveredUrls")
                        or len(crawl_data.get("discoveredUrls", []))
                        or len(raw_urls_set)
                        or len(verified_pages)
                    )
                    unverified_count = (
                        saved_stats.get("unverifiedOrNon200Urls")
                        if saved_stats.get("unverifiedOrNon200Urls") is not None
                        else saved_stats.get("unverifiedUrls", len(raw_urls_set) - len(verified_pages))
                    )
                    merged_status_counts = saved_stats.get("statusCounts") or status_counts

                    url_stats = {
                        "totalPages": len(verified_pages),
                        "verifiedPages": len(verified_pages),
                        "totalDiscoveredUrls": max(total_discovered, len(raw_pages)),
                        "uniqueDiscoveredUrls": unique_discovered,
                        "unverifiedOrNon200Urls": unverified_count,
                        "unverifiedUrls": unverified_count,
                        "statusCounts": merged_status_counts,
                    }

                    # Keep crawl_data synchronized with verified pages and diagnostics
                    crawl_data["pages"] = verified_pages
                    crawl_data["stats"] = url_stats
                    if "discoveredUrls" not in crawl_data:
                        crawl_data["discoveredUrls"] = [
                            {
                                "url": p.get("url"),
                                "status": p.get("status"),
                                "title": p.get("title"),
                                "domainType": p.get("domainType", "Internal"),
                                "timestamp": p.get("timestamp"),
                                "isVerified200": p.get("status") == 200,
                            }
                            for p in raw_pages
                        ]
                    json_pretty = json.dumps(crawl_data, indent=2)

                    # Persist updated crawl_data so /download/result exactly matches verified pages
                    try:
                        with open(RESULT_FILE, "w", encoding="utf-8") as f:
                            json.dump(crawl_data, f, indent=2)
                    except Exception as save_err:
                        logging.debug("Could not re-save filtered result file: %s", save_err)

                    # Collect emails, phones, and classification
                    email_set = set()
                    phone_set = set()
                    page_crypto_set = set()
                    for p in pages:
                        for contact in p.get("contacts", []):
                            val = contact.get("value")
                            if not val:
                                continue
                            if contact.get("source") == "mailto":
                                email_set.add(val)
                            elif contact.get("source") == "tel":
                                phone_set.add(val)
                        if not classification_label and p.get("classification"):
                            classification_label = p["classification"].get("label")

                        # Scan page body text for crypto addresses
                        page_text = p.get("content", {}).get("text", "")
                        if page_text:
                            for b in re.findall(r"\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,59})\b", page_text):
                                page_crypto_set.add(f"BTC: {b}")
                            for e in re.findall(r"\b(0x[a-fA-F0-9]{40})\b", page_text):
                                page_crypto_set.add(f"ETH: {e}")
                            for x in re.findall(r"\b(4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b", page_text):
                                page_crypto_set.add(f"XMR: {x}")

                    emails_found = sorted(email_set)
                    phones_found = sorted(phone_set)
                except Exception as exc:
                    logging.debug("Error reading crawl result file: %s", exc)

            # Parse security reconnaissance data from console output
            recon_data = parse_info_recon_from_stdout(output)
            all_crypto = set(recon_data.get("bitcoins", []))
            if 'page_crypto_set' in locals():
                all_crypto.update(page_crypto_set)
            btc_found = sorted(all_crypto)

            for itm in recon_data.get("intel", []):
                if "@" in itm and itm not in emails_found:
                    emails_found.append(itm)
            emails_found.sort()

            action_mode = action

            # If user requested AI Analyst Investigation
            if action == "analyze" and RESULT_FILE.exists() and RESULT_FILE.stat().st_size > 0:
                try:
                    analyst_cmd = [
                        python_exec,
                        str(script_path),
                        "analyze",
                        str(RESULT_FILE),
                        "--provider",
                        "none",
                        "--output",
                        str(INVESTIGATION_DIR),
                    ]
                    analyst_res = subprocess.run(
                        analyst_cmd, capture_output=True, text=True, timeout=60, cwd=str(REPO_DIR)
                    )
                    report_file = INVESTIGATION_DIR / "report.md"
                    if report_file.exists():
                        analyst_report = report_file.read_text(encoding="utf-8")
                    if analyst_res.stdout:
                        output += "\n--- AI Analyst Investigation Output ---\n" + analyst_res.stdout
                    if analyst_res.stderr:
                        output += "\n" + analyst_res.stderr
                except Exception as exc:
                    logging.debug("Error running analyst: %s", exc)

            if action == "tree":
                tree_output = extract_tree_from_stdout(output)
                if not tree_output and pages:
                    lines = [f"📂 {pages[0].get('title', 'Root')} ({pages[0].get('url', '')})"]
                    for p in pages[1:]:
                        lines.append(f"  └── 📄 {p.get('title', 'Page')} ({p.get('url', '')})")
                    tree_output = "\n".join(lines)

    ssl_notice = False
    if ".onion" in (target_url or "").lower():
        diag = crawl_data.get("diagnostics", {}) if 'crawl_data' in locals() else {}
        if diag.get("sslStatus") or any(p.get("unverifiedSsl") or (p.get("url") or "").startswith("https://") for p in pages):
            ssl_notice = True
        elif (target_url or "").startswith("https://"):
            ssl_notice = True

    return render_template_string(
        HTML_TEMPLATE,
        tor_online=tor_online,
        proxy_host=tor_host,
        proxy_port=tor_port,
        command_run=command_run,
        return_code=return_code,
        console_output=strip_ansi(output),
        raw_query=raw_query,
        target_url=target_url,
        total_pages=len(pages),
        pages=pages,
        url_stats=url_stats,
        emails_found=emails_found,
        phones_found=phones_found,
        btc_found=btc_found,
        classification_label=classification_label,
        recon_data=recon_data,
        json_pretty=json_pretty,
        analyst_report=analyst_report,
        tree_output=tree_output,
        action_mode=action_mode,
        result_available=result_available,
        ssl_notice=ssl_notice,
    )


@app.route("/api/tor-status")
def tor_status():
    """API endpoint to query real-time Tor daemon health and exit IP."""
    host = request.args.get("host", "127.0.0.1")
    try:
        port = int(request.args.get("port", "9050"))
    except ValueError:
        port = 9050

    net_info = get_tor_network_ip(host, port)
    return jsonify(net_info)


@app.route("/download/result")
def download_result():
    """Download the latest crawl result JSON file."""
    if RESULT_FILE.exists():
        return send_file(
            RESULT_FILE,
            as_attachment=True,
            download_name=f"torbot-crawl-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.json",
            mimetype="application/json",
        )
    return "No crawl result available for download.", 404


@app.route("/download/investigation")
def download_investigation():
    """Download the latest Analyst investigation markdown report."""
    report_file = INVESTIGATION_DIR / "report.md"
    if report_file.exists():
        return send_file(
            report_file,
            as_attachment=True,
            download_name="investigation-report.md",
            mimetype="text/markdown",
        )
    return "No investigation report available.", 404


def is_port_free(port: int, host: str = "127.0.0.1") -> bool:
    """Check if host:port can be bound by a server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


def free_port_if_in_use(port: int) -> bool:
    """Check if port is in use and attempt to terminate the occupying process."""
    if is_port_free(port):
        return True

    print(f"Port {port} is currently in use. Freeing port...")
    try:
        subprocess.run(["fuser", "-k", f"{port}/tcp"], capture_output=True, timeout=5)
        import time
        time.sleep(0.5)
    except Exception as e:
        logging.debug("Error releasing port %s: %s", port, e)

    return is_port_free(port)


def find_next_free_port(start_port: int = 5000, max_attempts: int = 20) -> int:
    """Find the next available port if start_port cannot be freed."""
    for p in range(start_port, start_port + max_attempts):
        if is_port_free(p):
            return p
    return start_port


if __name__ == "__main__":
    target_port = int(os.environ.get("PORT", 5000))
    if not free_port_if_in_use(target_port):
        target_port = find_next_free_port(target_port)
    print(f"Starting TorBot Web Interface on http://127.0.0.1:{target_port} ...")
    app.run(host="127.0.0.1", port=target_port, debug=False)