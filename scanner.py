#!/usr/bin/env python3
"""
ReconPilot — Automated Bug Bounty Vulnerability Scanner
=======================================================
A high-performance, modular recon → crawl → filter → scan pipeline
designed for bug bounty reconnaissance and vulnerability discovery.

Usage:
    python3 scanner.py example.com
    python3 scanner.py -l domains.txt
    python3 scanner.py example.com --threads 50 --rate-limit 100
    python3 scanner.py -l targets.txt --skip-subfinder --crawl-only
    python3 scanner.py example.com --resume --severity high,critical

Author: ReconPilot
License: MIT
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import logging
import os
import re
import signal
import subprocess
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

# ═══════════════════════════════════════════════════════════════════════════════
# ANSI COLOR CODES
# ═══════════════════════════════════════════════════════════════════════════════

class Colors:
    """ANSI escape codes for terminal colors."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BG_RED    = "\033[41m"
    BG_GREEN  = "\033[42m"
    BG_YELLOW = "\033[43m"


def cprint(msg: str, color: str = Colors.WHITE, bold: bool = False) -> None:
    """Print a colored message to stdout."""
    prefix = Colors.BOLD if bold else ""
    print(f"{prefix}{color}{msg}{Colors.RESET}")


def banner() -> None:
    """Display the scanner banner."""
    art = f"""
{Colors.CYAN}{Colors.BOLD}
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║   ██████╗ ██████╗ ███████╗   ██████╗ ██████╗ ███████╗  ║
    ║  ██╔════╝██╔═══██╗██╔════╝   ██╔══██╗██╔══██╗██╔════╝  ║
    ║  ██║     ██║   ██║███████╗   ██████╔╝██████╔╝█████╗    ║
    ║  ██║     ██║   ██║╚════██║   ██╔══██╗██╔══██╗██╔══╝    ║
    ║  ╚██████╗╚██████╔╝███████║   ██████╔╝██║  ██║███████╗  ║
    ║   ╚═════╝ ╚═════╝ ╚══════╝   ╚═════╝ ╚═╝  ╚═╝╚══════╝  ║
    ║              {Colors.YELLOW}Bug Bounty Scanner v1.0{Colors.CYAN}              ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
{Colors.RESET}"""
    print(art)


# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING SETUP
# ═══════════════════════════════════════════════════════════════════════════════

def setup_logging(output_dir: str) -> logging.Logger:
    """Configure structured JSON logging to file and console."""
    log_path = os.path.join(output_dir, "scanner.log")
    logger = logging.getLogger("reconpilot")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    # File handler — JSON format
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        '{"time":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}'
    ))
    logger.addHandler(fh)

    # Console handler — human-readable
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter(
        f"{Colors.DIM}%(asctime)s{Colors.RESET} {Colors.CYAN}%(levelname)-8s{Colors.RESET} %(message)s",
        datefmt="%H:%M:%S",
    ))
    logger.addHandler(ch)

    return logger


# ═══════════════════════════════════════════════════════════════════════════════
# GRACEFUL SHUTDOWN
# ═══════════════════════════════════════════════════════════════════════════════

class ShutdownHandler:
    """Handles graceful CTRL+C shutdown."""

    def __init__(self):
        self.shutdown_event = threading.Event()
        self.current_phase = "initialization"
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    def _handle_signal(self, signum, frame):
        cprint(
            f"\n[!] CTRL+C received during '{self.current_phase}'. "
            f"Gracefully shutting down...",
            Colors.YELLOW, bold=True,
        )
        self.shutdown_event.set()

    def should_stop(self) -> bool:
        return self.shutdown_event.is_set()

    def set_phase(self, phase: str):
        self.current_phase = phase


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

class ScannerConfig:
    """Central configuration for the scanner."""

    REQUIRED_TOOLS = ["subfinder", "httpx-toolkit", "nuclei"]
    OPTIONAL_TOOLS = ["assetfinder", "waybackurls", "gau", "katana", "dirsearch"]

    # Extensions to filter out as static files
    STATIC_EXTENSIONS = frozenset({
        ".css", ".js", ".jsx", ".ts", ".tsx", ".woff", ".woff2",
        ".ttf", ".eot", ".otf", ".svg", ".ico", ".png", ".jpg",
        ".jpeg", ".gif", ".bmp", ".webp", ".mp4", ".mp3", ".wav",
        ".avi", ".mov", ".flv", ".wmv", ".pdf", ".doc", ".docx",
        ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".tar", ".gz",
        ".rar", ".7z", ".bz2", ".dmg", ".iso", ".apk", ".ipa",
    })

    def __init__(self, args: argparse.Namespace):
        self.domains: List[str] = args.domains if hasattr(args, "domains") and args.domains else []
        self.domain_file: Optional[str] = args.list if hasattr(args, "list") else None
        self.threads: int = getattr(args, "threads", 50)
        self.rate_limit: int = getattr(args, "rate_limit", 150)
        self.timeout: int = getattr(args, "timeout", 30)
        self.resume: bool = getattr(args, "resume", False)
        self.skip_subfinder: bool = getattr(args, "skip_subfinder", False)
        self.crawl_only: bool = getattr(args, "crawl_only", False)
        self.severity: str = getattr(args, "severity", "low,medium,high,critical")
        self.concurrency: int = getattr(args, "concurrency", 25)
        self.output_dir: str = getattr(args, "output", "output")
        self.telegram_bot_token: Optional[str] = os.environ.get("TELEGRAM_BOT_TOKEN")
        self.telegram_chat_id: Optional[str] = os.environ.get("TELEGRAM_CHAT_ID")
        self.custom_tool_paths: Dict[str, str] = {}
        if hasattr(args, "tool_paths") and args.tool_paths:
            for entry in args.tool_paths:
                if "=" in entry:
                    tool, path = entry.split("=", 1)
                    self.custom_tool_paths[tool.strip()] = path.strip()

        # Resolve tool paths
        self._tool_paths: Dict[str, str] = {}
        self._resolve_tool_paths()

    def _resolve_tool_paths(self):
        """Resolve binary paths for all tools."""
        all_tools = self.REQUIRED_TOOLS + self.OPTIONAL_TOOLS
        for tool in all_tools:
            if tool in self.custom_tool_paths:
                self._tool_paths[tool] = self.custom_tool_paths[tool]
            else:
                self._tool_paths[tool] = self._find_binary(tool)

    @staticmethod
    def _find_binary(name: str) -> Optional[str]:
        """Find a binary in PATH."""
        try:
            result = subprocess.run(
                ["which", name], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        # Fallback common locations
        common = [f"/usr/bin/{name}", f"/usr/local/bin/{name}", f"/opt/{name}/{name}"]
        for p in common:
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p
        return None

    def get_tool(self, name: str) -> Optional[str]:
        return self._tool_paths.get(name)


# ═══════════════════════════════════════════════════════════════════════════════
# DEPENDENCY CHECKING
# ═══════════════════════════════════════════════════════════════════════════════

def check_dependencies(config: ScannerConfig, logger: logging.Logger) -> bool:
    """Verify all required and optional tools are installed."""
    cprint("\n[*] Checking dependencies...", Colors.CYAN, bold=True)
    all_ok = True

    cprint("  Required tools:", Colors.WHITE)
    for tool in config.REQUIRED_TOOLS:
        path = config.get_tool(tool)
        if path:
            cprint(f"    {Colors.GREEN}✓{Colors.RESET} {tool:20s} → {path}")
            logger.debug(f"Dependency OK: {tool} at {path}")
        else:
            cprint(f"    {Colors.RED}✗{Colors.RESET} {tool:20s} → NOT FOUND", bold=True)
            logger.error(f"Missing required tool: {tool}")
            all_ok = False

    cprint("  Optional tools:", Colors.WHITE)
    for tool in config.OPTIONAL_TOOLS:
        path = config.get_tool(tool)
        if path:
            cprint(f"    {Colors.GREEN}✓{Colors.RESET} {tool:20s} → {path}")
            logger.debug(f"Optional tool OK: {tool} at {path}")
        else:
            cprint(f"    {Colors.YELLOW}!{Colors.RESET} {tool:20s} → NOT FOUND (optional)")
            logger.warning(f"Optional tool not found: {tool}")

    if not all_ok:
        cprint("\n[!] Missing required dependencies. Install them first.", Colors.RED, bold=True)
        cprint("    sudo apt install subfinder httpx-toolkit nuclei", Colors.YELLOW)
        return False

    cprint(f"\n  {Colors.GREEN}All required dependencies satisfied.{Colors.RESET}")
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# INPUT HANDLING & DOMAIN NORMALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

def normalize_domain(domain: str) -> str:
    """Normalize a domain: lowercase, strip protocol/path, remove trailing dot."""
    domain = domain.strip().lower()
    # Remove protocol
    domain = re.sub(r'^https?://', '', domain)
    # Remove path
    domain = domain.split('/')[0]
    # Remove port
    domain = domain.split(':')[0]
    # Remove trailing dot
    domain = domain.rstrip('.')
    return domain


def load_domains(config: ScannerConfig, logger: logging.Logger) -> List[str]:
    """Load domains from CLI args or file, normalize and deduplicate."""
    domains: Set[str] = set()

    if config.domains:
        for d in config.domains:
            nd = normalize_domain(d)
            if nd:
                domains.add(nd)
                logger.info(f"Domain from CLI: {nd}")

    if config.domain_file:
        fpath = Path(config.domain_file)
        if not fpath.is_file():
            cprint(f"[!] Domain file not found: {config.domain_file}", Colors.RED, bold=True)
            sys.exit(1)
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    nd = normalize_domain(line)
                    if nd:
                        domains.add(nd)
        logger.info(f"Loaded domains from file: {config.domain_file}")

    result = sorted(domains)
    logger.info(f"Total unique domains after normalization: {len(result)}")
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUT DIRECTORY SETUP
# ═══════════════════════════════════════════════════════════════════════════════

def setup_output_dirs(domains: List[str], base_output: str) -> Dict[str, Dict[str, str]]:
    """Create structured output directories for each domain."""
    dirs: Dict[str, Dict[str, str]] = {}
    for domain in domains:
        domain_dir = os.path.join(base_output, domain)
        os.makedirs(domain_dir, exist_ok=True)
        dirs[domain] = {
            "root": domain_dir,
            "subdomains": os.path.join(domain_dir, "subdomains.txt"),
            "alive": os.path.join(domain_dir, "alive_subdomains.txt"),
            "all_urls": os.path.join(domain_dir, "all_urls.txt"),
            "filtered_urls": os.path.join(domain_dir, "filtered_urls.txt"),
            "params": os.path.join(domain_dir, "params.txt"),
            "alive_params": os.path.join(domain_dir, "alive_params.txt"),
            "findings_json": os.path.join(domain_dir, "findings.json"),
            "findings_txt": os.path.join(domain_dir, "findings.txt"),
            "findings_csv": os.path.join(domain_dir, "findings.csv"),
            "resume": os.path.join(domain_dir, ".resume_state.json"),
        }
    return dirs


# ═══════════════════════════════════════════════════════════════════════════════
# FILE I/O UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def read_lines(filepath: str) -> List[str]:
    """Read non-empty lines from a file (memory-efficient generator internally)."""
    if not os.path.isfile(filepath):
        return []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]


def write_lines(filepath: str, lines: List[str], mode: str = 'w') -> int:
    """Write lines to a file, returning the count written."""
    with open(filepath, mode, encoding='utf-8') as f:
        for line in lines:
            f.write(line + '\n')
    return len(lines)


def append_lines(filepath: str, lines: List[str]) -> int:
    """Append lines to a file."""
    return write_lines(filepath, lines, mode='a')


def merge_unique_files(output_path: str, *input_paths: str) -> int:
    """Merge multiple files, deduplicate, write to output. Returns unique count."""
    seen: Set[str] = set()
    for ip in input_paths:
        if os.path.isfile(ip):
            with open(ip, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    s = line.strip()
                    if s and s not in seen:
                        seen.add(s)
    write_lines(output_path, sorted(seen))
    return len(seen)


def file_line_count(filepath: str) -> int:
    """Count lines in a file efficiently."""
    if not os.path.isfile(filepath):
        return 0
    count = 0
    with open(filepath, 'rb') as f:
        for _ in f:
            count += 1
    return count


# ═══════════════════════════════════════════════════════════════════════════════
# RESUME STATE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

class ResumeState:
    """Manages resume state for each domain."""

    def __init__(self, state_path: str):
        self.state_path = state_path
        self.state: Dict[str, bool] = {}
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        if os.path.isfile(self.state_path):
            try:
                with open(self.state_path, 'r') as f:
                    self.state = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.state = {}

    def _save(self):
        with open(self.state_path, 'w') as f:
            json.dump(self.state, f, indent=2)

    def is_complete(self, phase: str) -> bool:
        return self.state.get(phase, False)

    def mark_complete(self, phase: str):
        with self._lock:
            self.state[phase] = True
            self._save()

    def reset(self):
        self.state = {}
        self._save()


# ═══════════════════════════════════════════════════════════════════════════════
# SUBPROCESS RUNNER
# ═══════════════════════════════════════════════════════════════════════════════

def run_tool(
    cmd: List[str],
    logger: logging.Logger,
    timeout: int = 300,
    cwd: Optional[str] = None,
) -> Tuple[int, str, str]:
    """
    Run an external tool with timeout protection.
    Returns (returncode, stdout, stderr).
    """
    cmd_str = ' '.join(cmd)
    logger.debug(f"Running: {cmd_str}")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            return (
                proc.returncode,
                stdout.decode('utf-8', errors='ignore'),
                stderr.decode('utf-8', errors='ignore'),
            )
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            logger.error(f"Tool timed out after {timeout}s: {cmd[0]}")
            return (-1, "", f"Timeout after {timeout}s")
    except FileNotFoundError:
        logger.error(f"Tool not found: {cmd[0]}")
        return (-1, "", f"Tool not found: {cmd[0]}")
    except Exception as e:
        logger.error(f"Error running {cmd[0]}: {e}")
        return (-1, "", str(e))


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2 — SUBDOMAIN ENUMERATION
# ═══════════════════════════════════════════════════════════════════════════════

def run_subfinder(
    domain: str,
    output_file: str,
    config: ScannerConfig,
    logger: logging.Logger,
) -> List[str]:
    """Run subfinder for subdomain enumeration."""
    tool = config.get_tool("subfinder")
    if not tool:
        logger.error("subfinder not available")
        return []

    cprint(f"  [→] Running subfinder on {domain}...", Colors.BLUE)
    cmd = [
        tool, "-d", domain,
        "-silent",
        "-o", output_file,
        "-timeout", str(config.timeout),
        "-rate-limit", str(config.rate_limit),
    ]

    rc, stdout, stderr = run_tool(cmd, logger, timeout=300)
    if rc != 0 and not os.path.isfile(output_file):
        logger.error(f"subfinder failed for {domain}: {stderr}")
        return []

    subdomains = read_lines(output_file)
    # Deduplicate in memory (subfinder may occasionally output dupes)
    subdomains = sorted(set(subdomains))
    write_lines(output_file, subdomains)

    cprint(f"  {Colors.GREEN}✓{Colors.RESET} subfinder: {len(subdomains)} subdomains", Colors.GREEN)
    logger.info(f"Subfinder found {len(subdomains)} subdomains for {domain}")
    return subdomains


def run_assetfinder(
    domain: str,
    output_file: str,
    config: ScannerConfig,
    logger: logging.Logger,
) -> List[str]:
    """Run assetfinder (optional) and merge with existing results."""
    tool = config.get_tool("assetfinder")
    if not tool:
        logger.debug("assetfinder not available, skipping")
        return []

    cprint(f"  [→] Running assetfinder on {domain}...", Colors.BLUE)
    tmp_file = output_file + ".assetfinder.tmp"

    cmd = [tool, "--subs-only", domain]
    rc, stdout, stderr = run_tool(cmd, logger, timeout=300)

    if rc != 0 or not stdout:
        logger.warning(f"assetfinder failed or empty for {domain}")
        return []

    asset_subs = [s.strip() for s in stdout.splitlines() if s.strip()]
    write_lines(tmp_file, asset_subs)

    # Merge with existing subdomains
    existing = read_lines(output_file)
    merged = sorted(set(existing + asset_subs))
    write_lines(output_file, merged)

    # Cleanup temp
    if os.path.exists(tmp_file):
        os.remove(tmp_file)

    new_count = len(merged) - len(existing)
    cprint(f"  {Colors.GREEN}✓{Colors.RESET} assetfinder: {len(asset_subs)} subs ({new_count} new)", Colors.GREEN)
    logger.info(f"Assetfinder found {new_count} new subdomains for {domain}")
    return merged


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3 — LIVE HOST DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

def run_httpx(
    input_file: str,
    output_file: str,
    config: ScannerConfig,
    logger: logging.Logger,
    extra_args: Optional[List[str]] = None,
) -> List[str]:
    """Run httpx-toolkit to detect live hosts."""
    tool = config.get_tool("httpx-toolkit")
    if not tool:
        logger.error("httpx-toolkit not available")
        return []

    if not os.path.isfile(input_file) or file_line_count(input_file) == 0:
        logger.warning(f"Empty or missing input file for httpx: {input_file}")
        return []

    cprint(f"  [→] Running httpx on {os.path.basename(input_file)}...", Colors.BLUE)

    cmd = [
        tool,
        "-l", input_file,
        "-silent",
        "-o", output_file,
        "-follow-redirects",
        "-status-code",
        "-title",
        "-tech-detect",
        "-threads", str(config.threads),
        "-rate-limit", str(config.rate_limit),
        "-timeout", str(config.timeout),
    ]
    if extra_args:
        cmd.extend(extra_args)

    rc, stdout, stderr = run_tool(cmd, logger, timeout=600)
    if rc != 0 and not os.path.isfile(output_file):
        logger.error(f"httpx failed: {stderr}")
        return []

    alive = read_lines(output_file)
    alive = sorted(set(alive))
    write_lines(output_file, alive)

    cprint(f"  {Colors.GREEN}✓{Colors.RESET} httpx: {len(alive)} live hosts", Colors.GREEN)
    logger.info(f"HTTPX found {len(alive)} live hosts")
    return alive


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 4 — URL COLLECTION
# ═══════════════════════════════════════════════════════════════════════════════

def run_waybackurls(
    domain: str,
    output_file: str,
    config: ScannerConfig,
    logger: logging.Logger,
) -> List[str]:
    """Collect URLs from Wayback Machine."""
    tool = config.get_tool("waybackurls")
    if not tool:
        logger.debug("waybackurls not available, skipping")
        return []

    cprint(f"  [→] Running waybackurls on {domain}...", Colors.BLUE)
    cmd = [tool, domain]

    rc, stdout, stderr = run_tool(cmd, logger, timeout=300)
    if rc != 0 or not stdout:
        logger.warning(f"waybackurls failed for {domain}")
        return []

    urls = sorted(set(s.strip() for s in stdout.splitlines() if s.strip()))
    write_lines(output_file, urls)

    cprint(f"  {Colors.GREEN}✓{Colors.RESET} waybackurls: {len(urls)} URLs", Colors.GREEN)
    logger.info(f"Waybackurls collected {len(urls)} URLs for {domain}")
    return urls


def run_gau(
    domain: str,
    output_file: str,
    config: ScannerConfig,
    logger: logging.Logger,
) -> List[str]:
    """Collect URLs using gau (getallurls)."""
    tool = config.get_tool("gau")
    if not tool:
        logger.debug("gau not available, skipping")
        return []

    cprint(f"  [→] Running gau on {domain}...", Colors.BLUE)
    cmd = [tool, "--subs", domain]

    rc, stdout, stderr = run_tool(cmd, logger, timeout=300)
    if rc != 0 or not stdout:
        logger.warning(f"gau failed for {domain}")
        return []

    urls = sorted(set(s.strip() for s in stdout.splitlines() if s.strip()))
    write_lines(output_file, urls)

    cprint(f"  {Colors.GREEN}✓{Colors.RESET} gau: {len(urls)} URLs", Colors.GREEN)
    logger.info(f"GAU collected {len(urls)} URLs for {domain}")
    return urls


def run_katana(
    domain: str,
    output_file: str,
    config: ScannerConfig,
    logger: logging.Logger,
) -> List[str]:
    """Crawl URLs using katana."""
    tool = config.get_tool("katana")
    if not tool:
        logger.debug("katana not available, skipping")
        return []

    cprint(f"  [→] Running katana on {domain}...", Colors.BLUE)
    cmd = [
        tool,
        "-u", f"https://{domain}",
        "-d", "3",
        "-aff",
        "-jc",
        "-o", output_file,
        "-silent",
        "-depth", "3",
        "-c", str(min(config.threads, 50)),
        "-rl", str(config.rate_limit),
        "-timeout", str(config.timeout),
    ]

    rc, stdout, stderr = run_tool(cmd, logger, timeout=600)
    if rc != 0 and not os.path.isfile(output_file):
        logger.warning(f"katana failed for {domain}: {stderr}")
        return []

    urls = read_lines(output_file)
    urls = sorted(set(urls))
    write_lines(output_file, urls)

    cprint(f"  {Colors.GREEN}✓{Colors.RESET} katana: {len(urls)} URLs", Colors.GREEN)
    logger.info(f"Katana crawled {len(urls)} URLs for {domain}")
    return urls


def collect_urls(
    domain: str,
    all_urls_file: str,
    config: ScannerConfig,
    logger: logging.Logger,
) -> List[str]:
    """Run all URL collection tools in parallel and merge results."""
    cprint(f"\n  {Colors.MAGENTA}▶ PHASE 4: URL Collection for {domain}{Colors.RESET}", Colors.MAGENTA, bold=True)

    temp_files: List[str] = []

    # Run all URL collectors in parallel using threads
    def _run_collector(name: str, func, *args) -> Tuple[str, List[str]]:
        tmp = all_urls_file + f".{name}.tmp"
        temp_files.append(tmp)
        result = func(*args, tmp, config, logger)
        return name, result

    collectors = []
    collectors.append(("waybackurls", run_waybackurls, domain))
    collectors.append(("gau", run_gau, domain))
    collectors.append(("katana", run_katana, domain))

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(_run_collector, name, func, *args): name
            for name, func, *args in [
                ("waybackurls", run_waybackurls, domain),
                ("gau", run_gau, domain),
                ("katana", run_katana, domain),
            ]
        }
        for future in as_completed(futures):
            try:
                name, result = future.result()
                logger.debug(f"Collector {name} returned {len(result)} URLs")
            except Exception as e:
                logger.error(f"Collector error: {e}")

    # Merge all collected URLs
    existing_files = [f for f in temp_files if os.path.isfile(f)]
    total = merge_unique_files(all_urls_file, *existing_files)

    # Cleanup temp files
    for f in temp_files:
        if os.path.exists(f):
            os.remove(f)

    cprint(f"  {Colors.GREEN}✓{Colors.RESET} Total unique URLs collected: {total}", Colors.GREEN)
    logger.info(f"Merged {total} unique URLs for {domain}")
    return read_lines(all_urls_file)


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 5 — DIRECTORY DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════════

def run_dirsearch(
    domain: str,
    alive_hosts: List[str],
    all_urls_file: str,
    config: ScannerConfig,
    logger: logging.Logger,
) -> List[str]:
    """Run dirsearch against alive hosts and append paths to URL list."""
    tool = config.get_tool("dirsearch")
    if not tool:
        logger.debug("dirsearch not available, skipping")
        return []

    cprint(f"\n  {Colors.MAGENTA}▶ PHASE 5: Directory Discovery for {domain}{Colors.RESET}", Colors.MAGENTA, bold=True)

    existing_urls = read_lines(all_urls_file)
    existing_count = len(existing_urls)

    # Limit dirsearch targets to avoid excessive runtime
    targets = alive_hosts[:50] if len(alive_hosts) > 50 else alive_hosts
    targets_file = all_urls_file + ".dirsearch_targets.tmp"
    write_lines(targets_file, [f"https://{h}" if not h.startswith("http") else h for h in targets])

    output_file = all_urls_file + ".dirsearch.tmp"
    cmd = [
        tool,
        "-l", targets_file,
        "-o", output_file,
        "--format=plain",
        "-t", str(min(config.threads, 30)),
        "--timeout", str(config.timeout),
        "--no-color",
        "-q",  # quiet
    ]

    cprint(f"  [→] Running dirsearch on {len(targets)} hosts...", Colors.BLUE)
    rc, stdout, stderr = run_tool(cmd, logger, timeout=600)

    new_urls: List[str] = []
    if os.path.isfile(output_file):
        # dirsearch plain output format: URL [STATUS_CODE]
        with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # Extract URL from dirsearch output
                match = re.match(r'(https?://\S+)', line)
                if match:
                    url = match.group(1).rstrip('[]')
                    if url not in existing_urls:
                        new_urls.append(url)

    if new_urls:
        append_lines(all_urls_file, new_urls)

    # Cleanup
    for f in [targets_file, output_file]:
        if os.path.exists(f):
            os.remove(f)

    cprint(f"  {Colors.GREEN}✓{Colors.RESET} dirsearch: {len(new_urls)} new paths discovered", Colors.GREEN)
    logger.info(f"Dirsearch found {len(new_urls)} new URLs for {domain}")
    return read_lines(all_urls_file)


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 6 — URL FILTERING
# ═══════════════════════════════════════════════════════════════════════════════

def is_static_url(url: str) -> bool:
    """Check if a URL points to a static file."""
    parsed = urlparse(url)
    path = parsed.path.lower()
    for ext in ScannerConfig.STATIC_EXTENSIONS:
        if path.endswith(ext):
            return True
    return False


def is_in_scope(url: str, scope_domains: Set[str]) -> bool:
    """Check if a URL belongs to in-scope domains."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    for domain in scope_domains:
        if hostname == domain or hostname.endswith(f".{domain}"):
            return True
    return False


def filter_urls(
    all_urls_file: str,
    filtered_file: str,
    scope_domains: Set[str],
    logger: logging.Logger,
) -> List[str]:
    """Filter URLs: keep in-scope, unique, non-static."""
    cprint(f"\n  {Colors.MAGENTA}▶ PHASE 6: URL Filtering{Colors.RESET}", Colors.MAGENTA, bold=True)

    total = 0
    filtered: List[str] = []
    removed_static = 0
    removed_oos = 0

    if not os.path.isfile(all_urls_file):
        logger.warning(f"No URLs file to filter: {all_urls_file}")
        write_lines(filtered_file, [])
        return []

    with open(all_urls_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            url = line.strip()
            if not url:
                continue
            total += 1

            if is_static_url(url):
                removed_static += 1
                continue

            if not is_in_scope(url, scope_domains):
                removed_oos += 1
                continue

            if url not in filtered:
                filtered.append(url)

    write_lines(filtered_file, filtered)

    cprint(f"  {Colors.GREEN}✓{Colors.RESET} Filtered: {len(filtered)} / {total} URLs kept", Colors.GREEN)
    cprint(f"    Removed {removed_static} static files, {removed_oos} out-of-scope", Colors.DIM)
    logger.info(
        f"URL filtering: {len(filtered)}/{total} kept "
        f"(static={removed_static}, oos={removed_oos})"
    )
    return filtered


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 7 — PARAMETER EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════════

def extract_params(
    filtered_file: str,
    params_file: str,
    logger: logging.Logger,
) -> List[str]:
    """Extract URLs containing query parameters."""
    cprint(f"\n  {Colors.MAGENTA}▶ PHASE 7: Parameter Extraction{Colors.RESET}", Colors.MAGENTA, bold=True)

    param_urls: List[str] = []
    total = 0

    if not os.path.isfile(filtered_file):
        logger.warning(f"No filtered URLs file: {filtered_file}")
        write_lines(params_file, [])
        return []

    with open(filtered_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            url = line.strip()
            if not url:
                continue
            total += 1
            parsed = urlparse(url)
            if parsed.query:
                # Normalize: keep URL path + query, remove fragment
                clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{parsed.query}"
                if clean not in param_urls:
                    param_urls.append(clean)

    write_lines(params_file, param_urls)

    cprint(
        f"  {Colors.GREEN}✓{Colors.RESET} Extracted {len(param_urls)} URLs with parameters "
        f"(from {total} filtered URLs)",
        Colors.GREEN,
    )
    logger.info(f"Parameter extraction: {len(param_urls)}/{total} URLs have parameters")
    return param_urls


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 8 — VERIFY ALIVE PARAM URLS
# ═══════════════════════════════════════════════════════════════════════════════

def verify_alive_params(
    params_file: str,
    alive_params_file: str,
    config: ScannerConfig,
    logger: logging.Logger,
) -> List[str]:
    """Re-check parameter URLs with httpx to confirm they're alive."""
    cprint(f"\n  {Colors.MAGENTA}▶ PHASE 8: Verifying Alive Parameter URLs{Colors.RESET}", Colors.MAGENTA, bold=True)

    return run_httpx(
        params_file,
        alive_params_file,
        config,
        logger,
        extra_args=["-mr", "-mc", "200,301,302,403,500"],
    )


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 9 — VULNERABILITY SCANNING
# ═══════════════════════════════════════════════════════════════════════════════

def run_nuclei_scan(
    input_file: str,
    output_dir: str,
    config: ScannerConfig,
    logger: logging.Logger,
) -> Dict:
    """Run Nuclei vulnerability scanner on parameter URLs."""
    tool = config.get_tool("nuclei")
    if not tool:
        logger.error("nuclei not available")
        return {}

    cprint(f"\n  {Colors.MAGENTA}▶ PHASE 9: Vulnerability Scanning (Nuclei){Colors.RESET}", Colors.MAGENTA, bold=True)

    if not os.path.isfile(input_file) or file_line_count(input_file) == 0:
        logger.warning(f"No parameter URLs to scan: {input_file}")
        cprint(f"  {Colors.YELLOW}!{Colors.RESET} No URLs to scan", Colors.YELLOW)
        return {}

    base_name = os.path.splitext(os.path.basename(input_file))[0]
    json_out = os.path.join(output_dir, f"nuclei_{base_name}.json")
    txt_out = os.path.join(output_dir, f"nuclei_{base_name}.txt")
    csv_out = os.path.join(output_dir, f"nuclei_{base_name}.csv")

    # Build severity flags
    severities = config.severity.split(",")
    sev_flags = []
    for s in severities:
        sev_flags.extend(["-severity", s.strip()])

    cmd = [
        tool,
        "-l", input_file,
        "-json",
        "-o", json_out,
        "-silent",
        "-c", str(config.concurrency),
        "-rl", str(config.rate_limit),
        "-timeout", str(config.timeout),
        "-retries", "1",
        "-no-color",
    ] + sev_flags

    cprint(f"  [→] Running Nuclei (severity: {config.severity})...", Colors.BLUE)
    rc, stdout, stderr = run_tool(cmd, logger, timeout=1800)  # 30 min max

    findings: List[Dict] = []
    if os.path.isfile(json_out):
        with open(json_out, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

    # Generate TXT output
    txt_lines = []
    for finding in findings:
        template = finding.get("template-id", "unknown")
        name = finding.get("info", {}).get("name", "unknown")
        severity = finding.get("info", {}).get("severity", "unknown")
        host = finding.get("host", "")
        matched = finding.get("matched-at", "")
        txt_lines.append(f"[{severity.upper()}] {template} - {name}")
        txt_lines.append(f"  Host: {host}")
        txt_lines.append(f"  Matched: {matched}")
        txt_lines.append("")

    write_lines(txt_out, txt_lines)

    # Generate CSV output
    csv_lines = ["template_id,name,severity,host,matched_at,type"]
    for finding in findings:
        template = finding.get("template-id", "")
        name = finding.get("info", {}).get("name", "").replace(",", ";")
        severity = finding.get("info", {}).get("severity", "")
        host = finding.get("host", "").replace(",", ";")
        matched = finding.get("matched-at", "").replace(",", ";")
        ftype = finding.get("type", "")
        csv_lines.append(f'"{template}","{name}","{severity}","{host}","{matched}","{ftype}"')
    write_lines(csv_out, csv_lines)

    # Severity summary
    severity_counts = Counter(f.get("info", {}).get("severity", "unknown") for f in findings)

    cprint(f"\n  {Colors.BOLD}═══ Nuclei Scan Results ═══{Colors.RESET}")
    if findings:
        sev_colors = {
            "critical": Colors.RED,
            "high": Colors.RED,
            "medium": Colors.YELLOW,
            "low": Colors.BLUE,
            "info": Colors.DIM,
        }
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                color = sev_colors.get(sev, Colors.WHITE)
                cprint(f"    {color}●{Colors.RESET} {sev.upper():10s}: {count}", color)
        cprint(f"    {Colors.WHITE}{'TOTAL':10s}: {len(findings)}{Colors.RESET}", Colors.WHITE, bold=True)
    else:
        cprint("    No vulnerabilities found.", Colors.DIM)

    cprint(f"  Results saved to: {output_dir}", Colors.DIM)

    logger.info(
        f"Nuclei scan complete: {len(findings)} findings "
        f"(severity breakdown: {dict(severity_counts)})"
    )

    return {
        "findings": findings,
        "severity_summary": dict(severity_counts),
        "total": len(findings),
    }


def save_results(
    scan_results: Dict[str, Dict],
    output_paths: Dict[str, str],
    logger: logging.Logger,
) -> None:
    """Compile final results into structured JSON and TXT reports."""
    cprint(f"\n  {Colors.MAGENTA}▶ PHASE 10: Saving Results{Colors.RESET}", Colors.MAGENTA, bold=True)

    # Build comprehensive findings
    all_findings: List[Dict] = []
    total_summary: Dict[str, int] = {}

    for domain, result in scan_results.items():
        if result.get("findings"):
            for f in result["findings"]:
                f["_domain"] = domain
            all_findings.extend(result["findings"])
        for sev, count in result.get("severity_summary", {}).items():
            total_summary[sev] = total_summary.get(sev, 0) + count

    # Write JSON
    json_output = {
        "scan_time": datetime.now().isoformat(),
        "total_findings": len(all_findings),
        "severity_summary": total_summary,
        "domains_scanned": list(scan_results.keys()),
        "findings": all_findings,
    }

    # Per-domain output
    for domain, paths in output_paths.items():
        domain_findings = [f for f in all_findings if f.get("_domain") == domain]
        domain_json = {
            "scan_time": datetime.now().isoformat(),
            "domain": domain,
            "total_findings": len(domain_findings),
            "severity_summary": scan_results.get(domain, {}).get("severity_summary", {}),
            "findings": domain_findings,
        }
        with open(paths["findings_json"], 'w', encoding='utf-8') as f:
            json.dump(domain_json, f, indent=2, ensure_ascii=False)

        # TXT report
        txt_lines = [
            f"{'='*60}",
            f"  ReconPilot Scan Report — {domain}",
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"{'='*60}",
            "",
            f"Total Findings: {len(domain_findings)}",
            "",
        ]
        if total_summary:
            txt_lines.append("Severity Breakdown:")
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = total_summary.get(sev, 0)
                if count > 0:
                    txt_lines.append(f"  - {sev.upper()}: {count}")
            txt_lines.append("")

        for i, finding in enumerate(domain_findings, 1):
            info = finding.get("info", {})
            txt_lines.extend([
                f"--- Finding #{i} ---",
                f"  Template: {finding.get('template-id', 'N/A')}",
                f"  Name: {info.get('name', 'N/A')}",
                f"  Severity: {info.get('severity', 'N/A')}",
                f"  Host: {finding.get('host', 'N/A')}",
                f"  Matched At: {finding.get('matched-at', 'N/A')}",
                f"  Type: {finding.get('type', 'N/A')}",
                "",
            ])

        write_lines(paths["findings_txt"], txt_lines)

        # CSV report
        csv_lines = [
            "finding_id,template_id,name,severity,host,matched_at,type,description"
        ]
        for i, finding in enumerate(domain_findings, 1):
            info = finding.get("info", {})
            desc = info.get("description", "").replace('"', '""').replace("\n", " ")[:200]
            csv_lines.append(
                f'{i},"{finding.get("template-id", "")}",'
                f'"{info.get("name", "")}",'
                f'"{info.get("severity", "")}",'
                f'"{finding.get("host", "")}",'
                f'"{finding.get("matched-at", "")}",'
                f'"{finding.get("type", "")}",'
                f'"{desc}"'
            )
        write_lines(paths["findings_csv"], csv_lines)

    cprint(f"  {Colors.GREEN}✓{Colors.RESET} Results saved for {len(scan_results)} domain(s)", Colors.GREEN)
    logger.info(f"Final results saved: {len(all_findings)} total findings")


# ═══════════════════════════════════════════════════════════════════════════════
# TELEGRAM NOTIFICATIONS
# ═══════════════════════════════════════════════════════════════════════════════

def send_telegram_notification(
    message: str,
    config: ScannerConfig,
    logger: logging.Logger,
) -> None:
    """Send a Telegram notification with scan summary."""
    if not config.telegram_bot_token or not config.telegram_chat_id:
        logger.debug("Telegram credentials not configured, skipping notification")
        return

    try:
        import urllib.request
        import urllib.parse

        url = f"https://api.telegram.org/bot{config.telegram_bot_token}/sendMessage"
        payload = urllib.parse.urlencode({
            "chat_id": config.telegram_chat_id,
            "text": message,
            "parse_mode": "HTML",
        }).encode('utf-8')

        req = urllib.request.Request(url, data=payload)
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                logger.info("Telegram notification sent successfully")
            else:
                logger.warning(f"Telegram notification failed: HTTP {resp.status}")
    except Exception as e:
        logger.error(f"Telegram notification error: {e}")


def build_notification_message(
    domain: str,
    findings: Dict,
) -> str:
    """Build a Telegram notification message from scan results."""
    total = findings.get("total", 0)
    summary = findings.get("severity_summary", {})

    msg = (
        f"<b>🔍 ReconPilot Scan Complete</b>\n\n"
        f"<b>Target:</b> <code>{domain}</code>\n"
        f"<b>Total Findings:</b> {total}\n\n"
    )

    if summary:
        msg += "<b>Severity Breakdown:</b>\n"
        sev_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
        for sev, count in sorted(summary.items(), key=lambda x: ["critical", "high", "medium", "low", "info"].index(x[0]) if x[0] in ["critical", "high", "medium", "low", "info"] else 99):
            icon = sev_icons.get(sev, "⚪")
            msg += f"  {icon} {sev.upper()}: {count}\n"

    msg += f"\n<i>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>"
    return msg


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN SCANNER ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

def scan_domain(
    domain: str,
    paths: Dict[str, str],
    config: ScannerConfig,
    resume: ResumeState,
    shutdown: ShutdownHandler,
    logger: logging.Logger,
) -> Dict:
    """Execute the full scanning pipeline for a single domain."""
    results: Dict = {"findings": [], "severity_summary": {}, "total": 0}
    scope_domains = {domain}

    def _phase(n: int, name: str) -> str:
        return f"phase_{n}_{name}"

    # ── PHASE 2: Subdomain Enumeration ───────────────────────────────────
    shutdown.set_phase(f"subdomain enumeration ({domain})")
    if config.skip_subfinder:
        cprint(f"\n  {Colors.YELLOW}⊘{Colors.RESET} Skipping subdomain enumeration (--skip-subfinder)", Colors.YELLOW)
    elif config.resume and resume.is_complete(_phase(2, "subdomains")):
        cprint(f"\n  {Colors.YELLOW}⊘{Colors.RESET} Phase 2 already completed, resuming...", Colors.YELLOW)
    else:
        cprint(f"\n{Colors.BOLD}{'═'*60}", Colors.CYAN)
        cprint(f"  TARGET: {domain}", Colors.CYAN, bold=True)
        cprint(f"  PHASE 2: Subdomain Enumeration", Colors.CYAN, bold=True)
        cprint(f"{'═'*60}{Colors.RESET}", Colors.CYAN)

        subdomains = run_subfinder(domain, paths["subdomains"], config, logger)
        subdomains = run_assetfinder(domain, paths["subdomains"], config, logger)

        if subdomains:
            # Add the root domain if not present
            if domain not in subdomains:
                subdomains.insert(0, domain)
                write_lines(paths["subdomains"], subdomains)
            # Update scope for filtering
            for sub in subdomains:
                scope_domains.add(normalize_domain(sub))

        resume.mark_complete(_phase(2, "subdomains"))

    # ── PHASE 3: Live Host Detection ─────────────────────────────────────
    if shutdown.should_stop():
        return results

    shutdown.set_phase(f"live host detection ({domain})")
    if config.resume and resume.is_complete(_phase(3, "alive")):
        cprint(f"\n  {Colors.YELLOW}⊘{Colors.RESET} Phase 3 already completed, resuming...", Colors.YELLOW)
    else:
        cprint(f"\n  {Colors.MAGENTA}▶ PHASE 3: Live Host Detection{Colors.RESET}", Colors.MAGENTA, bold=True)
        alive = run_httpx(paths["subdomains"], paths["alive"], config, logger)
        resume.mark_complete(_phase(3, "alive"))

    # ── PHASE 4: URL Collection ──────────────────────────────────────────
    if shutdown.should_stop():
        return results

    shutdown.set_phase(f"URL collection ({domain})")
    if config.resume and resume.is_complete(_phase(4, "urls")):
        cprint(f"\n  {Colors.YELLOW}⊘{Colors.RESET} Phase 4 already completed, resuming...", Colors.YELLOW)
    else:
        all_urls = collect_urls(domain, paths["all_urls"], config, logger)
        resume.mark_complete(_phase(4, "urls"))

    # ── PHASE 5: Directory Discovery ─────────────────────────────────────
    if shutdown.should_stop():
        return results

    shutdown.set_phase(f"directory discovery ({domain})")
    if config.resume and resume.is_complete(_phase(5, "dirsearch")):
        cprint(f"\n  {Colors.YELLOW}⊘{Colors.RESET} Phase 5 already completed, resuming...", Colors.YELLOW)
    else:
        alive_hosts = read_lines(paths["alive"])
        all_urls = run_dirsearch(domain, alive_hosts, paths["all_urls"], config, logger)
        resume.mark_complete(_phase(5, "dirsearch"))

    # ── PHASE 6: URL Filtering ───────────────────────────────────────────
    if shutdown.should_stop():
        return results

    shutdown.set_phase(f"URL filtering ({domain})")
    if config.resume and resume.is_complete(_phase(6, "filter")):
        cprint(f"\n  {Colors.YELLOW}⊘{Colors.RESET} Phase 6 already completed, resuming...", Colors.YELLOW)
    else:
        filtered = filter_urls(paths["all_urls"], paths["filtered_urls"], scope_domains, logger)
        resume.mark_complete(_phase(6, "filter"))

    if config.crawl_only:
        cprint(f"\n  {Colors.CYAN}■{Colors.RESET} Crawl-only mode. Skipping vulnerability scanning.", Colors.CYAN)
        return results

    # ── PHASE 7: Parameter Extraction ────────────────────────────────────
    if shutdown.should_stop():
        return results

    shutdown.set_phase(f"parameter extraction ({domain})")
    if config.resume and resume.is_complete(_phase(7, "params")):
        cprint(f"\n  {Colors.YELLOW}⊘{Colors.RESET} Phase 7 already completed, resuming...", Colors.YELLOW)
    else:
        params = extract_params(paths["filtered_urls"], paths["params"], logger)
        resume.mark_complete(_phase(7, "params"))

    # ── PHASE 8: Verify Alive Params ─────────────────────────────────────
    if shutdown.should_stop():
        return results

    shutdown.set_phase(f"alive param verification ({domain})")
    if config.resume and resume.is_complete(_phase(8, "alive_params")):
        cprint(f"\n  {Colors.YELLOW}⊘{Colors.RESET} Phase 8 already completed, resuming...", Colors.YELLOW)
    else:
        alive_params = verify_alive_params(paths["params"], paths["alive_params"], config, logger)
        resume.mark_complete(_phase(8, "alive_params"))

    # ── PHASE 9: Vulnerability Scanning ──────────────────────────────────
    if shutdown.should_stop():
        return results

    shutdown.set_phase(f"vulnerability scanning ({domain})")
    if config.resume and resume.is_complete(_phase(9, "nuclei")):
        cprint(f"\n  {Colors.YELLOW}⊘{Colors.RESET} Phase 9 already completed, resuming...", Colors.YELLOW)
    else:
        scan_output_dir = os.path.dirname(paths["alive_params"])
        results = run_nuclei_scan(paths["alive_params"], scan_output_dir, config, logger)
        resume.mark_complete(_phase(9, "nuclei"))

    # ── Send Telegram Notification ───────────────────────────────────────
    if results.get("total", 0) > 0:
        msg = build_notification_message(domain, results)
        send_telegram_notification(msg, config, logger)

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# ARGUMENT PARSING
# ═══════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description="ReconPilot — Automated Bug Bounty Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scanner.py example.com
  python3 scanner.py -l domains.txt
  python3 scanner.py example.com --threads 50 --rate-limit 100
  python3 scanner.py -l targets.txt --skip-subfinder --crawl-only
  python3 scanner.py example.com --resume --severity high,critical
  python3 scanner.py example.com --tool-paths subfinder=/opt/subfinder/subfinder
        """,
    )

    # Input sources
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "domains",
        nargs="*",
        default=[],
        help="One or more target domains (e.g., example.com)",
    )
    input_group.add_argument(
        "-l", "--list",
        metavar="FILE",
        help="File containing target domains (one per line)",
    )

    # Performance
    perf_group = parser.add_argument_group("Performance")
    perf_group.add_argument(
        "-t", "--threads",
        type=int,
        default=50,
        help="Number of threads for concurrent operations (default: 50)",
    )
    perf_group.add_argument(
        "--rate-limit",
        type=int,
        default=150,
        help="Requests per second rate limit (default: 150)",
    )
    perf_group.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout in seconds for each request (default: 30)",
    )
    perf_group.add_argument(
        "-c", "--concurrency",
        type=int,
        default=25,
        help="Nuclei template concurrency (default: 25)",
    )

    # Scan behavior
    scan_group = parser.add_argument_group("Scan Behavior")
    scan_group.add_argument(
        "--skip-subfinder",
        action="store_true",
        help="Skip subdomain enumeration phase",
    )
    scan_group.add_argument(
        "--crawl-only",
        action="store_true",
        help="Only perform crawling, skip vulnerability scanning",
    )
    scan_group.add_argument(
        "--severity",
        type=str,
        default="low,medium,high,critical",
        help="Comma-separated severity levels for Nuclei (default: low,medium,high,critical)",
    )

    # Resume & output
    resume_group = parser.add_argument_group("Resume & Output")
    resume_group.add_argument(
        "--resume",
        action="store_true",
        help="Resume from last completed phase",
    )
    resume_group.add_argument(
        "-o", "--output",
        type=str,
        default="output",
        help="Output directory (default: output)",
    )

    # Advanced
    adv_group = parser.add_argument_group("Advanced")
    adv_group.add_argument(
        "--tool-paths",
        nargs="+",
        metavar="TOOL=PATH",
        help="Custom tool paths (e.g., --tool-paths subfinder=/custom/path/subfinder)",
    )

    args = parser.parse_args()

    # Validate: if -l is used, domains should be empty (handled by mutually exclusive)
    # If no domains and no -l, argparse will error
    return args


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    """Main entry point for the scanner."""
    banner()
    start_time = time.time()

    # Parse arguments
    args = parse_args()
    config = ScannerConfig(args)

    # Load domains
    domains = load_domains(config, logging.getLogger("reconpilot"))

    if not domains:
        cprint("[!] No valid domains provided. Exiting.", Colors.RED, bold=True)
        sys.exit(1)

    # Display configuration
    cprint(f"\n{Colors.BOLD}{'─'*60}", Colors.CYAN)
    cprint(f"  Configuration", Colors.CYAN, bold=True)
    cprint(f"{'─'*60}{Colors.RESET}", Colors.CYAN)
    cprint(f"  Targets:       {len(domains)} domain(s)", Colors.WHITE)
    for d in domains:
        cprint(f"    • {d}", Colors.DIM)
    cprint(f"  Threads:       {config.threads}", Colors.WHITE)
    cprint(f"  Rate Limit:    {config.rate_limit} req/s", Colors.WHITE)
    cprint(f"  Timeout:       {config.timeout}s", Colors.WHITE)
    cprint(f"  Nuclei Conc:   {config.concurrency}", Colors.WHITE)
    cprint(f"  Severity:      {config.severity}", Colors.WHITE)
    cprint(f"  Output:        {config.output_dir}", Colors.WHITE)
    cprint(f"  Resume:        {'Yes' if config.resume else 'No'}", Colors.WHITE)
    cprint(f"  Crawl Only:    {'Yes' if config.crawl_only else 'No'}", Colors.WHITE)
    cprint(f"  Telegram:      {'Configured' if config.telegram_bot_token else 'Not configured'}", Colors.WHITE)
    cprint(f"{Colors.RESET}")

    # Setup output directories
    output_paths = setup_output_dirs(domains, config.output_dir)

    # Setup logging (use first domain's output dir for main log)
    first_domain = domains[0]
    logger = setup_logging(output_paths[first_domain]["root"])
    logger.info(f"ReconPilot started with {len(domains)} target(s)")

    # Check dependencies
    if not check_dependencies(config, logger):
        sys.exit(1)

    # Setup shutdown handler
    shutdown = ShutdownHandler()

    # PHASE 1: Input already handled — proceed to scanning
    cprint(f"\n{Colors.GREEN}{Colors.BOLD}{'═'*60}", Colors.GREEN)
    cprint(f"  Starting Recon Pipeline", Colors.GREEN, bold=True)
    cprint(f"{'═'*60}{Colors.RESET}\n", Colors.GREEN)

    # Scan each domain
    all_results: Dict[str, Dict] = {}

    for domain in domains:
        if shutdown.should_stop():
            cprint(f"\n[!] Shutdown requested. Stopping.", Colors.YELLOW, bold=True)
            break

        resume_state = ResumeState(output_paths[domain]["resume"])
        if not config.resume:
            resume_state.reset()

        try:
            result = scan_domain(
                domain=domain,
                paths=output_paths[domain],
                config=config,
                resume=resume_state,
                shutdown=shutdown,
                logger=logger,
            )
            all_results[domain] = result
        except Exception as e:
            logger.error(f"Error scanning {domain}: {e}", exc_info=True)
            cprint(f"\n  {Colors.RED}✗{Colors.RESET} Error scanning {domain}: {e}", Colors.RED)
            all_results[domain] = {"findings": [], "severity_summary": {}, "total": 0, "error": str(e)}

    # PHASE 10: Save final results
    if not config.crawl_only:
        save_results(all_results, output_paths, logger)

    # Summary
    elapsed = time.time() - start_time
    total_findings = sum(r.get("total", 0) for r in all_results.values())

    cprint(f"\n{Colors.BOLD}{'═'*60}", Colors.CYAN)
    cprint(f"  Scan Complete!", Colors.GREEN, bold=True)
    cprint(f"{'═'*60}{Colors.RESET}", Colors.CYAN)
    cprint(f"  Domains Scanned:  {len(all_results)}", Colors.WHITE)
    cprint(f"  Total Findings:   {total_findings}", Colors.WHITE)
    cprint(f"  Duration:         {elapsed:.1f}s ({elapsed/60:.1f}m)", Colors.WHITE)
    cprint(f"  Output:           {config.output_dir}/", Colors.WHITE)
    for domain in domains:
        cprint(f"    {domain}/", Colors.DIM)
    cprint(f"\n{Colors.RESET}")

    logger.info(
        f"Scan complete: {len(all_results)} domains, {total_findings} findings, "
        f"elapsed {elapsed:.1f}s"
    )

    # Final notification
    if total_findings > 0:
        summary_msg = (
            f"<b>🔍 ReconPilot — Full Scan Summary</b>\n\n"
            f"<b>Domains:</b> {len(all_results)}\n"
            f"<b>Total Findings:</b> {total_findings}\n"
            f"<b>Duration:</b> {elapsed/60:.1f} minutes\n"
        )
        send_telegram_notification(summary_msg, config, logger)


if __name__ == "__main__":
    main()