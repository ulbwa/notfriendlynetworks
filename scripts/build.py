#!/usr/bin/env python3
"""Build deduplicated friendly / not-friendly sing-box rule-sets.

Pipeline:
    1. Discover every source (static URLs + dynamically listed directories).
    2. Download all of them concurrently.
    3. Route each line by its actual content: CIDR -> IP set, otherwise domain.
    4. Deduplicate and resolve friendly-vs-not-friendly conflicts (friendly wins).
    5. Write sing-box source rule-sets (.json) and compile them to .srs.

Standard library only. Network access and the ``sing-box`` binary are required at
run time (provided by the GitHub Actions workflow).
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import domains
import netsets
import sources

ROOT = Path(__file__).resolve().parent.parent
FRIENDLY_DIR = ROOT / "friendly"
NOT_FRIENDLY_DIR = ROOT / "not-friendly"

USER_AGENT = "notfriendlynetworks-bot"
HTTP_TIMEOUT = 60
HTTP_RETRIES = 4
MAX_WORKERS = 16
RULESET_VERSION = 2

GITHUB_API = "https://api.github.com"


def _request(url: str, headers: dict[str, str] | None = None) -> bytes:
    """Fetch a URL with retries and exponential-ish backoff."""
    last_error: Exception | None = None
    base_headers = {"User-Agent": USER_AGENT}
    if headers:
        base_headers.update(headers)
    for attempt in range(HTTP_RETRIES):
        try:
            req = urllib.request.Request(url, headers=base_headers)
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            # 404 is terminal (some countries have no IPv6 file, etc.).
            if exc.code == 404:
                raise
            last_error = exc
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last_error = exc
        # Linear backoff without sleeping the whole pool for too long.
        _backoff(attempt)
    raise RuntimeError(f"failed to fetch {url}: {last_error}")


def _backoff(attempt: int) -> None:
    import time

    time.sleep(min(2 ** attempt, 8))


def github_token_headers() -> dict[str, str]:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def list_dir(repo: str, path: str) -> list[str]:
    """List entry names in a GitHub repository directory via the API."""
    url = f"{GITHUB_API}/repos/{repo}/contents/{path}"
    data = json.loads(_request(url, github_token_headers()))
    if not isinstance(data, list):
        raise RuntimeError(f"unexpected listing for {repo}/{path}: {data!r:.120}")
    return [entry["name"] for entry in data]


def download(url: str) -> str | None:
    """Download a source file, tolerating missing optional files (404)."""
    try:
        return _request(url).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            print(f"  skip (404): {url}", file=sys.stderr)
            return None
        raise


def parse_network(token: str):
    """Return a normalized CIDR string if ``token`` is an IP/CIDR, else ``None``."""
    try:
        return str(ipaddress.ip_network(token, strict=False))
    except ValueError:
        return None


def classify(text: str, bucket: str, ip_sets: dict, domain_sets: dict) -> None:
    """Route every line of a source file into the right bucket and set."""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped[0] in "#!":
            continue
        token = stripped.split()[0]
        network = parse_network(token)
        if network is not None:
            ip_sets[bucket].append(network)
            continue
        domain = domains.normalize(token)
        if domain:
            domain_sets[bucket].add(domain)


def gather() -> tuple[dict, dict]:
    """Download and classify every source."""
    print("Discovering sources...", file=sys.stderr)
    source_list = sources.build_sources(list_dir)
    print(f"  {len(source_list)} sources", file=sys.stderr)

    ip_sets = {"friendly": [], "not_friendly": []}
    domain_sets = {"friendly": set(), "not_friendly": set()}

    print("Downloading...", file=sys.stderr)
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        results = list(pool.map(lambda s: (download(s[0]), s[1]), source_list))

    for text, bucket in results:
        if text is not None:
            classify(text, bucket, ip_sets, domain_sets)
    return ip_sets, domain_sets


def write_ruleset(directory: Path, name: str, key: str, values: list[str]) -> None:
    """Write a sing-box source rule-set (.json) and compile it to .srs."""
    rules = [{key: values}] if values else []
    document = {"version": RULESET_VERSION, "rules": rules}

    json_path = directory / f"{name}.json"
    srs_path = directory / f"{name}.srs"
    json_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    sing_box = os.environ.get("SING_BOX", "sing-box")
    subprocess.run(
        [sing_box, "rule-set", "compile", "--output", str(srs_path), str(json_path)],
        check=True,
    )
    print(f"  {srs_path.relative_to(ROOT)}: {len(values)} entries", file=sys.stderr)


def main() -> int:
    FRIENDLY_DIR.mkdir(exist_ok=True)
    NOT_FRIENDLY_DIR.mkdir(exist_ok=True)

    ip_sets, domain_sets = gather()

    print("Resolving IP sets...", file=sys.stderr)
    friendly_ip, not_friendly_ip = netsets.resolve(
        ip_sets["friendly"], ip_sets["not_friendly"]
    )

    print("Resolving domain sets...", file=sys.stderr)
    friendly_dom, not_friendly_dom = domains.resolve(
        domain_sets["friendly"], domain_sets["not_friendly"]
    )

    print("Writing rule-sets...", file=sys.stderr)
    write_ruleset(FRIENDLY_DIR, "domain", "domain_suffix", friendly_dom)
    write_ruleset(FRIENDLY_DIR, "ip", "ip_cidr", friendly_ip)
    write_ruleset(NOT_FRIENDLY_DIR, "domain", "domain_suffix", not_friendly_dom)
    write_ruleset(NOT_FRIENDLY_DIR, "ip", "ip_cidr", not_friendly_ip)

    print("Done.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
