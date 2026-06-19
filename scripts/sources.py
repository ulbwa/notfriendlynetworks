"""Declaration of every upstream source and how it maps to a bucket.

A *source* is just a ``(url, bucket)`` pair. Each downloaded line is later routed
by its actual content (CIDR vs domain) regardless of which file it came from, so
mixed files are handled correctly and no per-file "kind" is needed here.

Buckets:
    "friendly"      -> Russia / Belarus / Kazakhstan (and Russia "outside")
    "not_friendly"  -> the rest of the world

Directory contents that change over time (country list, category/service/subnet
files) are discovered dynamically via an injected ``list_dir`` callback so new
upstream files are picked up automatically.
"""

from __future__ import annotations

from typing import Callable

RAW = "https://raw.githubusercontent.com"

IPVERSE = "ipverse/country-ip-blocks"
ALLOW = "itdoginfo/allow-domains"
REFILTER = "1andrevich/Re-filter-lists"

ALLOW_REF = "main"
REFILTER_REF = "main"
IPVERSE_REF = "master"

# Country codes that go into the friendly bucket; everything else is not-friendly.
FRIENDLY_COUNTRIES = {"ru", "by", "kz"}

# A directory lister: ``list_dir(repo, path) -> list[str]`` returning entry names.
ListDir = Callable[[str, str], "list[str]"]


def _raw(repo: str, ref: str, path: str) -> str:
    return f"{RAW}/{repo}/{ref}/{path}"


def _static_sources() -> list[tuple[str, str]]:
    """Sources with fixed, known paths."""
    return [
        # allow-domains — Russia domain lists (raw, comment-free format).
        (_raw(ALLOW, ALLOW_REF, "Russia/outside-raw.lst"), "friendly"),
        (_raw(ALLOW, ALLOW_REF, "Russia/inside-raw.lst"), "not_friendly"),
        # allow-domains — Ukraine domains.
        (_raw(ALLOW, ALLOW_REF, "Ukraine/inside-raw.lst"), "not_friendly"),
        # Re-filter-lists — everything not-friendly.
        (_raw(REFILTER, REFILTER_REF, "domains_all.lst"), "not_friendly"),
        (_raw(REFILTER, REFILTER_REF, "community.lst"), "not_friendly"),
        (_raw(REFILTER, REFILTER_REF, "ooni_domains.lst"), "not_friendly"),
        (_raw(REFILTER, REFILTER_REF, "ipsum.lst"), "not_friendly"),
        (_raw(REFILTER, REFILTER_REF, "community_ips.lst"), "not_friendly"),
        (_raw(REFILTER, REFILTER_REF, "discord_ips.lst"), "not_friendly"),
    ]


def _allow_discovered(list_dir: ListDir) -> list[tuple[str, str]]:
    """allow-domains category / service / subnet files (all not-friendly)."""
    out: list[tuple[str, str]] = []
    for path in ("Categories", "Services", "Subnets/IPv4", "Subnets/IPv6"):
        for name in list_dir(ALLOW, path):
            if name.endswith(".lst"):
                out.append((_raw(ALLOW, ALLOW_REF, f"{path}/{name}"), "not_friendly"))
    return out


def _ipverse_discovered(list_dir: ListDir) -> list[tuple[str, str]]:
    """ipverse per-country aggregated IPv4 + IPv6 lists."""
    out: list[tuple[str, str]] = []
    for code in list_dir(IPVERSE, "country"):
        code = code.lower()
        bucket = "friendly" if code in FRIENDLY_COUNTRIES else "not_friendly"
        for family in ("ipv4-aggregated.txt", "ipv6-aggregated.txt"):
            out.append((_raw(IPVERSE, IPVERSE_REF, f"country/{code}/{family}"), bucket))
    return out


def build_sources(list_dir: ListDir) -> list[tuple[str, str]]:
    """Assemble the full list of ``(url, bucket)`` sources."""
    sources = _static_sources()
    sources += _allow_discovered(list_dir)
    sources += _ipverse_discovered(list_dir)
    return sources
