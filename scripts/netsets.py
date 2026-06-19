"""Integer-interval algebra over IP networks.

Every CIDR is turned into an inclusive ``[start, end]`` integer interval, kept
separately per address family (IPv4 / IPv6). Working on merged interval lists
lets us, in a single pass, collapse exact duplicates, drop networks contained in
a larger one (mask deduplication), merge adjacent networks, and subtract one set
from another (used for friendly-wins conflict resolution).

The result is converted back to the *minimal* set of CIDRs.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable

Interval = tuple[int, int]

_FAMILIES = (4, 6)
_ADDR = {4: ipaddress.IPv4Address, 6: ipaddress.IPv6Address}


def parse_intervals(cidrs: Iterable[str], version: int) -> list[Interval]:
    """Parse CIDRs of the given family into a merged, sorted interval list."""
    intervals: list[Interval] = []
    for raw in cidrs:
        text = raw.strip()
        if not text:
            continue
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            continue
        if net.version != version:
            continue
        intervals.append((int(net.network_address), int(net.broadcast_address)))
    return merge(intervals)


def merge(intervals: list[Interval]) -> list[Interval]:
    """Merge overlapping and adjacent intervals into a minimal sorted list."""
    if not intervals:
        return []
    intervals.sort()
    merged: list[list[int]] = [list(intervals[0])]
    for start, end in intervals[1:]:
        last = merged[-1]
        if start <= last[1] + 1:  # overlapping or directly adjacent
            if end > last[1]:
                last[1] = end
        else:
            merged.append([start, end])
    return [(s, e) for s, e in merged]


def subtract(a: list[Interval], b: list[Interval]) -> list[Interval]:
    """Return ``a - b`` for two merged, sorted interval lists.

    ``a`` is processed in order and the cursor only ever moves forward, so a
    single forward pointer over ``b`` is sufficient and correct.
    """
    result: list[Interval] = []
    j = 0
    n = len(b)
    for start, end in a:
        cur = start
        while cur <= end:
            while j < n and b[j][1] < cur:
                j += 1
            if j < n and b[j][0] <= end:
                bs, be = b[j]
                if bs > cur:
                    result.append((cur, bs - 1))
                cur = be + 1
            else:
                result.append((cur, end))
                cur = end + 1
    return result


def intervals_to_cidrs(intervals: list[Interval], version: int) -> list[str]:
    """Convert intervals back into the minimal set of CIDR strings."""
    addr = _ADDR[version]
    nets: list = []
    for start, end in intervals:
        nets.extend(ipaddress.summarize_address_range(addr(start), addr(end)))
    return [str(n) for n in ipaddress.collapse_addresses(nets)]


def resolve(friendly: Iterable[str], not_friendly: Iterable[str]) -> tuple[list[str], list[str]]:
    """Deduplicate two CIDR collections and resolve conflicts in favour of friendly.

    Returns ``(friendly_cidrs, not_friendly_cidrs)`` as minimal, sorted CIDR
    lists covering both address families. Any address present in both inputs is
    removed from the not-friendly result.
    """
    friendly = list(friendly)
    not_friendly = list(not_friendly)
    out_friendly: list[str] = []
    out_not_friendly: list[str] = []
    for version in _FAMILIES:
        f = parse_intervals(friendly, version)
        nf = subtract(parse_intervals(not_friendly, version), f)
        out_friendly.extend(intervals_to_cidrs(f, version))
        out_not_friendly.extend(intervals_to_cidrs(nf, version))
    return out_friendly, out_not_friendly
