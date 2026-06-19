"""Domain normalization, suffix-based deduplication and conflict resolution.

Domains end up as sing-box ``domain_suffix`` rules, so a value also covers all of
its subdomains. We exploit that to drop redundant entries: if ``example.com`` is
present, ``sub.example.com`` is implied and removed. Conflicts between buckets are
resolved in favour of friendly — any not-friendly domain covered by a friendly
suffix is dropped.
"""

from __future__ import annotations

import re
from typing import Iterable

# A conservative validity check after normalization. Labels may contain
# underscores (some source lists use them); the whole thing must look like a
# hostname and carry no path/scheme/whitespace.
_LABEL = r"[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?"
_DOMAIN_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")


def normalize(line: str) -> str | None:
    """Normalize a single source line to a bare lowercase domain, or ``None``.

    Handles comments, blank lines, wildcard/leading-dot prefixes, trailing dots,
    IDN (converted to punycode) and an optional scheme/path. Returns ``None`` for
    anything that is not a usable domain (e.g. an IP address — those are routed
    through :mod:`netsets` instead).
    """
    text = line.strip().lower()
    if not text or text[0] in "#!":
        return None
    # Strip an accidental scheme and any path component.
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0]
    # Wildcards and leading dots both mean "this suffix".
    if text.startswith("*."):
        text = text[2:]
    text = text.strip(".")
    if not text:
        return None
    try:
        text = text.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        pass
    if not _DOMAIN_RE.match(text):
        return None
    return text


def _is_covered(domain: str, suffixes: set[str]) -> bool:
    """True if ``domain`` equals or is a subdomain of any suffix in ``suffixes``."""
    if domain in suffixes:
        return True
    labels = domain.split(".")
    for i in range(1, len(labels)):
        if ".".join(labels[i:]) in suffixes:
            return True
    return False


def collapse(domains: Iterable[str]) -> list[str]:
    """Drop domains that are already covered by a shorter suffix in the set."""
    unique = set(domains)
    kept = [d for d in unique if not _is_covered_by_others(d, unique)]
    return sorted(kept)


def _is_covered_by_others(domain: str, all_domains: set[str]) -> bool:
    labels = domain.split(".")
    for i in range(1, len(labels)):
        if ".".join(labels[i:]) in all_domains:
            return True
    return False


def resolve(friendly: Iterable[str], not_friendly: Iterable[str]) -> tuple[list[str], list[str]]:
    """Normalize, deduplicate and resolve conflicts in favour of friendly.

    Returns ``(friendly_domains, not_friendly_domains)`` as sorted lists of bare
    domains. Not-friendly domains covered by a friendly suffix are dropped.
    """
    friendly_norm = {d for d in (normalize(x) for x in friendly) if d}
    not_friendly_norm = {d for d in (normalize(x) for x in not_friendly) if d}

    friendly_final = set(collapse(friendly_norm))
    not_friendly_kept = {
        d for d in not_friendly_norm if not _is_covered(d, friendly_final)
    }
    not_friendly_final = collapse(not_friendly_kept)
    return sorted(friendly_final), not_friendly_final
