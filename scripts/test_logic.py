"""Offline correctness tests for the dedup / conflict-resolution core.

Run: ``python scripts/test_logic.py`` (no network, no sing-box needed).
"""

import ipaddress

import domains
import netsets


def _addrs(cidrs):
    """Expand CIDRs to the set of every contained address int (small ranges only)."""
    out = set()
    for c in cidrs:
        net = ipaddress.ip_network(c)
        out.update(range(int(net.network_address), int(net.broadcast_address) + 1))
    return out


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        raise AssertionError(name)


# --- IP: mask deduplication (contained network disappears) ---------------------
f, nf = netsets.resolve([], ["10.0.0.0/15", "10.0.0.0/24", "10.0.0.0/15"])
check("mask dedup collapses to /15", nf == ["10.0.0.0/15"])

# --- IP: adjacency merge -------------------------------------------------------
f, nf = netsets.resolve([], ["10.0.0.0/25", "10.0.0.128/25"])
check("adjacent /25s merge to /24", nf == ["10.0.0.0/24"])

# --- IP: friendly wins conflict, exact-cover removal ---------------------------
f, nf = netsets.resolve(["10.0.0.0/24"], ["10.0.0.0/24"])
check("identical conflict -> friendly only", f == ["10.0.0.0/24"] and nf == [])

# --- IP: friendly carves a hole out of a larger not-friendly block -------------
f, nf = netsets.resolve(["10.0.0.0/24"], ["10.0.0.0/16"])
friendly_addrs = _addrs(f)
nf_addrs = _addrs(nf)
original = _addrs(["10.0.0.0/16"])
check("no overlap between buckets", friendly_addrs.isdisjoint(nf_addrs))
check("friendly+notfriendly cover original", friendly_addrs | nf_addrs == original)
check("friendly is exactly the /24", friendly_addrs == _addrs(["10.0.0.0/24"]))

# --- IP: IPv6 is handled independently (tiny prefixes; /126 = 4 addresses) ------
f, nf = netsets.resolve(["2001:db8::/127"], ["2001:db8::/126"])
check("ipv6 subtract works", _addrs(f).isdisjoint(_addrs(nf)))
check("ipv6 union preserved", (_addrs(f) | _addrs(nf)) == _addrs(["2001:db8::/126"]))

# --- IP: mixed families in one call --------------------------------------------
f, nf = netsets.resolve(["10.0.0.0/8"], ["10.0.0.0/8", "2001:db8::/32"])
check("v4 conflict removed, v6 kept", f == ["10.0.0.0/8"] and nf == ["2001:db8::/32"])

# --- Domains: normalization ----------------------------------------------------
check("strip wildcard", domains.normalize("*.Example.COM") == "example.com")
check("strip leading dot", domains.normalize(".ua") == "ua")
check("strip scheme+path", domains.normalize("https://foo.bar/baz") == "foo.bar")
check("comment -> None", domains.normalize("# comment") is None)
check("blank -> None", domains.normalize("   ") is None)
check("trailing dot", domains.normalize("foo.bar.") == "foo.bar")

# --- Domains: suffix collapse --------------------------------------------------
collapsed = domains.collapse(["example.com", "sub.example.com", "other.com"])
check("subdomain dropped under suffix", collapsed == ["example.com", "other.com"])

# --- Domains: friendly wins ----------------------------------------------------
fd, nfd = domains.resolve(["example.com"], ["sub.example.com", "evil.com", "example.com"])
check("friendly domain wins", fd == ["example.com"] and nfd == ["evil.com"])

print("\nAll checks passed.")
