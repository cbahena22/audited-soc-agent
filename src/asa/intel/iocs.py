"""IOC model: validate / normalise, defang, and the routable() profile filter (ported from the earlier ioc-vetting tool)."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

TYPES = ("ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256")
PROFILES = ("real", "demo")


@dataclass(frozen=True, order=True)
class Ioc:
    type: str
    value: str  # normalised, never defanged


_HEX = {"md5": 32, "sha1": 40, "sha256": 64}
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_NODE_BAD = re.compile(r"[\s\x00-\x1f\x7f<>\"'`\\^{}|]")


def _norm_domain(value: str) -> str | None:
    v = value.strip().rstrip(".").lower()
    if not v or len(v) > 253 or ".." in v:
        return None
    try:
        v = v.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = v.split(".")
    if len(labels) < 2 or len(v) > 253:
        return None
    if not all(_LABEL.match(l) for l in labels):
        return None
    tld = labels[-1]
    if tld.isdigit() or not (tld.startswith("xn--") or tld.isalpha()):
        return None
    return v


def _norm_ip(value: str, version: int) -> str | None:
    if "%" in value or "/" in value or " " in value:
        return None
    try:
        ip = ipaddress.IPv4Address(value) if version == 4 else ipaddress.IPv6Address(value)
    except ValueError:
        return None
    return str(ip)


def _norm_url(value: str) -> str | None:
    if len(value) > 2048 or _NODE_BAD.search(value):
        return None
    try:
        parts = urlsplit(value)
        port = parts.port
        host = parts.hostname
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https", "ftp") or not host or parts.username or parts.password:
        return None
    if ":" in host:
        h = _norm_ip(host, 6)
        netloc = f"[{h}]" if h else None
    else:
        h = _norm_ip(host, 4) or _norm_domain(host)
        netloc = h
    if not h or netloc is None:
        return None
    if port is not None:
        netloc += f":{port}"
    rest = value[len(parts.scheme) + 3 + len(parts.netloc):]
    return f"{parts.scheme.lower()}://{netloc}{rest}"


def normalise(value: str, type: str) -> Ioc | None:
    """Validate and canonicalise; None when the value is not a well-formed IOC of that type."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if type in _HEX:
        v = value.lower()
        ok = len(v) == _HEX[type] and re.fullmatch(r"[0-9a-f]+", v)
        return Ioc(type, v) if ok else None
    out = None
    if type == "ipv4":
        out = _norm_ip(value, 4)
    elif type == "ipv6":
        out = _norm_ip(value, 6)
    elif type == "domain":
        out = _norm_domain(value)
    elif type == "url":
        out = _norm_url(value)
    return Ioc(type, out) if out else None


def host_of(ioc: Ioc) -> Ioc | None:
    """The host part of a URL IOC as its own IOC (ipv4 / ipv6 / domain)."""
    if ioc.type != "url":
        return None
    host = urlsplit(ioc.value).hostname or ""
    for t in ("ipv4", "ipv6", "domain"):
        n = normalise(host, t)
        if n:
            return n
    return None


def _dots(s: str) -> str:
    return s.replace(".", "[.]")


def defang(ioc: Ioc) -> str:
    """Safe-to-paste form: no live scheme, no bare dot in a host, no bare colon in an IPv6 address."""
    if ioc.type in _HEX:
        return ioc.value
    if ioc.type == "ipv4" or ioc.type == "domain":
        return _dots(ioc.value)
    if ioc.type == "ipv6":
        return ioc.value.replace(":", "[:]")
    parts = urlsplit(ioc.value)
    scheme = {"http": "hxxp", "https": "hxxps"}.get(parts.scheme, parts.scheme + "[x]")
    netloc = parts.netloc
    if netloc.startswith("["):
        end = netloc.index("]")
        netloc = netloc[:end + 1].replace(":", "[:]") + netloc[end + 1:]
    else:
        netloc = _dots(netloc)
    rest = ioc.value[len(parts.scheme) + 3 + len(parts.netloc):].replace("://", "[://]")
    return f"{scheme}://{netloc}{rest}"


_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_RESERVED_TLDS = {"example", "test", "invalid", "localhost", "local", "internal", "lan", "home", "corp", "onion"}
_RESERVED_ZONES = {"example.com", "example.net", "example.org"}
_DEMO_TLDS = {"example", "test", "invalid"}


def _is_reserved(domain: str) -> bool:
    return domain.rsplit(".", 1)[-1] in _RESERVED_TLDS or any(
        domain == z or domain.endswith("." + z) for z in _RESERVED_ZONES
    )


def _is_demo_name(domain: str) -> bool:
    return domain.rsplit(".", 1)[-1] in _DEMO_TLDS or any(
        domain == z or domain.endswith("." + z) for z in _RESERVED_ZONES
    )


def routable(ioc: Ioc, profile: str) -> bool:
    """real: public addresses and non-reserved names only. demo: documentation ranges / reserved test names only.
    Private, loopback and link-local space is dropped in both."""
    if profile not in PROFILES:
        raise ValueError("unknown profile")
    if ioc.type in _HEX:
        return True
    if ioc.type == "url":
        h = host_of(ioc)
        return bool(h) and routable(h, profile)
    if ioc.type in ("ipv4", "ipv6"):
        ip = ipaddress.ip_address(ioc.value)
        if any(ip in n for n in _DOC_NETS):
            return profile == "demo"
        if profile == "demo":
            return False
        if ip.version == 6 and ip in _NAT64:
            return False
        return ip.is_global
    if profile == "demo":
        return _is_demo_name(ioc.value)
    return not _is_reserved(ioc.value)
