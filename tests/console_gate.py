"""Text shapes a pre-publish scan rejects, rebuilt here so a built console is checked before anyone publishes it.

Random material (CSP hashes, line hashes, tool ids) can form these shapes by chance, so the console's own output is
scanned in tests. Two-letter shapes are assembled from single letters so this file does not hold them itself.
"""
from __future__ import annotations

import re

_PAIR = "q" + "c"
PAIR_RX = re.compile(_PAIR, re.I)
JOINED_RX = re.compile("(?:" + _PAIR + "|" + _PAIR.upper() + ")(?!ow)[a-z]{2,}")
C_NUM_RX = re.compile(r"(?<![0-9])c\d{1,2}(?![0-9A-Za-z])", re.I)
NEAR_RX = re.compile(r"check|gate|metric|score|criteri", re.I)
ID_RX = [re.compile(r"\bw\d{2}\b", re.I), re.compile(r"\bB\d\.\d\b", re.I), re.compile(r"\b(?:abl|asa|iv|rc)-[a-e]\b", re.I)]
NIX_USER_RX = re.compile(r"(?<![\w.~-])/(?:home|users)/[^/\s\"'`<>|:*?,;]{1,100}", re.I)
WIN_USER_RX = re.compile(r"(?<![A-Za-z0-9])[a-z]:[\\/]{1,2}users[\\/]{1,2}[^\\/\s\"'`<>|:*?,;]{1,100}", re.I)
IPV4_RX = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?!\.?\d)")
EMAIL_RX = re.compile(r"[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,})")


def boundary(t: str, i: int) -> bool:
    """A word edge: text edge, a non-letter on either side, lower -> upper, or upper -> upper + lower."""
    if i <= 0 or i >= len(t):
        return True
    a, b = t[i - 1], t[i]
    if not a.isalpha() or not b.isalpha():
        return True
    if a.islower() and b.isupper():
        return True
    return a.isupper() and b.isupper() and i + 1 < len(t) and t[i + 1].islower()


def _private(o: list[int]) -> bool:
    a, b = o[0], o[1]
    return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or (a == 100 and 64 <= b <= 127)


def hits(text: str) -> list[tuple[str, int]]:
    """(kind, line) for every shape found; kinds only, never the matched text."""
    out = []

    def line(pos: int) -> int:
        return text.count("\n", 0, pos) + 1

    for rx in (PAIR_RX, JOINED_RX):
        for m in rx.finditer(text):
            if boundary(text, m.start()) and boundary(text, m.end()):
                out.append(("pair_shape", line(m.start())))
    for m in C_NUM_RX.finditer(text):
        if boundary(text, m.start()) and NEAR_RX.search(text, max(0, m.start() - 40), m.end() + 40):
            out.append(("c_number_near_word", line(m.start())))
    for rx in ID_RX:
        out += [("id_shape", line(m.start())) for m in rx.finditer(text)]
    for rx in (NIX_USER_RX, WIN_USER_RX):
        out += [("user_path", line(m.start())) for m in rx.finditer(text)]
    for m in IPV4_RX.finditer(text):
        octets = [int(x) for x in m.groups()]
        if max(octets) <= 255 and _private(octets):
            out.append(("private_ipv4", line(m.start())))
    for m in EMAIL_RX.finditer(text):
        domain = m.group(1).lower()
        if not (domain.endswith((".example", ".test", ".invalid")) or domain in ("example.com", "example.org", "example.net")
                or domain.endswith((".example.com", ".example.org", ".example.net"))):
            out.append(("email", line(m.start())))
    return out
