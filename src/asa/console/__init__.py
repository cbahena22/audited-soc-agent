"""The demo console: `asa console build` turns one run folder into a static site (no server, no network, no script).

Pages: alert queue, case (claims, citations, checker, intel, injection, actions + recorded approvals), trust report,
audit trail (chain checked at build time), buyer's checklist, about. Opens from a folder (file://) or any static host.
"""
from .build import build

__all__ = ["build"]
