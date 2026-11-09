"""Static case page (case.html) for one run: no external URL, no inline handlers or style attributes, CSP by hash.

All text goes through html.escape. Citations are <details> elements (no JS needed). One small inline script
renders the raw verdict panel from an inline JSON block and writes only through textContent.

The section renderers (facts, verdict, injection, claims, actions, usage) are shared with the demo console
(`asa.console`), which adds intel, checker and approval panels around them.
"""
from __future__ import annotations

import base64
import hashlib
import json
from html import escape
from pathlib import Path
from typing import Any

from .common import recording_date

STYLE = """
:root { --bg: #fbfbf9; --fg: #1d1f21; --muted: #5c6166; --line: #d9dcd6; --card: #ffffff;
        --bad: #a3221b; --bad-bg: #fdecea; --ok: #1f6f43; --warn: #8a5a00; --banner: #eef2f7; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #16181a; --fg: #e6e6e3; --muted: #a2a7ab; --line: #34383c; --card: #1e2124;
          --bad: #ff8a80; --bad-bg: #3a1d1b; --ok: #7fd1a0; --warn: #f0c05a; --banner: #23303d; }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg); font: 15px/1.5 system-ui, sans-serif; }
main { max-width: 960px; margin: 0 auto; padding: 24px 16px 48px; }
h1 { font-size: 1.4rem; margin: 0 0 4px; } h2 { font-size: 1.1rem; margin: 28px 0 8px; }
.muted { color: var(--muted); }
.banner { background: var(--banner); border: 1px solid var(--line); border-radius: 6px; padding: 8px 12px; margin: 12px 0; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 12px 16px; margin: 8px 0; }
.verdict { font-size: 1.2rem; font-weight: 600; }
.verdict.malicious { color: var(--bad); } .verdict.benign { color: var(--ok); } .verdict.needs_human { color: var(--warn); }
.injection { background: var(--bad-bg); border: 2px solid var(--bad); border-radius: 8px; padding: 12px 16px; }
.injection h2 { color: var(--bad); margin-top: 0; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 2px 16px; margin: 0; } dt { color: var(--muted); }
details { margin: 4px 0; } summary { cursor: pointer; font-family: ui-monospace, monospace; }
pre { white-space: pre-wrap; word-break: break-word; background: var(--bg); border: 1px solid var(--line);
      border-radius: 6px; padding: 8px; font: 13px/1.4 ui-monospace, monospace; overflow-x: auto; }
blockquote { margin: 4px 0; padding-left: 10px; border-left: 3px solid var(--line); }
table { border-collapse: collapse; width: 100%; } th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
.tag { font-size: 0.8rem; border: 1px solid var(--line); border-radius: 4px; padding: 1px 6px; color: var(--muted); }
""".strip()

SCRIPT = ("const d = JSON.parse(document.getElementById('verdict-data').textContent);"
          "document.getElementById('raw').textContent = JSON.stringify(d, null, 2);")


def csp_hash(text: str) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def json_for_script(value: Any) -> str:
    """JSON that is safe inside <script type="application/json">: no <, >, & or line/paragraph separators in raw form."""
    text = json.dumps(value, sort_keys=True)  # ASCII-only: also escapes U+2028/9 and lone surrogates
    for raw, esc in (("&", "\\u0026"), ("<", "\\u003c"), (">", "\\u003e"), (" ", "\\u2028"), (" ", "\\u2029")):
        text = text.replace(raw, esc)
    return text


def _e(value: Any) -> str:
    return escape("" if value is None else str(value), quote=True)


e = _e  # the public name the console uses: every piece of data goes through it


def _event_details(event_id: Any, data: Any) -> str:
    from .tools import compact

    # model output: an id that is not a string (a list, a dict) is shown as text, never looked up
    event = data.by_id.get(event_id) if data is not None and isinstance(event_id, str) else None
    body = json.dumps(compact(event), indent=2, ensure_ascii=False) if event else "event not found in data/"
    return f"<details><summary>{_e(event_id)}</summary><pre>{_e(body)}</pre></details>"


def replay_banner(verdict: dict) -> str:
    replay = verdict.get("replay_of")
    if not isinstance(replay, dict) or not replay:
        return ""
    date = recording_date(replay.get("recording")) or "date unknown"
    return f'<p class="banner">replay of recorded run {_e(replay.get("recording"))}, {_e(replay.get("model"))}, {_e(date)}</p>'


def facts_html(alert: dict) -> str:
    rule = (alert.get("rule") or {}).get("name")
    technique = ((alert.get("threat") or {}).get("technique") or {}).get("id")
    return '<div class="card"><dl>' + "".join(
        f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in (
            ("rule", rule), ("technique", technique), ("severity", alert.get("severity")), ("host", alert.get("host")),
            ("user", alert.get("user")), ("time", alert.get("@timestamp")), ("trigger event", alert.get("event_id")))) + "</dl></div>"


def verdict_html(verdict: dict) -> str:
    v = verdict.get("verdict")
    return (f'<div class="card"><p class="verdict {_e(v)}">Verdict: {_e(v)} '
            f'<span class="tag">confidence {_e(verdict.get("confidence"))}</span></p>'
            f"<p>{_e(verdict.get('summary'))}</p>"
            + (f'<p class="muted">stop note: {_e(verdict.get("stop_note"))}</p>' if verdict.get("stop_note") else "")
            + "</div>")


def dicts(value: Any) -> list[dict]:
    """The dict items of a list (anything else in an untrusted file is skipped, never a crash)."""
    return [x for x in value if isinstance(x, dict)] if isinstance(value, list) else []


INJECTION_NOTE = "Reported and escalated to a person."


def injection_html(verdict: dict, data: Any, section_id: str | None = None, note: str = INJECTION_NOTE) -> str:
    """The injection panel, or "" when the agent reported none. `note` is fixed text (it is not escaped)."""
    reports = dicts(verdict.get("injection_reports"))
    if not reports:
        return ""
    items = "".join(f"<li><strong>{_e(r.get('event_id'))}</strong> field <code>{_e(r.get('field'))}</code>"
                    f"<blockquote>{_e(r.get('excerpt'))}</blockquote>{_event_details(r.get('event_id'), data)}</li>"
                    for r in reports)
    sid = f' id="{_e(section_id)}"' if section_id else ""
    return (f'<section class="injection"{sid}><h2>Injection reports: text in the events tried to steer the AI</h2>'
            f"<p>{note}</p><ul>{items}</ul></section>")


def claims_html(verdict: dict, data: Any) -> list[str]:
    parts = []
    claims = dicts(verdict.get("claims"))
    if not claims:
        parts.append('<p class="muted">No claims.</p>')
    for i, claim in enumerate(claims, 1):
        quotes = "".join(f"<blockquote>{_e(q.get('event_id'))} <code>{_e(q.get('field'))}</code>: {_e(q.get('text'))}</blockquote>"
                         for q in dicts(claim.get("quotes")))
        cites = "".join(_event_details(c, data) for c in claim.get("citations") or [] if isinstance(c, str))
        parts.append(f'<div class="card"><p><strong>{i}.</strong> {_e(claim.get("text"))}</p>{quotes}'
                     + (cites or '<p class="muted">no citation</p>') + "</div>")
    return parts


def actions_html(verdict: dict, approvals: dict | None = None) -> str:
    """Recommended actions as a table. `approvals` (action id -> approval line) adds the recorded dry-run approval."""
    actions = dicts(verdict.get("recommended_actions"))
    if not actions:
        return '<p class="muted">None.</p>'

    def status(a: dict) -> str:
        found = (approvals or {}).get(a["id"]) if isinstance(a.get("id"), str) else None
        if not isinstance(found, dict):
            return "not executed"
        return (f"approved as a dry run by {_e(found.get('by'))} at {_e(found.get('at'))} (name self-declared); "
                "not executed")

    def cites(a: dict) -> str:
        return ", ".join(str(c) for c in a.get("citations")) if isinstance(a.get("citations"), list) else ""

    rows = "".join(f"<tr><td>{_e(a.get('id'))}</td><td>{_e(a.get('action'))}</td><td>{_e(a.get('target'))}</td>"
                   f"<td>{_e(a.get('reason'))}</td><td>{_e(cites(a))}</td>"
                   f"<td>{status(a)}</td></tr>" for a in actions)
    return ("<table><thead><tr><th>id</th><th>action</th><th>target</th><th>reason</th><th>citations</th>"
            f"<th>status</th></tr></thead><tbody>{rows}</tbody></table>")


def usage_html(verdict: dict) -> str:
    usage = verdict.get("usage") if isinstance(verdict.get("usage"), dict) else {}
    return (f'<p class="muted">tokens: input {_e(usage.get("input_tokens"))}, cache write {_e(usage.get("cache_creation_tokens"))}, '
            f'cache read {_e(usage.get("cache_read_tokens"))}, output {_e(usage.get("output_tokens"))} &middot; '
            f'cost ${_e(usage.get("cost_usd"))}</p>')


def render(verdict: dict, alert: dict, data: Any, run_id: str) -> str:
    alert_id = verdict.get("alert_id")
    parts = []
    banner = replay_banner(verdict)
    if banner:
        parts.append(banner)
    parts.append(f"<h1>Case {_e(alert_id)}: {_e(alert.get('title'))}</h1>")
    parts.append(f'<p class="muted">run {_e(run_id)} &middot; {_e(verdict.get("model"))} &middot; effort {_e(verdict.get("effort"))}</p>')
    parts.append(facts_html(alert))
    parts.append(verdict_html(verdict))
    injection = injection_html(verdict, data)
    if injection:
        parts.append(injection)
    parts.append("<h2>Claims and evidence</h2>")
    parts.extend(claims_html(verdict, data))
    parts.append("<h2>Recommended actions (not executed)</h2>")
    parts.append(actions_html(verdict))
    parts.append(usage_html(verdict))
    parts.append('<h2>Raw verdict</h2><pre id="raw">(raw verdict appears here when scripts run)</pre>')

    csp = (f"default-src 'none'; script-src '{csp_hash(SCRIPT)}'; style-src '{csp_hash(STYLE)}'; "
           "img-src 'none'; base-uri 'none'; form-action 'none'")
    return ("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            f'<meta http-equiv="Content-Security-Policy" content="{csp}">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            f"<title>Case {_e(alert_id)}</title><style>{STYLE}</style></head>\n<body><main>\n"
            + "\n".join(parts)
            + f'\n</main>\n<script type="application/json" id="verdict-data">{json_for_script(verdict)}</script>\n'
            f"<script>{SCRIPT}</script>\n</body></html>\n")


def write(path: Path, verdict: dict, alert: dict, data: Any, run_id: str) -> None:
    path.write_text(render(verdict, alert, data, run_id), encoding="utf-8", errors="replace", newline="\n")
