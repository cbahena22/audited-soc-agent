"""HTML for the console pages. Pure functions: data in, one HTML string out (no file access, no clock).

Every value from a run file, the dataset or the checklist goes through `e()` (html.escape). Pages carry no script
(`script-src 'none'`), one inline style allowed by its hash, no `style=` attribute, no inline handler and no
absolute URL except code links under the one configured code base.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .. import case_page
from ..case_page import csp_hash, dicts, e
from ..common import ALERT_ID, recording_date
from .load import AlertRun

CODE_BASE = "https://github.com/cbahena22/audited-soc-agent/blob/main/"
CODE_BASE_RX = re.compile(r"^https://github\.com/[A-Za-z0-9][A-Za-z0-9-]{0,38}/audited-soc-agent/blob/[A-Za-z0-9._-]{1,60}/$")
CODE_PATH_RX = re.compile(r"^(?:src|tests|tools|evals|data|checklist|docs)/[A-Za-z0-9_][A-Za-z0-9_./-]{0,200}$")
SYMBOL_RX = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,120}$")
VIEW_RX = re.compile(r"^(queue|checklist|about|case|trust|audit)(?::(A-\d{3}))?(?:#([A-Za-z][A-Za-z0-9-]{0,40}))?$")
ROW_ID_RX = re.compile(r"^Q\d{2}$")
MAX_TRAIL_ROWS = 2000
INTEL_LABEL = "post-triage enrichment (synthetic provider answers)"
SELF_DECLARED = "Approver names are self-declared (--as is free text)."
DEMO_APPROVER = "scripted demo approval"
CONSOLE_INJECTION_NOTE = ("Reported and escalated to a person. Whether the verdict or a recommended action matched what "
                          "the text asked for is on the trust report.")

EXTRA_STYLE = """
:root { --link: #1f4f8a; }
@media (prefers-color-scheme: dark) { :root { --link: #9cc3ff; } }
a { color: var(--link); }
header.site { background: var(--card); border-bottom: 1px solid var(--line); }
header.site div { max-width: 1080px; margin: 0 auto; padding: 10px 16px; display: flex; flex-wrap: wrap; gap: 4px 20px; align-items: baseline; }
.brand { margin: 0; font-weight: 600; }
nav a { margin-right: 14px; white-space: nowrap; }
nav a[aria-current="page"] { color: var(--fg); font-weight: 600; text-decoration: underline; }
nav.sub { margin: 4px 0 16px; padding-bottom: 6px; border-bottom: 1px solid var(--line); }
main { max-width: 1080px; }
dd { margin: 0; overflow-wrap: anywhere; }
code, .hash { font-family: ui-monospace, monospace; font-size: 0.85em; overflow-wrap: anywhere; word-break: break-all; }
.mark { display: inline-block; min-width: 3.4em; text-align: center; font-size: 0.8rem; font-weight: 600; border: 1px solid currentColor; border-radius: 4px; padding: 0 6px; margin-right: 6px; }
.mark.pass { color: var(--ok); } .mark.note { color: var(--warn); } .mark.fail { color: var(--bad); }
.honest { border-left: 4px solid var(--warn); }
.honest ul, .card ul { margin: 4px 0; padding-left: 20px; }
.bad { color: var(--bad); font-weight: 600; } .ok { color: var(--ok); }
.scroll { overflow-x: auto; }
.row h3 { font-size: 1rem; margin: 0 0 4px; }
@media (max-width: 640px) {
  table.stack thead { display: none; }
  table.stack, table.stack tbody, table.stack tr, table.stack td { display: block; width: 100%; }
  table.stack tr { background: var(--card); border: 1px solid var(--line); border-radius: 8px; margin: 8px 0; padding: 4px 10px; }
  table.stack td { border: 0; padding: 2px 0; overflow-wrap: anywhere; }
  table.stack td::before { content: attr(data-label) ": "; color: var(--muted); }
  dl { grid-template-columns: 1fr; }
}
""".strip()
STYLE = case_page.STYLE + "\n" + EXTRA_STYLE


@dataclass
class Site:
    """Run-wide facts every page needs."""
    run_id: str
    recording: str | None = None
    model: str | None = None
    honesty: list[str] | None = None
    honesty_source: str | None = None
    # (reported, planted) from evals/results.json, when it describes the same recording as this run
    planted: tuple[int, int] | None = None
    code_base: str = CODE_BASE
    alert_ids: set[str] = field(default_factory=set)


def csp() -> str:
    return (f"default-src 'none'; style-src '{csp_hash(STYLE)}'; script-src 'none'; img-src 'self' data:; "
            "base-uri 'none'; form-action 'none'")


def page(site: Site, title: str, body: list[str], active: str) -> str:
    nav = "".join(f'<a href="{href}"' + (' aria-current="page"' if key == active else "") + f">{label}</a>"
                  for key, href, label in (("queue", "index.html", "Alert queue"), ("checklist", "checklist.html", "Buyer's checklist"),
                                           ("about", "about.html", "About this demo")))
    return ("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            f'<meta http-equiv="Content-Security-Policy" content="{csp()}">'
            '<meta name="referrer" content="no-referrer">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            f"<title>{e(title)} - audited SOC agent demo</title><style>{STYLE}</style></head>\n<body>\n"
            f'<header class="site"><div><p class="brand">Harbor Watch MSSP: AI triage, audited</p>'
            f'<nav aria-label="site">{nav}</nav></div></header>\n<main>\n'
            + run_banner(site) + "\n" + "\n".join(body) + "\n</main>\n</body></html>\n")


def run_banner(site: Site) -> str:
    if site.recording:
        what = (f"replay of recorded run {e(site.recording)} ({e(site.model)}, recorded {e(recording_date(site.recording) or 'on an unknown date')}): "
                "$0, no model call")
    else:
        what = "live run"
    return f'<p class="banner">Synthetic data. Run {e(site.run_id)}, {what}. Nothing here was executed anywhere.</p>'


def honesty_box(site: Site) -> str:
    if not site.honesty:
        return '<div class="card honest"><p>Eval results not found (evals/results.json): read every claim here as unmeasured.</p></div>'
    items = "".join(f"<li>{e(line)}</li>" for line in site.honesty)
    return (f'<div class="card honest"><p><strong>Read the trust claims with these numbers</strong></p><ul>{items}</ul>'
            f'<p class="muted">{e(site.honesty_source)}</p></div>')


def honesty_lines(results: Any) -> tuple[list[str], str] | None:
    """Plain numbers from evals/results.json, or None when the file does not have them."""
    t = results.get("triage") if isinstance(results, dict) else None
    try:
        acc, base, nh, conf = t["accuracy"], t["baseline"], t["needs_human"], t["confusion"]
        correct, n, base_correct, base_n = (_int(acc["correct"]), _int(acc["n"]), _int(base["correct"]), _int(base["n"]))
        handed, n_mal = _int(nh["k"]), _int(t["n_malicious"])
        expected_human = sum(_int(v) for v in conf["needs_human"].values())
        caught = _int(conf["malicious"]["malicious"])
    except (TypeError, KeyError, AttributeError, ValueError):
        return None
    over = " (it over-escalates)" if handed > expected_human else ""
    lines = [f"{correct}/{n} verdicts match the answer key; a severity-only rule gets {base_correct}/{base_n}.",
             f"It hands {handed} of {n} alerts to a person; the answer key expects {expected_human}{over}.",
             f"{n_mal} malicious alert{'s' if n_mal != 1 else ''} in the set; the agent marked {caught} as malicious.",
             SELF_DECLARED]
    return lines, f"source: evals/results.json, recording {t.get('recording')}, n = {n}"


def planted_counts(results: Any, recording: str | None) -> tuple[int, int] | None:
    """(reported, planted) planted instruction-shaped texts from evals/results.json, only for the same recording."""
    inj = results.get("injection") if isinstance(results, dict) else None
    if not isinstance(inj, dict) or recording is None or inj.get("recording") != recording:
        return None
    try:
        return _int(inj["reported"]), _int(inj["n"])
    except (KeyError, ValueError):
        return None


def injection_summary(runs: list[AlertRun], site: Site) -> str:
    """One honest line: reports, the alerts they are on, alerts that reported one event more than once, and (from
    evals/results.json) how many planted texts were reported. Escaped text, no markup."""
    per_alert: dict[str, list[tuple[str, str]]] = {}
    for run in runs:
        reports = dicts(run.verdict.get("injection_reports"))
        if reports:
            per_alert[run.alert_id] = [(str(r.get("event_id")), str(r.get("field"))) for r in reports]
    total = sum(len(v) for v in per_alert.values())
    text = f"{total} injection report{'s' if total != 1 else ''} by the agent"
    if per_alert:
        text += f" on {len(per_alert)} alert{'s' if len(per_alert) != 1 else ''}"
    repeats = []
    for alert_id, reports in sorted(per_alert.items()):
        events = {event for event, _ in reports}
        if len(events) < len(reports):
            one_per_field = len(set(reports)) == len(reports)
            repeats.append(f"{alert_id}: {len(reports)} reports on {len(events)} event{'s' if len(events) != 1 else ''}"
                           + (", one per field" if one_per_field else ""))
    if repeats:
        text += f" ({'; '.join(repeats)})"
    if site.planted is not None:
        reported, planted = site.planted
        text += f"; {reported} of {planted} planted instruction-shaped texts reported (evals/results.json)"
    return e(text)


def _int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("not an int")
    return value


def _num(value: Any) -> int | float | None:
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _d(value: Any, key: str) -> dict:
    found = value.get(key) if isinstance(value, dict) else None
    return found if isinstance(found, dict) else {}


def _mark(kind: str) -> str:
    return f'<span class="mark {kind}">{kind}</span>'


def _td(label: str, html: str) -> str:
    return f'<td data-label="{e(label)}">{html}</td>'


def short(value: Any, n: int = 16) -> str:
    text = str(value) if value is not None else ""
    return e(text[:n] + ("..." if len(text) > n else ""))


# ------------------------------------------------------------------------------------------------ per-alert links

def case_href(alert_id: str) -> str:
    return f"case-{alert_id}.html"


def alert_nav(alert_id: str, active: str) -> str:
    links = "".join(f'<a href="{kind}-{alert_id}.html"' + (' aria-current="page"' if kind == active else "") + f">{label}</a>"
                    for kind, label in (("case", "Case"), ("trust", "Trust report"), ("audit", "Audit trail")))
    return f'<nav class="sub" aria-label="this alert"><a href="index.html">&larr; queue</a>{links}</nav>'


def intel_counts(run: AlertRun) -> dict[str, int]:
    counts = {"contain": 0, "review": 0, "clear": 0}
    for ind in dicts((run.intel or {}).get("indicators")):
        if isinstance(ind.get("verdict"), str) and ind["verdict"] in counts:
            counts[ind["verdict"]] += 1
    return counts


# ------------------------------------------------------------------------------------------------ queue

def queue_page(site: Site, runs: list[AlertRun], skipped: dict[str, str], alerts: dict) -> str:
    rows = []
    totals = {"needs_human": 0, "benign": 0, "malicious": 0}
    for run in runs:
        v, alert = run.verdict, alerts.get(run.alert_id) or {}
        verdict = v.get("verdict")
        if isinstance(verdict, str) and verdict in totals:
            totals[verdict] += 1
        reports = len(dicts(v.get("injection_reports")))
        counts = intel_counts(run)
        intel = ("not run" if run.intel is None else
                 " / ".join(f"{k} {n}" for k, n in counts.items() if n) or "no indicators")
        cost = _num(_d(v, "usage").get("cost_usd"))
        rows.append("<tr>" + "".join((
            _td("Alert", f'<a href="{case_href(run.alert_id)}">{e(run.alert_id)}</a>'),
            _td("Title", e(alert.get("title"))),
            _td("Severity", e(alert.get("severity"))),
            _td("Verdict", f'<span class="verdict {e(verdict)}">{e(verdict)}</span>'),
            _td("Confidence", e(v.get("confidence"))),
            _td("Needs a person", "yes" if verdict == "needs_human" else "no"),
            _td("Injection", f'<span class="bad">{reports} reported</span>' if reports else "none"),
            _td("Intel", e(intel)),
            _td("Recorded cost", f"${cost:.4f}" if cost is not None else "?"),
        )) + "</tr>")
    head = "".join(f"<th>{h}</th>" for h in ("Alert", "Title", "Severity", "Verdict", "Confidence", "Needs a person",
                                              "Injection", "Intel", "Recorded cost"))
    body = [
        "<h1>Alert queue</h1>",
        f"<p>{len(runs)} alerts triaged by the agent in this run: {totals['needs_human']} handed to a person, "
        f"{totals['benign']} benign, {totals['malicious']} malicious; {injection_summary(runs, site)}. "
        "Open an alert for its case, trust report and audit trail.</p>",
        honesty_box(site),
        f'<table class="stack"><thead><tr>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table>',
    ]
    if skipped:
        body.append("<h2>Not shown</h2><ul>" + "".join(f"<li>{e(k)}: {e(r)}</li>" for k, r in sorted(skipped.items())) + "</ul>")
    return page(site, "Alert queue", body, "queue")


# ------------------------------------------------------------------------------------------------ case

def _notes(run: AlertRun, names: tuple[str, ...]) -> str:
    found = [(n, run.notes[n]) for n in names if n in run.notes]
    return "".join(f'<p class="bad">{e(n)} could not be read: {e(r)}</p>' for n, r in found)


def checker_html(run: AlertRun) -> str:
    rel = f"out/runs/{site_run(run)}/{run.alert_id}"
    if run.check is None:
        return f'<p class="muted">The evidence checker has not run on this alert (asa check {e(rel)}).</p>' + _notes(run, ("check.json",))
    findings = dicts(run.check.get("findings"))
    claims = run.check.get("claims")
    if not findings:
        text = f'<p>{_mark("pass")}0 findings on {e(claims)} claims: every citation is an event the agent was shown, every quote is in its field.</p>'
    else:
        rows = "".join("<tr>" + _td("Kind", e(f.get("kind"))) + _td("Claim", e(f.get("claim_index"))) + _td("Event", e(f.get("event_id")))
                       + _td("Detail", e(f.get("detail"))) + "</tr>" for f in findings)
        text = (f'<p>{_mark("fail")}{len(findings)} findings on {e(claims)} claims.</p>'
                f'<table class="stack"><thead><tr><th>Kind</th><th>Claim</th><th>Event</th><th>Detail</th></tr></thead><tbody>{rows}</tbody></table>')
    return text + '<p class="muted">The checker proves a quote exists, not that the conclusion is right.</p>'


def site_run(run: AlertRun) -> str:
    return run.run_dir.parent.name


def _fields(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    items = sorted(value.items(), key=lambda kv: str(kv[0]))[:10]
    return "; ".join(f"{e(k)}={e(v if not isinstance(v, (dict, list)) else '...')}" for k, v in items)


def intel_html(run: AlertRun) -> str:
    head = f'<h2 id="intel">Threat intel: {INTEL_LABEL}</h2>'
    rel = f"out/runs/{site_run(run)}/{run.alert_id}"
    if run.intel is None:
        return head + f'<p class="muted">No intel step for this alert (asa intel {e(rel)}).</p>' + _notes(run, ("intel.json",))
    indicators = dicts(run.intel.get("indicators"))
    lead = (f"<p>Source: {e(run.intel.get('source'))}. Indicators come only from events the verdict cites. "
            "The verdict did not use this step: it ran after triage, in plain code.</p>")
    if not indicators:
        return head + lead + '<p class="muted">No indicators in the cited events.</p>'
    rows = []
    for ind in indicators:
        verdict = ind.get("verdict")
        providers = ind.get("providers") if isinstance(ind.get("providers"), dict) else {}
        prov = "<br>".join(f"{e(name)}: {e(_d(providers, name).get('status'))}"
                           + (f' <span class="muted">{_fields(_d(providers, name).get("fields"))}</span>' if _d(providers, name).get("fields") else "")
                           for name in sorted(providers, key=str))
        cites = ind.get("from_event_ids")
        rows.append("<tr>" + _td("Type", e(ind.get("type"))) + _td("Value", f"<code>{e(ind.get('value'))}</code>")
                    + _td("From events", e(", ".join(str(c) for c in cites) if isinstance(cites, list) else ""))
                    + _td("Decision", f'<span class="{"bad" if verdict == "contain" else ""}">{e(verdict)}</span>')
                    + _td("Rule", e(ind.get("rule"))) + _td("Providers (synthetic)", prov) + "</tr>")
    table = ('<table class="stack"><thead><tr><th>Type</th><th>Value</th><th>From events</th><th>Decision</th><th>Rule</th>'
             f'<th>Providers (synthetic)</th></tr></thead><tbody>{"".join(rows)}</tbody></table>')
    return head + lead + table


def case_console_page(site: Site, run: AlertRun, alert: dict, data: Any, trail: dict | None = None) -> str:
    """The case page. `trail` (build.check_trail's result) adds the build-time chain banner under the title."""
    v = run.verdict
    body = [alert_nav(run.alert_id, "case"),
            f"<h1>Case {e(run.alert_id)}: {e(alert.get('title'))}</h1>"]
    if trail is not None:
        body.append(trail_banner(site, run, trail))
    body += [f'<p class="muted">run {e(site.run_id)} &middot; {e(v.get("model"))} &middot; effort {e(v.get("effort"))}</p>',
             case_page.facts_html(alert), case_page.verdict_html(v)]
    injection = case_page.injection_html(v, data, section_id="injection", note=CONSOLE_INJECTION_NOTE)
    if injection:
        body.append(injection)
    body.append('<h2 id="claims">Claims and evidence</h2><p class="muted">Each claim with the events it cites; open an event '
                "id to see the event as the agent's tools showed it.</p>")
    body.extend(case_page.claims_html(v, data))
    body.append('<h2 id="checker">Evidence checker</h2>' + checker_html(run))
    body.append(intel_html(run))
    body.append('<h2 id="actions">Recommended actions and recorded approvals</h2>'
                f'<div class="scroll">{case_page.actions_html(v, run.approvals)}</div>'
                f'<p class="muted">Approvals are dry runs: nothing is sent or executed. {SELF_DECLARED}</p>'
                + _notes(run, ("approvals.jsonl",)))
    body.append(case_page.usage_html(v))
    return page(site, f"Case {run.alert_id}", body, "case")


# ------------------------------------------------------------------------------------------------ trust

def _tools_text(tools: dict) -> str:
    items = [(str(k), _num(n)) for k, n in tools.items()]
    return ", ".join(f"{name} x{n}" for name, n in sorted(items) if n is not None) or "none"


def _reported_text(reported: Any) -> str:
    out = []
    for item in reported if isinstance(reported, list) else []:
        if isinstance(item, dict):
            out.append(" ".join(str(item.get(k)) for k in ("event_id", "field") if item.get(k) is not None))
        else:
            out.append(str(item))
    return ", ".join(out)


def trust_rows(t: dict, trail: dict) -> list[tuple[str, str, str]]:
    """(mark, title, detail html) rows from trust.json plus the build-time trail check."""
    def e(value: Any) -> str:  # noqa: F811 - a missing number reads "?", not an empty gap
        return "?" if value is None else case_page.e(value)

    rows = []
    actions = _d(t, "actions")
    executed, recommended = _num(actions.get("executed")), _num(actions.get("recommended"))
    approved = dicts(actions.get("approved"))
    rows.append(("pass" if executed == 0 else "fail" if executed else "note", "It changed nothing in your environment",
                 f"Actions recommended: {e(recommended)}; approved as dry runs: {len(approved)}; executed: {e(executed)}. "
                 "No code path in this package carries an action out."))

    read = _d(t, "data_read")
    rows.append(("note", "What it read",
                 f"Tools called: {e(_tools_text(_d(read, 'tools_called')))}. It saw {e(read.get('events_seen'))} events "
                 f"and cited {e(read.get('events_cited'))}. Every tool is read-only over the synthetic dataset."))

    ev = _d(t, "evidence")
    claims, supported = _num(ev.get("claims")), _num(ev.get("supported"))
    findings = {str(k): _num(n) for k, n in _d(ev, "findings_by_kind").items() if _num(n)}
    clean = claims is not None and supported == claims and not findings
    rows.append(("pass" if clean else "note", "Every claim cites an event it was shown",
                 f"{e(supported)} of {e(claims)} claims pass the evidence checker"
                 + (f"; findings: {e(', '.join(f'{k} x{n}' for k, n in sorted(findings.items())))}" if findings else "; no findings")
                 + ". The checker proves a quote exists, not that the conclusion is right."))

    inj = _d(t, "injection")
    reported, followed, planted = inj.get("reported"), inj.get("followed"), inj.get("planted_known")
    n_reported = len(reported) if isinstance(reported, list) else 0
    if isinstance(followed, int) and not isinstance(followed, bool) and followed > 0:
        mark, text = "fail", f"Followed {followed} planted instruction(s)."
    elif followed == 0 and n_reported:
        mark, text = "pass", f"Reported and escalated {n_reported} ({e(_reported_text(reported))}); 0 followed."
    elif followed == 0:
        mark, text = "pass", "No instruction-shaped text reported; 0 followed."
    else:
        mark, text = "note", (f"Reported {n_reported}" + (f" ({e(_reported_text(reported))})" if n_reported else "")
                              + "; whether any was followed is not computed for this alert.")
    known = {True: " This alert holds a planted instruction from the known set.", False: " No planted instruction is known for this alert."}
    rows.append((mark, "Planted instructions in the logs", text + known.get(planted, "") if isinstance(planted, bool) else text))

    who = "; ".join(f"{e(a.get('id'))} by {e(a.get('by'))} at {e(a.get('at'))}" for a in approved) or "none recorded"
    rows.append(("note", "Who approved", f"{who}. {SELF_DECLARED} Approvals are dry runs: nothing is sent."))

    intel = _d(t, "intel")
    if intel:
        rows.append(("note", f"Threat intel: {INTEL_LABEL}",
                     f"{e(intel.get('indicators'))} indicators from cited events: {e(intel.get('contain'))} contain, "
                     f"{e(intel.get('review'))} review, {e(intel.get('clear'))} clear (source: {e(intel.get('source'))}). "
                     "The verdict did not use it."))
    else:
        rows.append(("note", f"Threat intel: {INTEL_LABEL}", "Not run for this alert."))

    cost = _d(t, "cost")
    usd, budget = _num(cost.get("usd")), _num(cost.get("budget_usd"))
    within = usd is not None and budget is not None and usd <= budget
    rows.append(("pass" if within else "note", "What it cost",
                 f"Recorded cost ${e(usd)} over {e(cost.get('turns'))} model turns; "
                 + (f"hard cap ${e(budget)}." if budget is not None else "no cap needed for a replay ($0 now).")))

    audit = _d(t, "audit")
    state = trail.get("state")
    mark = {"verified": "pass", "failed": "fail"}.get(state, "note")
    rows.append((mark, "The record was not edited",
                 f"{e(audit.get('lines'))} trail lines; head <span class=\"hash\">{e(audit.get('head_sha256'))}</span> when the report "
                 f"was made. When this page was built: {e(trail_state_text(trail))}. A hash chain shows edits; it does not stop "
                 "someone rewriting the whole chain, so the head of the demo run is also written in the README (git history anchors it)."))
    return rows


def trust_page(site: Site, run: AlertRun, alert: dict, trail: dict) -> str:
    body = [alert_nav(run.alert_id, "trust"), f"<h1>Trust report {e(run.alert_id)}: {e(alert.get('title'))}</h1>"]
    if run.trust is None:
        rel = f"out/runs/{site_run(run)}/{run.alert_id}"
        body.append(f'<p class="muted">No trust report for this alert yet (asa trust {e(rel)}).</p>' + _notes(run, ("trust.json",)))
        body.append(honesty_box(site))
        return page(site, f"Trust report {run.alert_id}", body, "trust")
    body.append(f'<p class="muted">From trust.json (made {e(run.trust.get("generated_at"))}). Pass = the claim holds for this run; '
                "note = read the detail; fail = do not rely on it.</p>")
    body.append(honesty_box(site))
    body.append('<div id="rows">' + "".join(f'<div class="card row"><h3>{_mark(m)}{e(title)}</h3><p>{detail}</p></div>'
                                           for m, title, detail in trust_rows(run.trust, trail)) + "</div>")
    limits = [x for x in run.trust.get("limits") or [] if isinstance(x, str)] if isinstance(run.trust.get("limits"), list) else []
    if limits:
        body.append('<h2 id="limits">Limits</h2><ul>' + "".join(f"<li>{e(x)}</li>" for x in limits) + "</ul>")
    return page(site, f"Trust report {run.alert_id}", body, "trust")


# ------------------------------------------------------------------------------------------------ audit trail

def trail_state_text(trail: dict) -> str:
    state = trail.get("state")
    if state == "verified":
        return f"chain verified, head {trail.get('head')}"
    if state == "failed":
        return f"chain did NOT verify, first bad line {trail.get('first_bad_seq')} ({trail.get('reason')})"
    return f"not checked ({trail.get('reason')})"


def trail_banner(site: Site, run: AlertRun, trail: dict) -> str:
    """The build-time chain state of one alert's audit trail (audit page and case page)."""
    rel = f"out/runs/{site_run(run)}/{run.alert_id}"
    state = trail.get("state")
    if state == "verified":
        return (f'<p class="banner"><span class="mark pass">pass</span>Chain verified when this page was built, head '
                f'<span class="hash">{e(trail.get("head"))}</span>; re-run <code>asa audit verify {e(rel)}</code></p>')
    if state == "failed":
        return (f'<p class="injection"><span class="mark fail">fail</span>Chain did NOT verify when this page was built: first bad '
                f"line {e(trail.get('first_bad_seq'))} ({e(trail.get('reason'))}). Do not rely on this record; "
                f"re-run <code>asa audit verify {e(rel)}</code></p>")
    return f'<p class="banner"><span class="mark note">note</span>Chain not checked when this page was built: {e(trail.get("reason"))}.</p>'


def audit_page(site: Site, run: AlertRun, alert: dict, trail: dict) -> str:
    rel = f"out/runs/{site_run(run)}/{run.alert_id}"
    banner = trail_banner(site, run, trail)
    body = [alert_nav(run.alert_id, "audit"), f"<h1>Audit trail {e(run.alert_id)}: {e(alert.get('title'))}</h1>", banner,
            '<p class="muted">One line per step, each holding the hash of the line before it. Lines record hashes and short '
            "summaries, not copies of tool output. The replay writes the trail; a live run writes it as it goes.</p>"]
    lines = run.trail
    if lines is None:
        body.append(f'<p class="muted">No audit.jsonl in {e(rel)}.</p>' + _notes(run, ("audit.jsonl",)))
        return page(site, f"Audit trail {run.alert_id}", body, "audit")
    rows = []
    for line in lines[:MAX_TRAIL_ROWS]:
        if not isinstance(line, dict):
            rows.append('<tr><td colspan="7" class="bad">unreadable line (not a JSON object)</td></tr>')
            continue
        rows.append("<tr>" + _td("Seq", e(line.get("seq"))) + _td("At", e(line.get("at"))) + _td("Kind", e(line.get("kind")))
                    + _td("Actor", e(line.get("actor"))) + _td("Summary", e(line.get("summary")))
                    + _td("Data hash", f'<span class="hash">{short(line.get("data_sha256"))}</span>')
                    + _td("Line hash", f'<span class="hash">{short(line.get("sha256"))}</span>') + "</tr>")
    body.append(f'<table class="stack" id="chain"><thead><tr><th>Seq</th><th>At</th><th>Kind</th><th>Actor</th><th>Summary</th>'
                f'<th>Data hash</th><th>Line hash</th></tr></thead><tbody>{"".join(rows)}</tbody></table>')
    if len(lines) > MAX_TRAIL_ROWS:
        body.append(f'<p class="muted">First {MAX_TRAIL_ROWS} of {len(lines)} lines shown.</p>')
    return page(site, f"Audit trail {run.alert_id}", body, "audit")


# ------------------------------------------------------------------------------------------------ checklist

def view_href(view: Any, site: Site) -> tuple[str, str] | None:
    """(href, label) for a checklist console_view such as "case:A-007#injection"; None when it names no built page."""
    m = VIEW_RX.fullmatch(view) if isinstance(view, str) else None
    if not m:
        return None
    kind, alert_id, anchor = m.groups()
    if kind in ("queue", "checklist", "about"):
        if alert_id:
            return None
        href = {"queue": "index.html", "checklist": "checklist.html", "about": "about.html"}[kind]
    else:
        if not alert_id or alert_id not in site.alert_ids or not ALERT_ID.fullmatch(alert_id):
            return None
        href = f"{kind}-{alert_id}.html"
    return href + (f"#{anchor}" if anchor else ""), view


def _items(value: Any) -> list:
    return value if isinstance(value, list) else []


def code_link(item: Any, site: Site) -> str:
    """`path::symbol` as a link under the code base; anything else is shown as plain text."""
    text = str(item) if item is not None else ""
    path, _, symbol = text.partition("::")
    if CODE_PATH_RX.fullmatch(path) and ".." not in path and (not symbol or SYMBOL_RX.fullmatch(symbol)):
        return f'<a href="{e(site.code_base + path)}"><code>{e(text)}</code></a>'
    return f"<code>{e(text)}</code>"


def checklist_page(site: Site, rows: Any, problem: str | None) -> str:
    body = ["<h1>Buyer's checklist</h1>",
            "<p>The questions a security team asks before it lets an AI agent triage its alerts. Each answer points to the "
            "view that shows it, the code that does it and the test that proves it.</p>"]
    if rows is None:
        body.append(f'<p class="muted">checklist/checklist.json {"could not be read: " + e(problem) if problem else "not found"}.</p>')
        return page(site, "Buyer's checklist", body, "checklist")
    for row in dicts(rows):
        rid = row.get("id")
        anchor = f' id="{e(rid)}"' if isinstance(rid, str) and ROW_ID_RX.fullmatch(rid) else ""
        pending = row.get("pending") is True
        view = view_href(row.get("console_view"), site)
        see = (f'<a href="{e(view[0])}">{e(view[1])}</a>' if view else
               f"<code>{e(row.get('console_view'))}</code>" if row.get("console_view") else "none")
        code = ", ".join(code_link(c, site) for c in _items(row.get("code"))) or "none"
        tests = ", ".join(code_link(c, site) for c in _items(row.get("tests"))) or "none"
        body.append(f'<div class="card row"{anchor}><h3>{e(rid)}. {e(row.get("question"))}'
                    + (' <span class="tag">being built</span>' if pending else "") + "</h3>"
                    f"<p>{e(row.get('answer'))}</p><dl><dt>See it</dt><dd>{see}</dd><dt>Code</dt><dd>{code}</dd>"
                    f"<dt>Tests</dt><dd>{tests}</dd><dt>Limits</dt><dd>{e(row.get('limits'))}</dd></dl></div>")
    return page(site, "Buyer's checklist", body, "checklist")


# ------------------------------------------------------------------------------------------------ about

LIMITS = (
    "Synthetic data and one recorded run (n = 30): the numbers describe this set, not your environment.",
    "The evidence checker proves a quote exists in the cited event, not that the reasoning is right.",
    "Planted instructions are a known set; text that does not look like an instruction is not flagged.",
    "Threat-intel decisions come from synthetic provider answers, after triage; the verdict did not use them.",
    "The console replays a run; it does not run the agent.",
    "Approvals are dry runs: nothing is executed anywhere. Approver names are self-declared.",
    "The audit trail is tamper-evident, not tamper-proof: a hash chain shows an edit, it does not stop someone "
    "rewriting the whole chain. The head hash of the demo run is written in the README so git history anchors it.",
)


def about_page(site: Site) -> str:
    date = recording_date(site.recording) or "on an unknown date"
    rec = (f"a replay of recorded run {e(site.recording)} ({e(site.model)}, recorded {e(date)}): "
           "the agent triaged each alert once with the real model API, and replaying the recording costs $0 and makes no "
           "model call" if site.recording else "a live run")
    body = [
        "<h1>About this demo</h1>",
        "<p>Harbor Watch MSSP is a fictional managed security provider. Every alert, host, user and address here is "
        "synthetic (documentation IP ranges, <code>corp.example</code> names).</p>",
        f"<p>What you are looking at: {rec}. The replay writes the audit trail; a live run writes it as it goes.</p>",
        "<p>Dates and times: the recorded date is the one in the recording id. Times in the audit trails and trust "
        "reports (ending in Z) are UTC, so they can fall on the next day.</p>" if site.recording else "",
        "<p>The agent can only read. Its recommended actions wait for a person, and the two approvals in this demo are dry "
        f"runs recorded as &quot;{DEMO_APPROVER}&quot;. Threat intel is {INTEL_LABEL}; the verdict did not use it.</p>",
        "<h2>Reproduce it</h2><p>From a clone: install from the lock files, then <code>asa demo</code> (replay, intel, "
        "two scripted approvals, evidence check, trust reports, this console). Check any trail with "
        "<code>asa audit verify out/runs/&lt;run&gt;/&lt;alert&gt;</code>.</p>",
        "<h2>Read with these numbers</h2>", honesty_box(site),
        '<h2 id="limits">Honest limits</h2><ul>' + "".join(f"<li>{e(x)}</li>" for x in LIMITS) + "</ul>",
        "<p class=\"muted\">These pages have no scripts and load nothing from the network "
        "(Content-Security-Policy default-src 'none'). Links to code open the public repository.</p>",
    ]
    return page(site, "About this demo", body, "about")


def valid_code_base(text: str) -> bool:
    return isinstance(text, str) and bool(CODE_BASE_RX.fullmatch(text))
